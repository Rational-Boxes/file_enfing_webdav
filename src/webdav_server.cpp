#include "webdav_server.h"
#include <Poco/Net/HTTPServerResponse.h>
#include <Poco/Net/HTTPServerRequest.h>
#include <Poco/Net/HTMLForm.h>
#include <Poco/StreamCopier.h>
#include <Poco/Path.h>
#include <Poco/URI.h>
#include <Poco/Exception.h>
#include <Poco/JSON/Parser.h>
#include <Poco/JSON/Stringifier.h>
#include <Poco/Base64Encoder.h>
#include <Poco/Base64Decoder.h>
#include <Poco/MD5Engine.h>
#include <Poco/DigestEngine.h>
#include <iostream>
#include <sstream>
#include <fstream>

namespace webdav {

void WebDAVRequestHandler::handleRequest(Poco::Net::HTTPServerRequest& request, Poco::Net::HTTPServerResponse& response) {
    std::string method = request.getMethod();
    
    // Extract tenant from host
    std::string host = request.getHost();
    std::string tenant = extractTenantFromHost(host);
    
    // Set default tenant if none found
    if (tenant.empty()) {
        tenant = "default";
    }
    
    // Route to appropriate handler based on method
    if (method == "GET" || method == "HEAD") {
        handleGet(request, response);
    } else if (method == "PUT") {
        handlePut(request, response);
    } else if (method == "MKCOL") {
        handleMkcol(request, response);
    } else if (method == "DELETE") {
        handleDelete(request, response);
    } else if (method == "PROPFIND") {
        handlePropfind(request, response);
    } else if (method == "PROPPATCH") {
        handleProppatch(request, response);
    } else if (method == "COPY") {
        handleCopy(request, response);
    } else if (method == "MOVE") {
        handleMove(request, response);
    } else if (method == "LOCK") {
        handleLock(request, response);
    } else if (method == "UNLOCK") {
        handleUnlock(request, response);
    } else {
        response.setStatus(Poco::Net::HTTPResponse::HTTP_NOT_IMPLEMENTED);
        response.setReason("Method Not Implemented");
        response.setContentLength(0);
        response.send();
    }
}

void WebDAVRequestHandler::handleGet(Poco::Net::HTTPServerRequest& request, Poco::Net::HTTPServerResponse& response) {
    std::string uri = request.getURI();
    Poco::URI poco_uri(uri);
    std::string path = poco_uri.getPath();
    
    // Extract tenant from host
    std::string host = request.getHost();
    std::string tenant = extractTenantFromHost(host);
    if (tenant.empty()) tenant = "default";
    
    // Authenticate user
    std::string user;
    std::vector<std::string> roles;
    if (!authenticateUser(request, user, tenant, roles)) {
        response.setStatus(Poco::Net::HTTPResponse::HTTP_UNAUTHORIZED);
        response.setReason("Unauthorized");
        response.setContentType("text/plain");
        std::ostream& ostr = response.send();
        ostr << "Authentication required";
        return;
    }
    
    // Resolve path to UUID
    std::string file_uuid = path_resolver_->resolvePathToUUID(path, tenant);
    if (file_uuid.empty()) {
        // Check if it's a directory by appending a slash
        std::string dir_path = path;
        if (dir_path.back() != '/') {
            dir_path += "/";
        }
        file_uuid = path_resolver_->resolvePathToUUID(dir_path, tenant);
        if (file_uuid.empty()) {
            response.setStatus(Poco::Net::HTTPResponse::HTTP_NOT_FOUND);
            response.setReason("Not Found");
            response.setContentType("text/plain");
            std::ostream& ostr = response.send();
            ostr << "Resource not found";
            return;
        }
        
        // It's a directory, list its contents
        fileengine_rpc::ListDirectoryRequest list_req;
        list_req.set_uid(file_uuid);
        
        fileengine_rpc::AuthenticationContext* auth_ctx = list_req.mutable_auth();
        auth_ctx->set_user(user);
        auth_ctx->set_tenant(tenant);
        for (const auto& role : roles) {
            auth_ctx->add_roles(role);
        }
        
        fileengine_rpc::ListDirectoryResponse list_resp = grpc_client_->listDirectory(list_req);
        if (!list_resp.success()) {
            response.setStatus(Poco::Net::HTTPResponse::HTTP_INTERNAL_SERVER_ERROR);
            response.setReason("Internal Server Error");
            response.setContentType("text/plain");
            std::ostream& ostr = response.send();
            ostr << "Failed to list directory: " << list_resp.error();
            return;
        }
        
        // Generate XML response for directory listing
        response.setStatus(Poco::Net::HTTPResponse::HTTP_OK);
        response.setReason("OK");
        response.setContentType("application/xml");
        std::ostream& ostr = response.send();
        
        ostr << "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n";
        ostr << "<D:multistatus xmlns:D=\"DAV:\">\n";
        
        for (const auto& entry : list_resp.entries()) {
            ostr << "  <D:response>\n";
            ostr << "    <D:href>" << path << (path.back() == '/' ? "" : "/") << entry.name() << (entry.type() == fileengine_rpc::FileType::DIRECTORY ? "/" : "") << "</D:href>\n";
            ostr << "    <D:propstat>\n";
            ostr << "      <D:prop>\n";
            ostr << "        <D:displayname>" << entry.name() << "</D:displayname>\n";
            ostr << "        <D:getlastmodified>" << entry.modified_at() << "</D:getlastmodified>\n";
            ostr << "        <D:creationdate>" << entry.created_at() << "</D:creationdate>\n";
            ostr << "        <D:resourcetype>" << (entry.type() == fileengine_rpc::FileType::DIRECTORY ? "<D:collection/>" : "") << "</D:resourcetype>\n";
            ostr << "        <D:getcontentlength>" << entry.size() << "</D:getcontentlength>\n";
            ostr << "      </D:prop>\n";
            ostr << "      <D:status>HTTP/1.1 200 OK</D:status>\n";
            ostr << "    </D:propstat>\n";
            ostr << "  </D:response>\n";
        }
        
        ostr << "</D:multistatus>\n";
        return;
    }
    
    // It's a file, get its content
    fileengine_rpc::GetFileRequest get_req;
    get_req.set_uid(file_uuid);
    
    fileengine_rpc::AuthenticationContext* auth_ctx = get_req.mutable_auth();
    auth_ctx->set_user(user);
    auth_ctx->set_tenant(tenant);
    for (const auto& role : roles) {
        auth_ctx->add_roles(role);
    }
    
    fileengine_rpc::GetFileResponse get_resp = grpc_client_->getFile(get_req);
    if (!get_resp.success()) {
        response.setStatus(Poco::Net::HTTPResponse::HTTP_INTERNAL_SERVER_ERROR);
        response.setReason("Internal Server Error");
        response.setContentType("text/plain");
        std::ostream& ostr = response.send();
        ostr << "Failed to get file: " << get_resp.error();
        return;
    }
    
    response.setStatus(Poco::Net::HTTPResponse::HTTP_OK);
    response.setReason("OK");
    response.setContentType("application/octet-stream"); // TODO: Determine actual content type
    response.setContentLength(get_resp.data().size());
    std::ostream& ostr = response.send();
    ostr.write(get_resp.data().data(), get_resp.data().size());
}

void WebDAVRequestHandler::handlePut(Poco::Net::HTTPServerRequest& request, Poco::Net::HTTPServerResponse& response) {
    std::string uri = request.getURI();
    Poco::URI poco_uri(uri);
    std::string path = poco_uri.getPath();
    
    // Extract tenant from host
    std::string host = request.getHost();
    std::string tenant = extractTenantFromHost(host);
    if (tenant.empty()) tenant = "default";
    
    // Authenticate user
    std::string user;
    std::vector<std::string> roles;
    if (!authenticateUser(request, user, tenant, roles)) {
        response.setStatus(Poco::Net::HTTPResponse::HTTP_UNAUTHORIZED);
        response.setReason("Unauthorized");
        response.setContentType("text/plain");
        std::ostream& ostr = response.send();
        ostr << "Authentication required";
        return;
    }
    
    // Check if file already exists
    std::string file_uuid = path_resolver_->resolvePathToUUID(path, tenant);
    bool file_exists = !file_uuid.empty();
    
    // Get request body
    std::istream& istr = request.stream();
    std::string content;
    Poco::StreamCopier::copyToString(istr, content);
    
    // If file doesn't exist, create it first
    if (!file_exists) {
        // Extract parent directory and filename
        Poco::Path poco_path(path);
        std::string filename = poco_path.getFileName();
        poco_path.makeParent();
        std::string parent_path = poco_path.toString();
        
        // Get parent UUID
        std::string parent_uuid = path_resolver_->resolvePathToUUID(parent_path, tenant);
        if (parent_uuid.empty()) {
            // Parent directory doesn't exist, return error
            response.setStatus(Poco::Net::HTTPResponse::HTTP_CONFLICT);
            response.setReason("Conflict");
            response.setContentType("text/plain");
            std::ostream& ostr = response.send();
            ostr << "Parent directory does not exist";
            return;
        }
        
        // Create the file using Touch
        fileengine_rpc::TouchRequest touch_req;
        touch_req.set_parent_uid(parent_uuid);
        touch_req.set_name(filename);
        
        fileengine_rpc::AuthenticationContext* auth_ctx = touch_req.mutable_auth();
        auth_ctx->set_user(user);
        auth_ctx->set_tenant(tenant);
        for (const auto& role : roles) {
            auth_ctx->add_roles(role);
        }
        
        fileengine_rpc::TouchResponse touch_resp = grpc_client_->touch(touch_req);
        if (!touch_resp.success()) {
            response.setStatus(Poco::Net::HTTPResponse::HTTP_INTERNAL_SERVER_ERROR);
            response.setReason("Internal Server Error");
            response.setContentType("text/plain");
            std::ostream& ostr = response.send();
            ostr << "Failed to create file: " << touch_resp.error();
            return;
        }
        
        file_uuid = touch_resp.uid();
        
        // Create path mapping
        path_resolver_->createPathMapping(path, file_uuid, tenant);
    }
    
    // Now update the file content
    fileengine_rpc::PutFileRequest put_req;
    put_req.set_uid(file_uuid);
    put_req.mutable_data()->assign(content.begin(), content.end());
    
    fileengine_rpc::AuthenticationContext* auth_ctx = put_req.mutable_auth();
    auth_ctx->set_user(user);
    auth_ctx->set_tenant(tenant);
    for (const auto& role : roles) {
        auth_ctx->add_roles(role);
    }
    
    fileengine_rpc::PutFileResponse put_resp = grpc_client_->putFile(put_req);
    if (!put_resp.success()) {
        response.setStatus(Poco::Net::HTTPResponse::HTTP_INTERNAL_SERVER_ERROR);
        response.setReason("Internal Server Error");
        response.setContentType("text/plain");
        std::ostream& ostr = response.send();
        ostr << "Failed to put file: " << put_resp.error();
        return;
    }
    
    response.setStatus(Poco::Net::HTTPResponse::HTTP_CREATED);
    response.setReason("Created");
    response.setContentType("text/plain");
    std::ostream& ostr = response.send();
    ostr << "File uploaded successfully";
}

void WebDAVRequestHandler::handleMkcol(Poco::Net::HTTPServerRequest& request, Poco::Net::HTTPServerResponse& response) {
    std::string uri = request.getURI();
    Poco::URI poco_uri(uri);
    std::string path = poco_uri.getPath();
    
    // Ensure path ends with a slash for directories
    if (path.back() != '/') {
        path += "/";
    }
    
    // Extract tenant from host
    std::string host = request.getHost();
    std::string tenant = extractTenantFromHost(host);
    if (tenant.empty()) tenant = "default";
    
    // Authenticate user
    std::string user;
    std::vector<std::string> roles;
    if (!authenticateUser(request, user, tenant, roles)) {
        response.setStatus(Poco::Net::HTTPResponse::HTTP_UNAUTHORIZED);
        response.setReason("Unauthorized");
        response.setContentType("text/plain");
        std::ostream& ostr = response.send();
        ostr << "Authentication required";
        return;
    }
    
    // Check if directory already exists
    if (path_resolver_->pathExists(path, tenant)) {
        response.setStatus(Poco::Net::HTTPResponse::HTTP_METHOD_NOT_ALLOWED);
        response.setReason("Method Not Allowed");
        response.setContentType("text/plain");
        std::ostream& ostr = response.send();
        ostr << "Collection already exists";
        return;
    }
    
    // Extract parent directory and directory name
    Poco::Path poco_path(path);
    std::string dir_name = poco_path.getFileName();
    poco_path.makeParent();
    std::string parent_path = poco_path.toString();
    
    // Get parent UUID
    std::string parent_uuid = path_resolver_->resolvePathToUUID(parent_path, tenant);
    if (parent_uuid.empty()) {
        // Parent directory doesn't exist, return error
        response.setStatus(Poco::Net::HTTPResponse::HTTP_CONFLICT);
        response.setReason("Conflict");
        response.setContentType("text/plain");
        std::ostream& ostr = response.send();
        ostr << "Parent directory does not exist";
        return;
    }
    
    // Create the directory
    fileengine_rpc::MakeDirectoryRequest mkcol_req;
    mkcol_req.set_parent_uid(parent_uuid);
    mkcol_req.set_name(dir_name);
    
    fileengine_rpc::AuthenticationContext* auth_ctx = mkcol_req.mutable_auth();
    auth_ctx->set_user(user);
    auth_ctx->set_tenant(tenant);
    for (const auto& role : roles) {
        auth_ctx->add_roles(role);
    }
    
    fileengine_rpc::MakeDirectoryResponse mkcol_resp = grpc_client_->makeDirectory(mkcol_req);
    if (!mkcol_resp.success()) {
        response.setStatus(Poco::Net::HTTPResponse::HTTP_INTERNAL_SERVER_ERROR);
        response.setReason("Internal Server Error");
        response.setContentType("text/plain");
        std::ostream& ostr = response.send();
        ostr << "Failed to create directory: " << mkcol_resp.error();
        return;
    }
    
    // Create path mapping
    path_resolver_->createPathMapping(path, mkcol_resp.uid(), tenant);
    
    response.setStatus(Poco::Net::HTTPResponse::HTTP_CREATED);
    response.setReason("Created");
    response.setContentType("text/plain");
    std::ostream& ostr = response.send();
    ostr << "Directory created successfully";
}

void WebDAVRequestHandler::handleDelete(Poco::Net::HTTPServerRequest& request, Poco::Net::HTTPServerResponse& response) {
    std::string uri = request.getURI();
    Poco::URI poco_uri(uri);
    std::string path = poco_uri.getPath();
    
    // Extract tenant from host
    std::string host = request.getHost();
    std::string tenant = extractTenantFromHost(host);
    if (tenant.empty()) tenant = "default";
    
    // Authenticate user
    std::string user;
    std::vector<std::string> roles;
    if (!authenticateUser(request, user, tenant, roles)) {
        response.setStatus(Poco::Net::HTTPResponse::HTTP_UNAUTHORIZED);
        response.setReason("Unauthorized");
        response.setContentType("text/plain");
        std::ostream& ostr = response.send();
        ostr << "Authentication required";
        return;
    }
    
    // Resolve path to UUID
    std::string resource_uuid = path_resolver_->resolvePathToUUID(path, tenant);
    if (resource_uuid.empty()) {
        // Also check with trailing slash for directories
        std::string dir_path = path;
        if (dir_path.back() != '/') {
            dir_path += "/";
        }
        resource_uuid = path_resolver_->resolvePathToUUID(dir_path, tenant);
        if (resource_uuid.empty()) {
            response.setStatus(Poco::Net::HTTPResponse::HTTP_NOT_FOUND);
            response.setReason("Not Found");
            response.setContentType("text/plain");
            std::ostream& ostr = response.send();
            ostr << "Resource not found";
            return;
        }
    }
    
    // Check if it's a directory
    fileengine_rpc::StatRequest stat_req;
    stat_req.set_uid(resource_uuid);
    
    fileengine_rpc::AuthenticationContext* auth_ctx = stat_req.mutable_auth();
    auth_ctx->set_user(user);
    auth_ctx->set_tenant(tenant);
    for (const auto& role : roles) {
        auth_ctx->add_roles(role);
    }
    
    fileengine_rpc::StatResponse stat_resp = grpc_client_->stat(stat_req);
    if (!stat_resp.success()) {
        response.setStatus(Poco::Net::HTTPResponse::HTTP_INTERNAL_SERVER_ERROR);
        response.setReason("Internal Server Error");
        response.setContentType("text/plain");
        std::ostream& ostr = response.send();
        ostr << "Failed to get resource info: " << stat_resp.error();
        return;
    }
    
    // Perform delete operation based on resource type
    if (stat_resp.info().type() == fileengine_rpc::FileType::DIRECTORY) {
        // Remove trailing slash if present for directory path
        std::string dir_path = path;
        if (dir_path.back() == '/') {
            dir_path = dir_path.substr(0, dir_path.length() - 1);
        }
        
        fileengine_rpc::RemoveDirectoryRequest rm_req;
        rm_req.set_uid(resource_uuid);
        
        fileengine_rpc::AuthenticationContext* rm_auth_ctx = rm_req.mutable_auth();
        rm_auth_ctx->set_user(user);
        rm_auth_ctx->set_tenant(tenant);
        for (const auto& role : roles) {
            rm_auth_ctx->add_roles(role);
        }
        
        fileengine_rpc::RemoveDirectoryResponse rm_resp = grpc_client_->removeDirectory(rm_req);
        if (!rm_resp.success()) {
            response.setStatus(Poco::Net::HTTPResponse::HTTP_INTERNAL_SERVER_ERROR);
            response.setReason("Internal Server Error");
            response.setContentType("text/plain");
            std::ostream& ostr = response.send();
            ostr << "Failed to remove directory: " << rm_resp.error();
            return;
        }
        
        // Remove path mapping
        path_resolver_->removePathMapping(dir_path + "/", tenant);
    } else {
        fileengine_rpc::RemoveFileRequest rm_req;
        rm_req.set_uid(resource_uuid);
        
        fileengine_rpc::AuthenticationContext* rm_auth_ctx = rm_req.mutable_auth();
        rm_auth_ctx->set_user(user);
        rm_auth_ctx->set_tenant(tenant);
        for (const auto& role : roles) {
            rm_auth_ctx->add_roles(role);
        }
        
        fileengine_rpc::RemoveFileResponse rm_resp = grpc_client_->removeFile(rm_req);
        if (!rm_resp.success()) {
            response.setStatus(Poco::Net::HTTPResponse::HTTP_INTERNAL_SERVER_ERROR);
            response.setReason("Internal Server Error");
            response.setContentType("text/plain");
            std::ostream& ostr = response.send();
            ostr << "Failed to remove file: " << rm_resp.error();
            return;
        }
        
        // Remove path mapping
        path_resolver_->removePathMapping(path, tenant);
    }
    
    response.setStatus(Poco::Net::HTTPResponse::HTTP_NO_CONTENT);
    response.setReason("No Content");
    response.setContentType("text/plain");
    std::ostream& ostr = response.send();
}

void WebDAVRequestHandler::handlePropfind(Poco::Net::HTTPServerRequest& request, Poco::Net::HTTPServerResponse& response) {
    std::string uri = request.getURI();
    Poco::URI poco_uri(uri);
    std::string path = poco_uri.getPath();
    
    // Extract tenant from host
    std::string host = request.getHost();
    std::string tenant = extractTenantFromHost(host);
    if (tenant.empty()) tenant = "default";
    
    // Authenticate user
    std::string user;
    std::vector<std::string> roles;
    if (!authenticateUser(request, user, tenant, roles)) {
        response.setStatus(Poco::Net::HTTPResponse::HTTP_UNAUTHORIZED);
        response.setReason("Unauthorized");
        response.setContentType("text/plain");
        std::ostream& ostr = response.send();
        ostr << "Authentication required";
        return;
    }
    
    // Resolve path to UUID
    std::string resource_uuid = path_resolver_->resolvePathToUUID(path, tenant);
    if (resource_uuid.empty()) {
        // Also check with trailing slash for directories
        std::string dir_path = path;
        if (dir_path.back() != '/') {
            dir_path += "/";
        }
        resource_uuid = path_resolver_->resolvePathToUUID(dir_path, tenant);
        if (resource_uuid.empty()) {
            response.setStatus(Poco::Net::HTTPResponse::HTTP_NOT_FOUND);
            response.setReason("Not Found");
            response.setContentType("text/plain");
            std::ostream& ostr = response.send();
            ostr << "Resource not found";
            return;
        }
    }
    
    // Get resource info
    fileengine_rpc::StatRequest stat_req;
    stat_req.set_uid(resource_uuid);
    
    fileengine_rpc::AuthenticationContext* auth_ctx = stat_req.mutable_auth();
    auth_ctx->set_user(user);
    auth_ctx->set_tenant(tenant);
    for (const auto& role : roles) {
        auth_ctx->add_roles(role);
    }
    
    fileengine_rpc::StatResponse stat_resp = grpc_client_->stat(stat_req);
    if (!stat_resp.success()) {
        response.setStatus(Poco::Net::HTTPResponse::HTTP_INTERNAL_SERVER_ERROR);
        response.setReason("Internal Server Error");
        response.setContentType("text/plain");
        std::ostream& ostr = response.send();
        ostr << "Failed to get resource info: " << stat_resp.error();
        return;
    }
    
    // Generate XML response with properties
    response.setStatus(Poco::Net::HTTPResponse::HTTP_OK);
    response.setReason("OK");
    response.setContentType("application/xml");
    std::ostream& ostr = response.send();
    
    ostr << "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n";
    ostr << "<D:multistatus xmlns:D=\"DAV:\">\n";
    ostr << "  <D:response>\n";
    ostr << "    <D:href>" << path << "</D:href>\n";
    ostr << "    <D:propstat>\n";
    ostr << "      <D:prop>\n";
    ostr << "        <D:displayname>" << stat_resp.info().name() << "</D:displayname>\n";
    ostr << "        <D:getlastmodified>" << stat_resp.info().modified_at() << "</D:getlastmodified>\n";
    ostr << "        <D:creationdate>" << stat_resp.info().created_at() << "</D:creationdate>\n";
    ostr << "        <D:resourcetype>" << (stat_resp.info().type() == fileengine_rpc::FileType::DIRECTORY ? "<D:collection/>" : "") << "</D:resourcetype>\n";
    ostr << "        <D:getcontentlength>" << stat_resp.info().size() << "</D:getcontentlength>\n";
    ostr << "        <D:getcontenttype>" << (stat_resp.info().type() == fileengine_rpc::FileType::DIRECTORY ? "httpd/unix-directory" : "application/octet-stream") << "</D:getcontenttype>\n";
    ostr << "      </D:prop>\n";
    ostr << "      <D:status>HTTP/1.1 200 OK</D:status>\n";
    ostr << "    </D:propstat>\n";
    ostr << "  </D:response>\n";
    ostr << "</D:multistatus>\n";
}

void WebDAVRequestHandler::handleProppatch(Poco::Net::HTTPServerRequest& request, Poco::Net::HTTPServerResponse& response) {
    // For now, we'll just return a not implemented response
    // In a full implementation, this would handle property updates
    response.setStatus(Poco::Net::HTTPResponse::HTTP_NOT_IMPLEMENTED);
    response.setReason("Not Implemented");
    response.setContentType("text/plain");
    std::ostream& ostr = response.send();
    ostr << "PROPPATCH not fully implemented";
}

void WebDAVRequestHandler::handleCopy(Poco::Net::HTTPServerRequest& request, Poco::Net::HTTPServerResponse& response) {
    // Extract destination header
    std::string destination = request.get("Destination", "");
    if (destination.empty()) {
        response.setStatus(Poco::Net::HTTPResponse::HTTP_BAD_REQUEST);
        response.setReason("Bad Request");
        response.setContentType("text/plain");
        std::ostream& ostr = response.send();
        ostr << "Missing Destination header";
        return;
    }
    
    std::string uri = request.getURI();
    Poco::URI poco_uri(uri);
    std::string source_path = poco_uri.getPath();
    
    Poco::URI dest_uri(destination);
    std::string dest_path = dest_uri.getPath();
    
    // Extract tenant from host
    std::string host = request.getHost();
    std::string tenant = extractTenantFromHost(host);
    if (tenant.empty()) tenant = "default";
    
    // Authenticate user
    std::string user;
    std::vector<std::string> roles;
    if (!authenticateUser(request, user, tenant, roles)) {
        response.setStatus(Poco::Net::HTTPResponse::HTTP_UNAUTHORIZED);
        response.setReason("Unauthorized");
        response.setContentType("text/plain");
        std::ostream& ostr = response.send();
        ostr << "Authentication required";
        return;
    }
    
    // Resolve source path to UUID
    std::string source_uuid = path_resolver_->resolvePathToUUID(source_path, tenant);
    if (source_uuid.empty()) {
        // Also check with trailing slash for directories
        std::string dir_path = source_path;
        if (dir_path.back() != '/') {
            dir_path += "/";
        }
        source_uuid = path_resolver_->resolvePathToUUID(dir_path, tenant);
        if (source_uuid.empty()) {
            response.setStatus(Poco::Net::HTTPResponse::HTTP_NOT_FOUND);
            response.setReason("Not Found");
            response.setContentType("text/plain");
            std::ostream& ostr = response.send();
            ostr << "Source resource not found";
            return;
        }
    }
    
    // Extract destination parent directory and name
    Poco::Path dest_poco_path(dest_path);
    std::string dest_name = dest_poco_path.getFileName();
    dest_poco_path.makeParent();
    std::string dest_parent_path = dest_poco_path.toString();
    
    // Get destination parent UUID
    std::string dest_parent_uuid = path_resolver_->resolvePathToUUID(dest_parent_path, tenant);
    if (dest_parent_uuid.empty()) {
        response.setStatus(Poco::Net::HTTPResponse::HTTP_CONFLICT);
        response.setReason("Conflict");
        response.setContentType("text/plain");
        std::ostream& ostr = response.send();
        ostr << "Destination parent directory does not exist";
        return;
    }
    
    // Perform copy operation
    fileengine_rpc::CopyRequest copy_req;
    copy_req.set_source_uid(source_uuid);
    copy_req.set_destination_parent_uid(dest_parent_uuid);
    
    fileengine_rpc::AuthenticationContext* auth_ctx = copy_req.mutable_auth();
    auth_ctx->set_user(user);
    auth_ctx->set_tenant(tenant);
    for (const auto& role : roles) {
        auth_ctx->add_roles(role);
    }
    
    fileengine_rpc::CopyResponse copy_resp = grpc_client_->copy(copy_req);
    if (!copy_resp.success()) {
        response.setStatus(Poco::Net::HTTPResponse::HTTP_INTERNAL_SERVER_ERROR);
        response.setReason("Internal Server Error");
        response.setContentType("text/plain");
        std::ostream& ostr = response.send();
        ostr << "Failed to copy resource: " << copy_resp.error();
        return;
    }
    
    // Create path mapping for the copied resource
    // Use the destination parent UUID as the resource UUID for the copy operation
    // The copy operation doesn't return a new UUID, so we need to resolve the new path
    std::string new_resource_uuid = path_resolver_->resolvePathToUUID(dest_path, tenant);
    if (!new_resource_uuid.empty()) {
        path_resolver_->createPathMapping(dest_path, new_resource_uuid, tenant);
    }
    
    response.setStatus(Poco::Net::HTTPResponse::HTTP_CREATED);
    response.setReason("Created");
    response.setContentType("text/plain");
    std::ostream& ostr = response.send();
    ostr << "Resource copied successfully";
}

void WebDAVRequestHandler::handleMove(Poco::Net::HTTPServerRequest& request, Poco::Net::HTTPServerResponse& response) {
    // Extract destination header
    std::string destination = request.get("Destination", "");
    if (destination.empty()) {
        response.setStatus(Poco::Net::HTTPResponse::HTTP_BAD_REQUEST);
        response.setReason("Bad Request");
        response.setContentType("text/plain");
        std::ostream& ostr = response.send();
        ostr << "Missing Destination header";
        return;
    }
    
    std::string uri = request.getURI();
    Poco::URI poco_uri(uri);
    std::string source_path = poco_uri.getPath();
    
    Poco::URI dest_uri(destination);
    std::string dest_path = dest_uri.getPath();
    
    // Extract tenant from host
    std::string host = request.getHost();
    std::string tenant = extractTenantFromHost(host);
    if (tenant.empty()) tenant = "default";
    
    // Authenticate user
    std::string user;
    std::vector<std::string> roles;
    if (!authenticateUser(request, user, tenant, roles)) {
        response.setStatus(Poco::Net::HTTPResponse::HTTP_UNAUTHORIZED);
        response.setReason("Unauthorized");
        response.setContentType("text/plain");
        std::ostream& ostr = response.send();
        ostr << "Authentication required";
        return;
    }
    
    // Resolve source path to UUID
    std::string source_uuid = path_resolver_->resolvePathToUUID(source_path, tenant);
    if (source_uuid.empty()) {
        // Also check with trailing slash for directories
        std::string dir_path = source_path;
        if (dir_path.back() != '/') {
            dir_path += "/";
        }
        source_uuid = path_resolver_->resolvePathToUUID(dir_path, tenant);
        if (source_uuid.empty()) {
            response.setStatus(Poco::Net::HTTPResponse::HTTP_NOT_FOUND);
            response.setReason("Not Found");
            response.setContentType("text/plain");
            std::ostream& ostr = response.send();
            ostr << "Source resource not found";
            return;
        }
    }
    
    // Extract destination parent directory and name
    Poco::Path dest_poco_path(dest_path);
    std::string dest_name = dest_poco_path.getFileName();
    dest_poco_path.makeParent();
    std::string dest_parent_path = dest_poco_path.toString();
    
    // Get destination parent UUID
    std::string dest_parent_uuid = path_resolver_->resolvePathToUUID(dest_parent_path, tenant);
    if (dest_parent_uuid.empty()) {
        response.setStatus(Poco::Net::HTTPResponse::HTTP_CONFLICT);
        response.setReason("Conflict");
        response.setContentType("text/plain");
        std::ostream& ostr = response.send();
        ostr << "Destination parent directory does not exist";
        return;
    }
    
    // Perform move operation
    fileengine_rpc::MoveRequest move_req;
    move_req.set_source_uid(source_uuid);
    move_req.set_destination_parent_uid(dest_parent_uuid);
    
    fileengine_rpc::AuthenticationContext* auth_ctx = move_req.mutable_auth();
    auth_ctx->set_user(user);
    auth_ctx->set_tenant(tenant);
    for (const auto& role : roles) {
        auth_ctx->add_roles(role);
    }
    
    fileengine_rpc::MoveResponse move_resp = grpc_client_->move(move_req);
    if (!move_resp.success()) {
        response.setStatus(Poco::Net::HTTPResponse::HTTP_INTERNAL_SERVER_ERROR);
        response.setReason("Internal Server Error");
        response.setContentType("text/plain");
        std::ostream& ostr = response.send();
        ostr << "Failed to move resource: " << move_resp.error();
        return;
    }
    
    // Update path mapping (remove old, add new)
    path_resolver_->removePathMapping(source_path, tenant);
    path_resolver_->createPathMapping(dest_path, source_uuid, tenant);
    
    response.setStatus(Poco::Net::HTTPResponse::HTTP_CREATED);
    response.setReason("Created");
    response.setContentType("text/plain");
    std::ostream& ostr = response.send();
    ostr << "Resource moved successfully";
}

void WebDAVRequestHandler::handleLock(Poco::Net::HTTPServerRequest& request, Poco::Net::HTTPServerResponse& response) {
    // Since FileEngine is pervasively versioned and immutable, traditional file locking doesn't apply
    // We'll implement a minimal lock response for client compatibility
    response.setStatus(Poco::Net::HTTPResponse::HTTP_OK);
    response.setReason("OK");
    response.setContentType("application/xml");
    std::ostream& ostr = response.send();
    
    ostr << "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n";
    ostr << "<D:prop xmlns:D=\"DAV:\">\n";
    ostr << "  <D:lockdiscovery>\n";
    ostr << "    <D:activelock>\n";
    ostr << "      <D:locktype><D:write/></D:locktype>\n";
    ostr << "      <D:lockscope><D:exclusive/></D:lockscope>\n";
    ostr << "      <D:depth>infinity</D:depth>\n";
    ostr << "      <D:timeout>Second-600</D:timeout>\n";
    ostr << "      <D:locktoken>\n";
    ostr << "        <D:href>opaquelocktoken:" << "dummy-lock-token" << "</D:href>\n";
    ostr << "      </D:locktoken>\n";
    ostr << "      <D:owner>\n";
    ostr << "        <D:href>User</D:href>\n";
    ostr << "      </D:owner>\n";
    ostr << "    </D:activelock>\n";
    ostr << "  </D:lockdiscovery>\n";
    ostr << "</D:prop>\n";
}

void WebDAVRequestHandler::handleUnlock(Poco::Net::HTTPServerRequest& request, Poco::Net::HTTPServerResponse& response) {
    // Since FileEngine is pervasively versioned and immutable, traditional file unlocking doesn't apply
    // We'll return a success response for client compatibility
    response.setStatus(Poco::Net::HTTPResponse::HTTP_NO_CONTENT);
    response.setReason("No Content");
    response.setContentType("text/plain");
    std::ostream& ostr = response.send();
}

std::string WebDAVRequestHandler::extractTenantFromHost(const std::string& host) {
    return webdav::extractTenantFromHostname(host);
}

bool WebDAVRequestHandler::authenticateUser(Poco::Net::HTTPServerRequest& request, std::string& user, std::string& tenant, std::vector<std::string>& roles) {
    // Check for Authorization header
    std::string auth_header = request.get("Authorization", "");
    if (auth_header.empty()) {
        return false;
    }
    
    // Handle Basic Authentication
    if (auth_header.substr(0, 5) == "Basic") {
        std::string encoded_credentials = trim(auth_header.substr(6));
        
        // Decode Base64 credentials
        std::istringstream istr(encoded_credentials);
        std::ostringstream ostr;
        Poco::Base64Decoder b64in(istr);
        Poco::StreamCopier::copyStream(b64in, ostr);
        std::string credentials = ostr.str();
        size_t colon_pos = credentials.find(':');
        if (colon_pos == std::string::npos) {
            return false;
        }
        
        std::string username = credentials.substr(0, colon_pos);
        std::string password = credentials.substr(colon_pos + 1);
        
        // Authenticate with LDAP
        UserInfo user_info = ldap_auth_->authenticateUser(username, password);
        if (!user_info.authenticated) {
            return false;
        }
        
        user = user_info.user_id;
        tenant = user_info.tenant.empty() ? tenant : user_info.tenant; // Use extracted tenant if available
        roles = user_info.roles;
        
        return true;
    }
    
    // For now, only Basic authentication is supported
    // Digest authentication would be implemented here if needed
    return false;
}

WebDAVServer::WebDAVServer(const std::string& host, int port)
    : host_(host), port_(port),
      grpc_client_(std::make_shared<GRPCClientWrapper>(webdav::getEnvOrDefault("FILEENGINE_GRPC_HOST", "localhost") + ":" + webdav::getEnvOrDefault("FILEENGINE_GRPC_PORT", "50051"))),
      path_resolver_(std::make_shared<PathResolver>(grpc_client_)),
      ldap_auth_(std::make_shared<LDAPAuthenticator>(
          webdav::getEnvOrDefault("FILEENGINE_LDAP_ENDPOINT", "ldap://localhost:1389"),
          webdav::getEnvOrDefault("FILEENGINE_LDAP_DOMAIN", "dc=rationalboxes,dc=com"),
          webdav::getEnvOrDefault("FILEENGINE_LDAP_BIND_DN", "cn=admin,dc=rationalboxes,dc=com"),
          webdav::getEnvOrDefault("FILEENGINE_LDAP_BIND_PASSWORD", "admin")
      )),
      socket_(std::make_unique<Poco::Net::ServerSocket>(port)),
      server_params_(new Poco::Net::HTTPServerParams),
      server_(nullptr) {
    server_params_->setKeepAlive(true);
}

WebDAVServer::~WebDAVServer() {
    stop();
    // Explicitly reset the server to ensure proper cleanup
    server_.reset();
}

void WebDAVServer::start() {
    auto factory = new WebDAVRequestHandlerFactory(grpc_client_, path_resolver_, ldap_auth_);
    server_ = std::make_unique<Poco::Net::HTTPServer>(factory, *socket_, server_params_);
    server_->start();

    std::cout << "WebDAV server listening on " << host_ << ":" << port_ << std::endl;
}

void WebDAVServer::stop() {
    if (server_) {
        server_->stop();
    }
    if (socket_) {
        socket_->close();
    }
}

} // namespace webdav