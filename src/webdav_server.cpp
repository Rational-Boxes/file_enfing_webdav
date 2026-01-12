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
    std::string uri = request.getURI();

    // Log the incoming request if debug level is enabled
    webdav::debugLog("Received " + method + " request for URI: " + uri + " from " + request.clientAddress().toString());

    // Extract tenant from host
    std::string host = request.getHost();
    std::string tenant = extractTenantFromHost(host);

    // Set default tenant if none found
    if (tenant.empty()) {
        tenant = "default";
    }

    webdav::debugLog("Resolved tenant: " + tenant + " from host: " + host);

    // Route to appropriate handler based on method
    if (method == "GET" || method == "HEAD") {
        webdav::debugLog("Routing to GET/HEAD handler");
        handleGet(request, response);
    } else if (method == "PUT") {
        webdav::debugLog("Routing to PUT handler");
        handlePut(request, response);
    } else if (method == "MKCOL") {
        webdav::debugLog("Routing to MKCOL handler");
        handleMkcol(request, response);
    } else if (method == "DELETE") {
        webdav::debugLog("Routing to DELETE handler");
        handleDelete(request, response);
    } else if (method == "PROPFIND") {
        webdav::debugLog("Routing to PROPFIND handler");
        handlePropfind(request, response);
    } else if (method == "PROPPATCH") {
        webdav::debugLog("Routing to PROPPATCH handler");
        handleProppatch(request, response);
    } else if (method == "COPY") {
        webdav::debugLog("Routing to COPY handler");
        handleCopy(request, response);
    } else if (method == "MOVE") {
        webdav::debugLog("Routing to MOVE handler");
        handleMove(request, response);
    } else if (method == "LOCK") {
        webdav::debugLog("Routing to LOCK handler");
        handleLock(request, response);
    } else if (method == "UNLOCK") {
        webdav::debugLog("Routing to UNLOCK handler");
        handleUnlock(request, response);
    } else if (method == "OPTIONS") {
        webdav::debugLog("Routing to OPTIONS handler");
        handleOptions(request, response);
    } else {
        webdav::debugLog("Unsupported method: " + method + " for URI: " + uri);
        response.setStatus(Poco::Net::HTTPResponse::HTTP_NOT_IMPLEMENTED);
        response.setReason("Method Not Implemented");
        response.setContentType("text/plain");
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
        response.set("WWW-Authenticate", "Basic realm=\"WebDAV Server\"");
        response.setContentType("text/plain");
        std::ostream& ostr = response.send();
        ostr << "Authentication required";
        return;
    }

    // For root path, return a simple directory listing
    if (path == "/" || path == "/index.html") {
        response.setStatus(Poco::Net::HTTPResponse::HTTP_OK);
        response.setReason("OK");
        response.setContentType("text/html");
        std::ostream& ostr = response.send();
        ostr << "<html><body><h1>WebDAV Server</h1><p>Welcome to the WebDAV server.</p></body></html>";
        return;
    }

    // For other paths, we would need to implement path-to-UUID mapping
    // Since we removed the database dependency, we'll implement a minimal approach
    // to demonstrate the functionality
    
    // In a real implementation, we would need to map the path to a UUID and then
    // retrieve the file content via gRPC
    response.setStatus(Poco::Net::HTTPResponse::HTTP_OK);
    response.setReason("OK");
    response.setContentType("text/plain");
    std::ostream& ostr = response.send();
    ostr << "GET request for path: " << path << " (tenant: " << tenant << ")";
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
        response.set("WWW-Authenticate", "Basic realm=\"WebDAV Server\"");
        response.setContentType("text/plain");
        std::ostream& ostr = response.send();
        ostr << "Authentication required";
        return;
    }

    // Get request body
    std::istream& istr = request.stream();
    std::string content;
    Poco::StreamCopier::copyToString(istr, content);

    // In a real implementation, we would need to implement path-to-UUID mapping
    // For now, we'll simulate the functionality by creating a dummy file
    response.setStatus(Poco::Net::HTTPResponse::HTTP_CREATED);
    response.setReason("Created");
    response.setContentType("text/plain");
    std::ostream& ostr = response.send();
    ostr << "PUT request for path: " << path << " (tenant: " << tenant << ") - Content length: " << content.length();
}

void WebDAVRequestHandler::handleMkcol(Poco::Net::HTTPServerRequest& request, Poco::Net::HTTPServerResponse& response) {
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
        response.set("WWW-Authenticate", "Basic realm=\"WebDAV Server\"");
        response.setContentType("text/plain");
        std::ostream& ostr = response.send();
        ostr << "Authentication required";
        return;
    }

    // In a real implementation, we would create a directory via gRPC
    // For now, we'll simulate the functionality
    response.setStatus(Poco::Net::HTTPResponse::HTTP_CREATED);
    response.setReason("Created");
    response.setContentType("text/plain");
    std::ostream& ostr = response.send();
    ostr << "MKCOL request for path: " << path << " (tenant: " << tenant << ")";
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
        response.set("WWW-Authenticate", "Basic realm=\"WebDAV Server\"");
        response.setContentType("text/plain");
        std::ostream& ostr = response.send();
        ostr << "Authentication required";
        return;
    }

    // In a real implementation, we would delete the resource via gRPC
    // For now, we'll simulate the functionality
    response.setStatus(Poco::Net::HTTPResponse::HTTP_NO_CONTENT);
    response.setReason("No Content");
    response.setContentType("text/plain");
    std::ostream& ostr = response.send();
    ostr << "DELETE request for path: " << path << " (tenant: " << tenant << ")";
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
        response.set("WWW-Authenticate", "Basic realm=\"WebDAV Server\"");
        response.setContentType("application/xml");
        std::ostream& ostr = response.send();
        ostr << "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n";
        ostr << "<D:error xmlns:D=\"DAV:\"/>";
        return;
    }

    // For root path, return a basic directory listing
    if (path == "/" || path.empty()) {
        response.setStatus(Poco::Net::HTTPResponse::HTTP_OK);
        response.setReason("OK");
        response.setContentType("application/xml; charset=utf-8");
        std::ostream& ostr = response.send();

        ostr << "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n";
        ostr << "<D:multistatus xmlns:D=\"DAV:\">\n";
        ostr << "  <D:response>\n";
        ostr << "    <D:href>/</D:href>\n";
        ostr << "    <D:propstat>\n";
        ostr << "      <D:prop>\n";
        ostr << "        <D:displayname>Root Directory</D:displayname>\n";
        ostr << "        <D:resourcetype><D:collection/></D:resourcetype>\n";
        ostr << "        <D:getcontenttype>httpd/unix-directory</D:getcontenttype>\n";
        ostr << "        <D:creationdate>2026-01-10T00:00:00Z</D:creationdate>\n";
        ostr << "        <D:getlastmodified>2026-01-10T00:00:00Z</D:getlastmodified>\n";
        ostr << "      </D:prop>\n";
        ostr << "      <D:status>HTTP/1.1 200 OK</D:status>\n";
        ostr << "    </D:propstat>\n";
        ostr << "  </D:response>\n";
        ostr << "</D:multistatus>\n";
        return;
    }

    // For other paths, return a simple response
    response.setStatus(Poco::Net::HTTPResponse::HTTP_OK);
    response.setReason("OK");
    response.setContentType("application/xml; charset=utf-8");
    std::ostream& ostr = response.send();

    ostr << "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n";
    ostr << "<D:multistatus xmlns:D=\"DAV:\">\n";
    ostr << "  <D:response>\n";
    ostr << "    <D:href>" << path << "</D:href>\n";
    ostr << "    <D:propstat>\n";
    ostr << "      <D:prop>\n";
    ostr << "        <D:displayname>" << path.substr(path.find_last_of('/') + 1) << "</D:displayname>\n";
    ostr << "        <D:resourcetype></D:resourcetype>\n";
    ostr << "        <D:getcontenttype>application/octet-stream</D:getcontenttype>\n";
    ostr << "        <D:creationdate>2026-01-10T00:00:00Z</D:creationdate>\n";
    ostr << "        <D:getlastmodified>2026-01-10T00:00:00Z</D:getlastmodified>\n";
    ostr << "        <D:getcontentlength>0</D:getcontentlength>\n";
    ostr << "      </D:prop>\n";
    ostr << "      <D:status>HTTP/1.1 200 OK</D:status>\n";
    ostr << "    </D:propstat>\n";
    ostr << "  </D:response>\n";
    ostr << "</D:multistatus>\n";
}

void WebDAVRequestHandler::handleProppatch(Poco::Net::HTTPServerRequest& request, Poco::Net::HTTPServerResponse& response) {
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
        response.set("WWW-Authenticate", "Basic realm=\"WebDAV Server\"");
        response.setContentType("text/plain");
        std::ostream& ostr = response.send();
        ostr << "Authentication required";
        return;
    }

    // For now, return a simple response
    // In a real implementation, this would handle property updates
    response.setStatus(Poco::Net::HTTPResponse::HTTP_MULTI_STATUS);
    response.setReason("Multi-Status");
    response.setContentType("application/xml; charset=utf-8");
    std::ostream& ostr = response.send();

    ostr << "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n";
    ostr << "<D:multistatus xmlns:D=\"DAV:\">\n";
    ostr << "  <D:response>\n";
    ostr << "    <D:href>" << path << "</D:href>\n";
    ostr << "    <D:propstat>\n";
    ostr << "      <D:prop>\n";
    ostr << "        <D:displayname/>\n";
    ostr << "      </D:prop>\n";
    ostr << "      <D:status>HTTP/1.1 424 Failed Dependency</D:status>\n";
    ostr << "    </D:propstat>\n";
    ostr << "  </D:response>\n";
    ostr << "</D:multistatus>\n";
}

void WebDAVRequestHandler::handleCopy(Poco::Net::HTTPServerRequest& request, Poco::Net::HTTPServerResponse& response) {
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
        response.set("WWW-Authenticate", "Basic realm=\"WebDAV Server\"");
        response.setContentType("text/plain");
        std::ostream& ostr = response.send();
        ostr << "Authentication required";
        return;
    }

    // In a real implementation, we would copy the resource via gRPC
    // For now, we'll simulate the functionality
    response.setStatus(Poco::Net::HTTPResponse::HTTP_CREATED);
    response.setReason("Created");
    response.setContentType("text/plain");
    std::ostream& ostr = response.send();
    ostr << "COPY request from: " << source_path << " to: " << dest_path << " (tenant: " << tenant << ")";
}

void WebDAVRequestHandler::handleMove(Poco::Net::HTTPServerRequest& request, Poco::Net::HTTPServerResponse& response) {
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
        response.set("WWW-Authenticate", "Basic realm=\"WebDAV Server\"");
        response.setContentType("text/plain");
        std::ostream& ostr = response.send();
        ostr << "Authentication required";
        return;
    }

    // In a real implementation, we would move the resource via gRPC
    // For now, we'll simulate the functionality
    response.setStatus(Poco::Net::HTTPResponse::HTTP_CREATED);
    response.setReason("Created");
    response.setContentType("text/plain");
    std::ostream& ostr = response.send();
    ostr << "MOVE request from: " << source_path << " to: " << dest_path << " (tenant: " << tenant << ")";
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

void WebDAVRequestHandler::handleOptions(Poco::Net::HTTPServerRequest& request, Poco::Net::HTTPServerResponse& response) {
    // WebDAV requires the OPTIONS method to return specific headers
    response.setStatus(Poco::Net::HTTPResponse::HTTP_OK);
    response.setReason("OK");
    
    // Set WebDAV-specific headers
    response.set("Allow", "GET, HEAD, POST, PUT, DELETE, OPTIONS, MKCOL, PROPFIND, PROPPATCH, COPY, MOVE, LOCK, UNLOCK");
    response.set("DAV", "1, 2");
    response.set("MS-Author-Via", "DAV");
    
    // Set content type and send empty response body
    response.setContentType("text/plain");
    response.setContentLength(0);
    response.send();
}

std::string WebDAVRequestHandler::extractTenantFromHost(const std::string& host) {
    return webdav::extractTenantFromHostname(host);
}

bool WebDAVRequestHandler::authenticateUser(Poco::Net::HTTPServerRequest& request, std::string& user, std::string& tenant, std::vector<std::string>& roles) {
    // Check for Authorization header
    std::string auth_header = request.get("Authorization", "");
    webdav::debugLog("Processing authentication request with auth header length: " + std::to_string(auth_header.length()));
    
    if (auth_header.empty()) {
        webdav::debugLog("No Authorization header found in request");
        return false;
    }
    
    // Handle Basic Authentication
    if (auth_header.substr(0, 5) == "Basic") {
        webdav::debugLog("Processing Basic authentication for user");
        std::string encoded_credentials = trim(auth_header.substr(6));
        
        // Decode Base64 credentials
        std::istringstream istr(encoded_credentials);
        std::ostringstream ostr;
        Poco::Base64Decoder b64in(istr);
        Poco::StreamCopier::copyStream(b64in, ostr);
        std::string credentials = ostr.str();
        size_t colon_pos = credentials.find(':');
        if (colon_pos == std::string::npos) {
            webdav::debugLog("Invalid credentials format - no colon found");
            return false;
        }
        
        std::string username = credentials.substr(0, colon_pos);
        std::string password = credentials.substr(colon_pos + 1);
        
        webdav::debugLog("Attempting to authenticate user: " + username);
        
        // Authenticate with LDAP
        UserInfo user_info = ldap_auth_->authenticateUser(username, password);
        if (!user_info.authenticated) {
            webdav::debugLog("LDAP authentication failed for user: " + username);
            return false;
        }
        
        // Log the roles loaded from LDAP
        std::string roles_str = [&user_info]() {
            std::string roles_list;
            for (size_t i = 0; i < user_info.roles.size(); ++i) {
                if (i > 0) roles_list += ", ";
                roles_list += user_info.roles[i];
            }
            return roles_list.empty() ? "none" : roles_list;
        }();

        webdav::debugLog("LDAP authentication successful for user: " + username +
                         " (tenant: " + user_info.tenant + ")" +
                         " with roles: [" + roles_str + "]");
        
        user = user_info.user_id;
        tenant = user_info.tenant.empty() ? tenant : user_info.tenant; // Use extracted tenant if available
        roles = user_info.roles;
        
        return true;
    }
    
    webdav::debugLog("Unsupported authentication scheme: " + auth_header.substr(0, auth_header.find(' ')));
    
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
          webdav::getEnvOrDefault("FILEENGINE_LDAP_BIND_PASSWORD", "admin"),
          webdav::getEnvOrDefault("FILEENGINE_LDAP_TENANT_BASE", "ou=tenants,dc=rationalboxes,dc=com"),
          webdav::getEnvOrDefault("FILEENGINE_LDAP_USER_BASE", "ou=users,dc=rationalboxes,dc=com")
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
    auto* factory = new WebDAVRequestHandlerFactory(grpc_client_, path_resolver_, ldap_auth_);
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