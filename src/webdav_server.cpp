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
        response.setContentType("text/plain");
        std::ostream& ostr = response.send();
        ostr << "Authentication required";
        return;
    }

    // For now, without database, we'll need to work differently
    // In a real implementation with direct gRPC access, we might need to implement
    // a different approach to map paths to UUIDs without a database
    // For now, we'll return a not implemented response
    response.setStatus(Poco::Net::HTTPResponse::HTTP_NOT_IMPLEMENTED);
    response.setReason("Not Implemented");
    response.setContentType("text/plain");
    std::ostream& ostr = response.send();
    ostr << "GET method requires path-to-UUID mapping which needs database or alternative implementation";
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

    // For now, without database, we'll need to work differently
    // In a real implementation, this would require a different approach
    // to map paths to UUIDs without a database
    response.setStatus(Poco::Net::HTTPResponse::HTTP_NOT_IMPLEMENTED);
    response.setReason("Not Implemented");
    response.setContentType("text/plain");
    std::ostream& ostr = response.send();
    ostr << "PUT method requires path-to-UUID mapping which needs database or alternative implementation";
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
        response.setContentType("text/plain");
        std::ostream& ostr = response.send();
        ostr << "Authentication required";
        return;
    }

    // For now, without database, we'll need to work differently
    // In a real implementation, this would require a different approach
    // to map paths to UUIDs without a database
    response.setStatus(Poco::Net::HTTPResponse::HTTP_NOT_IMPLEMENTED);
    response.setReason("Not Implemented");
    response.setContentType("text/plain");
    std::ostream& ostr = response.send();
    ostr << "MKCOL method requires path-to-UUID mapping which needs database or alternative implementation";
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

    // For now, without database, we'll need to work differently
    // In a real implementation, this would require a different approach
    // to map paths to UUIDs without a database
    response.setStatus(Poco::Net::HTTPResponse::HTTP_NOT_IMPLEMENTED);
    response.setReason("Not Implemented");
    response.setContentType("text/plain");
    std::ostream& ostr = response.send();
    ostr << "DELETE method requires path-to-UUID mapping which needs database or alternative implementation";
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

    // For now, without database, we'll need to work differently
    // In a real implementation, this would require a different approach
    // to map paths to UUIDs without a database
    response.setStatus(Poco::Net::HTTPResponse::HTTP_NOT_IMPLEMENTED);
    response.setReason("Not Implemented");
    response.setContentType("text/plain");
    std::ostream& ostr = response.send();
    ostr << "PROPFIND method requires path-to-UUID mapping which needs database or alternative implementation";
}

void WebDAVRequestHandler::handleProppatch(Poco::Net::HTTPServerRequest& request, Poco::Net::HTTPServerResponse& response) {
    response.setStatus(Poco::Net::HTTPResponse::HTTP_NOT_IMPLEMENTED);
    response.setReason("Not Implemented");
    response.setContentType("text/plain");
    std::ostream& ostr = response.send();
    ostr << "PROPPATCH not fully implemented";
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
        response.setContentType("text/plain");
        std::ostream& ostr = response.send();
        ostr << "Authentication required";
        return;
    }

    // For now, without database, we'll need to work differently
    // In a real implementation, this would require a different approach
    // to map paths to UUIDs without a database
    response.setStatus(Poco::Net::HTTPResponse::HTTP_NOT_IMPLEMENTED);
    response.setReason("Not Implemented");
    response.setContentType("text/plain");
    std::ostream& ostr = response.send();
    ostr << "COPY method requires path-to-UUID mapping which needs database or alternative implementation";
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
        response.setContentType("text/plain");
        std::ostream& ostr = response.send();
        ostr << "Authentication required";
        return;
    }

    // For now, without database, we'll need to work differently
    // In a real implementation, this would require a different approach
    // to map paths to UUIDs without a database
    response.setStatus(Poco::Net::HTTPResponse::HTTP_NOT_IMPLEMENTED);
    response.setReason("Not Implemented");
    response.setContentType("text/plain");
    std::ostream& ostr = response.send();
    ostr << "MOVE method requires path-to-UUID mapping which needs database or alternative implementation";
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
    webdav::debugLog("Processing authentication request with auth header length: " + std::to_string(auth_header.length()));
    
    if (auth_header.empty()) {
        webdav::debugLog("No Authorization header found in request");
        return false;
    }
    
    // Handle Basic Authentication
    if (auth_header.substr(0, 5) == "Basic") {
        webdav::debugLog("Processing Basic authentication");
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
        
        webdav::debugLog("LDAP authentication successful for user: " + username + " with roles: " +
                         [&user_info]() {
                             std::string roles_str;
                             for (size_t i = 0; i < user_info.roles.size(); ++i) {
                                 if (i > 0) roles_str += ",";
                                 roles_str += user_info.roles[i];
                             }
                             return roles_str;
                         }());
        
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