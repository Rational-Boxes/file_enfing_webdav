#ifndef PATH_RESOLVER_H
#define PATH_RESOLVER_H

#include <string>
#include <unordered_map>
#include <memory>
#include <mutex>
#include <pqxx/pqxx> // PostgreSQL C++ client library
#include <queue>

#include "grpc_client_wrapper.h"

namespace webdav {

class PathResolver {
public:
    PathResolver(std::shared_ptr<GRPCClientWrapper> grpc_client);

    // Resolve a path to a UUID
    std::string resolvePathToUUID(const std::string& path, const std::string& tenant);

    // Resolve a UUID to a path
    std::string resolveUUIDToPath(const std::string& uuid, const std::string& tenant);

    // Create a new path-to-UUID mapping
    bool createPathMapping(const std::string& path, const std::string& uuid, const std::string& tenant);

    // Remove a path-to-UUID mapping
    bool removePathMapping(const std::string& path, const std::string& tenant);

    // Check if a path exists
    bool pathExists(const std::string& path, const std::string& tenant);

    // Get parent UUID from a path
    std::string getParentUUID(const std::string& path, const std::string& tenant);

private:
    std::shared_ptr<GRPCClientWrapper> grpc_client_;
};

} // namespace webdav

#endif // PATH_RESOLVER_H