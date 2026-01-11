#ifndef PATH_RESOLVER_H
#define PATH_RESOLVER_H

#include <string>
#include <unordered_map>
#include <memory>
#include <mutex>
#include <pqxx/pqxx> // PostgreSQL C++ client library

#include "grpc_client_wrapper.h"

namespace webdav {

class PathResolver {
public:
    PathResolver(std::shared_ptr<GRPCClientWrapper> grpc_client, 
                 const std::string& db_connection_string);
    
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
    pqxx::connection conn_;
    
    // Simple in-memory cache for frequently accessed paths
    std::unordered_map<std::string, std::string> path_to_uuid_cache_; // path -> uuid
    std::unordered_map<std::string, std::string> uuid_to_path_cache_; // uuid -> path
    mutable std::mutex cache_mutex_;
    
    // Helper function to get tenant-specific cache key
    std::string getCacheKey(const std::string& path, const std::string& tenant);
    
    // Database operations
    std::string getPathFromDB(const std::string& path, const std::string& tenant);
    std::string getUUIDFromDB(const std::string& uuid, const std::string& tenant);
    bool insertPathToDB(const std::string& path, const std::string& uuid, const std::string& tenant);
    bool deletePathFromDB(const std::string& path, const std::string& tenant);
};

} // namespace webdav

#endif // PATH_RESOLVER_H