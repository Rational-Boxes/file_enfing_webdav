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
    std::string db_connection_string_;
    // Connection pool for concurrent access
    std::vector<std::unique_ptr<pqxx::connection>> connection_pool_;
    std::queue<pqxx::connection*> available_connections_;
    mutable std::mutex pool_mutex_;
    static constexpr size_t MAX_POOL_SIZE = 10;

    // Cache for path-to-UUID mappings with TTL to handle cache coherency
    struct CacheEntry {
        std::string value;
        std::chrono::steady_clock::time_point expiry_time;
    };

    std::unordered_map<std::string, CacheEntry> path_to_uuid_cache_; // path -> uuid
    std::unordered_map<std::string, CacheEntry> uuid_to_path_cache_; // uuid -> path
    mutable std::mutex cache_mutex_;

    // Cache TTL (Time To Live) to ensure cache coherency with external changes
    static constexpr std::chrono::seconds CACHE_TTL = std::chrono::seconds(30);
    
    // Helper function to get tenant-specific cache key
    std::string getCacheKey(const std::string& path, const std::string& tenant);

    // Database operations
    std::string getPathFromDB(const std::string& path, const std::string& tenant);
    std::string getUUIDFromDB(const std::string& uuid, const std::string& tenant);
    bool insertPathToDB(const std::string& path, const std::string& uuid, const std::string& tenant);
    bool deletePathFromDB(const std::string& path, const std::string& tenant);

    // Connection pool management
    void initializeConnectionPool();
    pqxx::connection* getConnection();
    void returnConnection(pqxx::connection* conn);
};

} // namespace webdav

#endif // PATH_RESOLVER_H