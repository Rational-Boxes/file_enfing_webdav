#include "path_resolver.h"
#include <iostream>
#include <algorithm>
#include <stdexcept>

namespace webdav {

PathResolver::PathResolver(std::shared_ptr<GRPCClientWrapper> grpc_client, 
                         const std::string& db_connection_string)
    : grpc_client_(grpc_client), conn_(db_connection_string) {
    // Initialize the database table if it doesn't exist
    try {
        pqxx::work txn(conn_);
        txn.exec("CREATE TABLE IF NOT EXISTS path_mappings ("
                 "id SERIAL PRIMARY KEY, "
                 "path TEXT NOT NULL, "
                 "uuid TEXT NOT NULL, "
                 "tenant TEXT NOT NULL, "
                 "created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, "
                 "UNIQUE(path, tenant))");
        txn.commit();
    } catch (const std::exception& e) {
        std::cerr << "Failed to initialize path mappings table: " << e.what() << std::endl;
        throw;
    }
}

std::string PathResolver::resolvePathToUUID(const std::string& path, const std::string& tenant) {
    // First, try to get from cache
    {
        std::lock_guard<std::mutex> lock(cache_mutex_);
        auto it = path_to_uuid_cache_.find(getCacheKey(path, tenant));
        if (it != path_to_uuid_cache_.end()) {
            return it->second;
        }
    }

    // If not in cache, get from DB
    std::string uuid = getPathFromDB(path, tenant);
    if (!uuid.empty()) {
        // Add to cache
        std::lock_guard<std::mutex> lock(cache_mutex_);
        path_to_uuid_cache_[getCacheKey(path, tenant)] = uuid;
    }

    return uuid;
}

std::string PathResolver::resolveUUIDToPath(const std::string& uuid, const std::string& tenant) {
    // First, try to get from cache
    {
        std::lock_guard<std::mutex> lock(cache_mutex_);
        auto it = uuid_to_path_cache_.find(getCacheKey(uuid, tenant));
        if (it != uuid_to_path_cache_.end()) {
            return it->second;
        }
    }

    // If not in cache, we need to search in the database
    // Note: This is inefficient but necessary for reverse lookup
    try {
        pqxx::work txn(conn_);
        auto result = txn.exec_params(
            "SELECT path FROM path_mappings WHERE uuid = $1 AND tenant = $2",
            uuid, tenant
        );
        
        if (!result.empty()) {
            std::string path = result[0]["path"].c_str();
            
            // Add to cache
            std::lock_guard<std::mutex> lock(cache_mutex_);
            uuid_to_path_cache_[getCacheKey(uuid, tenant)] = path;
            
            return path;
        }
    } catch (const std::exception& e) {
        std::cerr << "Failed to resolve UUID to path: " << e.what() << std::endl;
    }

    return "";
}

bool PathResolver::createPathMapping(const std::string& path, const std::string& uuid, const std::string& tenant) {
    try {
        // Insert into database
        pqxx::work txn(conn_);
        auto result = txn.exec_params(
            "INSERT INTO path_mappings (path, uuid, tenant) VALUES ($1, $2, $3) "
            "ON CONFLICT (path, tenant) DO UPDATE SET uuid = $2",
            path, uuid, tenant
        );
        txn.commit();

        // Add to cache
        std::lock_guard<std::mutex> lock(cache_mutex_);
        path_to_uuid_cache_[getCacheKey(path, tenant)] = uuid;
        uuid_to_path_cache_[getCacheKey(uuid, tenant)] = path;

        return true;
    } catch (const std::exception& e) {
        std::cerr << "Failed to create path mapping: " << e.what() << std::endl;
        return false;
    }
}

bool PathResolver::removePathMapping(const std::string& path, const std::string& tenant) {
    try {
        // Remove from database
        pqxx::work txn(conn_);
        auto result = txn.exec_params(
            "DELETE FROM path_mappings WHERE path = $1 AND tenant = $2",
            path, tenant
        );
        txn.commit();

        // Remove from cache
        std::lock_guard<std::mutex> lock(cache_mutex_);
        auto path_key = getCacheKey(path, tenant);
        auto uuid_it = path_to_uuid_cache_.find(path_key);
        if (uuid_it != path_to_uuid_cache_.end()) {
            auto uuid_key = getCacheKey(uuid_it->second, tenant);
            uuid_to_path_cache_.erase(uuid_key);
        }
        path_to_uuid_cache_.erase(path_key);

        return true;
    } catch (const std::exception& e) {
        std::cerr << "Failed to remove path mapping: " << e.what() << std::endl;
        return false;
    }
}

bool PathResolver::pathExists(const std::string& path, const std::string& tenant) {
    return !resolvePathToUUID(path, tenant).empty();
}

std::string PathResolver::getParentUUID(const std::string& path, const std::string& tenant) {
    if (path == "/" || path.empty()) {
        return ""; // Root has no parent
    }

    // Find the parent path
    std::string parent_path = path;
    size_t pos = parent_path.find_last_of('/');
    if (pos != std::string::npos) {
        if (pos == 0) {
            parent_path = "/"; // Parent of "/something" is "/"
        } else {
            parent_path = parent_path.substr(0, pos);
        }
    }

    return resolvePathToUUID(parent_path, tenant);
}

std::string PathResolver::getCacheKey(const std::string& path, const std::string& tenant) {
    return tenant + ":" + path;
}

std::string PathResolver::getPathFromDB(const std::string& path, const std::string& tenant) {
    try {
        pqxx::work txn(conn_);
        auto result = txn.exec_params(
            "SELECT uuid FROM path_mappings WHERE path = $1 AND tenant = $2",
            path, tenant
        );
        
        if (!result.empty()) {
            return result[0]["uuid"].c_str();
        }
    } catch (const std::exception& e) {
        std::cerr << "Failed to get path from DB: " << e.what() << std::endl;
    }
    
    return "";
}

std::string PathResolver::getUUIDFromDB(const std::string& uuid, const std::string& tenant) {
    try {
        pqxx::work txn(conn_);
        auto result = txn.exec_params(
            "SELECT path FROM path_mappings WHERE uuid = $1 AND tenant = $2",
            uuid, tenant
        );
        
        if (!result.empty()) {
            return result[0]["path"].c_str();
        }
    } catch (const std::exception& e) {
        std::cerr << "Failed to get UUID from DB: " << e.what() << std::endl;
    }
    
    return "";
}

bool PathResolver::insertPathToDB(const std::string& path, const std::string& uuid, const std::string& tenant) {
    try {
        pqxx::work txn(conn_);
        txn.exec_params(
            "INSERT INTO path_mappings (path, uuid, tenant) VALUES ($1, $2, $3)",
            path, uuid, tenant
        );
        txn.commit();
        return true;
    } catch (const std::exception& e) {
        std::cerr << "Failed to insert path to DB: " << e.what() << std::endl;
        return false;
    }
}

bool PathResolver::deletePathFromDB(const std::string& path, const std::string& tenant) {
    try {
        pqxx::work txn(conn_);
        txn.exec_params(
            "DELETE FROM path_mappings WHERE path = $1 AND tenant = $2",
            path, tenant
        );
        txn.commit();
        return true;
    } catch (const std::exception& e) {
        std::cerr << "Failed to delete path from DB: " << e.what() << std::endl;
        return false;
    }
}

} // namespace webdav