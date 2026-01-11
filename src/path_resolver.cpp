#include "path_resolver.h"
#include <iostream>
#include <algorithm>
#include <stdexcept>

namespace webdav {

PathResolver::PathResolver(std::shared_ptr<GRPCClientWrapper> grpc_client,
                         const std::string& db_connection_string)
    : grpc_client_(grpc_client), db_connection_string_(db_connection_string) {
    // Initialize the connection pool with a few connections
    initializeConnectionPool();
}

void PathResolver::initializeConnectionPool() {
    std::lock_guard<std::mutex> lock(pool_mutex_);

    // Create initial connections for the pool
    for (size_t i = 0; i < 3; ++i) {  // Start with 3 connections
        try {
            auto conn = std::make_unique<pqxx::connection>(db_connection_string_);

            // Initialize the database table if it doesn't exist
            pqxx::work txn(*conn);
            txn.exec("CREATE TABLE IF NOT EXISTS path_mappings ("
                     "id SERIAL PRIMARY KEY, "
                     "path TEXT NOT NULL, "
                     "uuid TEXT NOT NULL, "
                     "tenant TEXT NOT NULL, "
                     "created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, "
                     "UNIQUE(path, tenant))");
            txn.commit();

            available_connections_.push(conn.get());
            connection_pool_.push_back(std::move(conn));
        } catch (const std::exception& e) {
            std::cerr << "Failed to initialize connection pool: " << e.what() << std::endl;
            throw;
        }
    }
}

pqxx::connection* PathResolver::getConnection() {
    std::lock_guard<std::mutex> lock(pool_mutex_);

    if (!available_connections_.empty()) {
        pqxx::connection* conn = available_connections_.front();
        available_connections_.pop();
        return conn;
    }

    // If pool is exhausted and we haven't reached max size, create a new connection
    if (connection_pool_.size() < MAX_POOL_SIZE) {
        try {
            auto conn = std::make_unique<pqxx::connection>(db_connection_string_);
            pqxx::connection* raw_conn = conn.get();
            available_connections_.push(raw_conn);
            connection_pool_.push_back(std::move(conn));
            return raw_conn;
        } catch (const std::exception& e) {
            std::cerr << "Failed to create new connection: " << e.what() << std::endl;
            return nullptr;
        }
    }

    // Pool is full, wait or return null (in a real implementation, you might want to wait)
    return nullptr;
}

void PathResolver::returnConnection(pqxx::connection* conn) {
    if (conn) {
        std::lock_guard<std::mutex> lock(pool_mutex_);
        available_connections_.push(conn);
    }
}

// Remove the ensureConnection method since we're using connection pooling

std::string PathResolver::resolvePathToUUID(const std::string& path, const std::string& tenant) {
    std::string cached_uuid;

    // First, try to get from cache
    {
        std::lock_guard<std::mutex> lock(cache_mutex_);
        auto it = path_to_uuid_cache_.find(getCacheKey(path, tenant));
        if (it != path_to_uuid_cache_.end()) {
            // Check if cache entry is still valid
            if (std::chrono::steady_clock::now() < it->second.expiry_time) {
                cached_uuid = it->second.value;
            } else {
                // Entry expired, remove it
                path_to_uuid_cache_.erase(it);
            }
        }
    }

    // If we found a valid cached entry, return it
    if (!cached_uuid.empty()) {
        return cached_uuid;
    }

    // If not in cache or expired, get from DB
    std::string uuid = getPathFromDB(path, tenant);
    if (!uuid.empty()) {
        // Add to cache with TTL
        std::lock_guard<std::mutex> lock(cache_mutex_);
        CacheEntry entry;
        entry.value = uuid;
        entry.expiry_time = std::chrono::steady_clock::now() + CACHE_TTL;
        path_to_uuid_cache_[getCacheKey(path, tenant)] = entry;
    }

    return uuid;
}

std::string PathResolver::resolveUUIDToPath(const std::string& uuid, const std::string& tenant) {
    std::string cached_path;

    // First, try to get from cache
    {
        std::lock_guard<std::mutex> lock(cache_mutex_);
        auto it = uuid_to_path_cache_.find(getCacheKey(uuid, tenant));
        if (it != uuid_to_path_cache_.end()) {
            // Check if cache entry is still valid
            if (std::chrono::steady_clock::now() < it->second.expiry_time) {
                cached_path = it->second.value;
            } else {
                // Entry expired, remove it
                uuid_to_path_cache_.erase(it);
            }
        }
    }

    // If we found a valid cached entry, return it
    if (!cached_path.empty()) {
        return cached_path;
    }

    // If not in cache or expired, we need to search in the database
    // Note: This is inefficient but necessary for reverse lookup
    pqxx::connection* conn = getConnection();
    if (!conn) {
        std::cerr << "Failed to get database connection" << std::endl;
        return "";
    }

    std::string result_path;
    try {
        pqxx::work txn(*conn);
        auto result = txn.exec_params(
            "SELECT path FROM path_mappings WHERE uuid = $1 AND tenant = $2",
            uuid, tenant
        );

        if (!result.empty()) {
            result_path = result[0]["path"].c_str();

            // Add to cache with TTL
            std::lock_guard<std::mutex> lock(cache_mutex_);
            CacheEntry entry;
            entry.value = result_path;
            entry.expiry_time = std::chrono::steady_clock::now() + CACHE_TTL;
            uuid_to_path_cache_[getCacheKey(uuid, tenant)] = entry;
        }
        txn.commit();
    } catch (const std::exception& e) {
        std::cerr << "Failed to resolve UUID to path: " << e.what() << std::endl;
        // Don't commit on error
    }

    // Return the connection to the pool
    returnConnection(conn);

    return result_path;
}

bool PathResolver::createPathMapping(const std::string& path, const std::string& uuid, const std::string& tenant) {
    pqxx::connection* conn = getConnection();
    if (!conn) {
        std::cerr << "Failed to get database connection" << std::endl;
        return false;
    }

    bool success = false;
    try {
        // Insert into database
        pqxx::work txn(*conn);
        auto result = txn.exec_params(
            "INSERT INTO path_mappings (path, uuid, tenant) VALUES ($1, $2, $3) "
            "ON CONFLICT (path, tenant) DO UPDATE SET uuid = $2",
            path, uuid, tenant
        );
        txn.commit();
        success = true;
    } catch (const std::exception& e) {
        std::cerr << "Failed to create path mapping: " << e.what() << std::endl;
        // Don't commit on error
    }

    // Return the connection to the pool
    returnConnection(conn);

    if (success) {
        // Add to cache with TTL
        std::lock_guard<std::mutex> lock(cache_mutex_);
        CacheEntry path_entry;
        path_entry.value = uuid;
        path_entry.expiry_time = std::chrono::steady_clock::now() + CACHE_TTL;
        path_to_uuid_cache_[getCacheKey(path, tenant)] = path_entry;

        CacheEntry uuid_entry;
        uuid_entry.value = path;
        uuid_entry.expiry_time = std::chrono::steady_clock::now() + CACHE_TTL;
        uuid_to_path_cache_[getCacheKey(uuid, tenant)] = uuid_entry;
    }

    return success;
}

bool PathResolver::removePathMapping(const std::string& path, const std::string& tenant) {
    pqxx::connection* conn = getConnection();
    if (!conn) {
        std::cerr << "Failed to get database connection" << std::endl;
        return false;
    }

    bool success = false;
    try {
        // Remove from database
        pqxx::work txn(*conn);
        auto result = txn.exec_params(
            "DELETE FROM path_mappings WHERE path = $1 AND tenant = $2",
            path, tenant
        );
        txn.commit();
        success = true;
    } catch (const std::exception& e) {
        std::cerr << "Failed to remove path mapping: " << e.what() << std::endl;
        // Don't commit on error
    }

    // Return the connection to the pool
    returnConnection(conn);

    if (success) {
        // Remove from cache
        std::lock_guard<std::mutex> lock(cache_mutex_);
        auto path_key = getCacheKey(path, tenant);
        auto uuid_it = path_to_uuid_cache_.find(path_key);
        if (uuid_it != path_to_uuid_cache_.end()) {
            auto uuid_key = getCacheKey(uuid_it->second.value, tenant);
            uuid_to_path_cache_.erase(uuid_key);
        }
        path_to_uuid_cache_.erase(path_key);
    }

    return success;
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
    pqxx::connection* conn = getConnection();
    if (!conn) {
        std::cerr << "Failed to get database connection" << std::endl;
        return "";
    }

    std::string result_uuid;
    try {
        pqxx::work txn(*conn);
        auto result = txn.exec_params(
            "SELECT uuid FROM path_mappings WHERE path = $1 AND tenant = $2",
            path, tenant
        );

        if (!result.empty()) {
            result_uuid = result[0]["uuid"].c_str();
        }
        txn.commit();
    } catch (const std::exception& e) {
        std::cerr << "Failed to get path from DB: " << e.what() << std::endl;
        // Don't commit on error
    }

    // Return the connection to the pool
    returnConnection(conn);

    return result_uuid;
}

std::string PathResolver::getUUIDFromDB(const std::string& uuid, const std::string& tenant) {
    pqxx::connection* conn = getConnection();
    if (!conn) {
        std::cerr << "Failed to get database connection" << std::endl;
        return "";
    }

    std::string result_path;
    try {
        pqxx::work txn(*conn);
        auto result = txn.exec_params(
            "SELECT path FROM path_mappings WHERE uuid = $1 AND tenant = $2",
            uuid, tenant
        );

        if (!result.empty()) {
            result_path = result[0]["path"].c_str();
        }
        txn.commit();
    } catch (const std::exception& e) {
        std::cerr << "Failed to get UUID from DB: " << e.what() << std::endl;
        // Don't commit on error
    }

    // Return the connection to the pool
    returnConnection(conn);

    return result_path;
}

bool PathResolver::insertPathToDB(const std::string& path, const std::string& uuid, const std::string& tenant) {
    pqxx::connection* conn = getConnection();
    if (!conn) {
        std::cerr << "Failed to get database connection" << std::endl;
        return false;
    }

    bool success = false;
    try {
        pqxx::work txn(*conn);
        txn.exec_params(
            "INSERT INTO path_mappings (path, uuid, tenant) VALUES ($1, $2, $3)",
            path, uuid, tenant
        );
        txn.commit();
        success = true;
    } catch (const std::exception& e) {
        std::cerr << "Failed to insert path to DB: " << e.what() << std::endl;
        // Don't commit on error
    }

    // Return the connection to the pool
    returnConnection(conn);

    return success;
}

bool PathResolver::deletePathFromDB(const std::string& path, const std::string& tenant) {
    pqxx::connection* conn = getConnection();
    if (!conn) {
        std::cerr << "Failed to get database connection" << std::endl;
        return false;
    }

    bool success = false;
    try {
        pqxx::work txn(*conn);
        txn.exec_params(
            "DELETE FROM path_mappings WHERE path = $1 AND tenant = $2",
            path, tenant
        );
        txn.commit();
        success = true;
    } catch (const std::exception& e) {
        std::cerr << "Failed to delete path from DB: " << e.what() << std::endl;
        // Don't commit on error
    }

    // Return the connection to the pool
    returnConnection(conn);

    return success;
}

} // namespace webdav