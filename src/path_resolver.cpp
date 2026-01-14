#include "path_resolver.h"
#include <iostream>
#include <algorithm>
#include <stdexcept>
#include <unordered_map>
#include <mutex>

namespace webdav {

PathResolver::PathResolver(std::shared_ptr<GRPCClientWrapper> grpc_client)
    : grpc_client_(grpc_client) {
    // Initialize with in-memory storage instead of database
    // Initialize root path mapping for both "default" tenant and empty string (default tenant)
    createPathMapping("/", "", "default"); // Empty UUID represents root, "default" tenant
    createPathMapping("/", "", ""); // Also map to empty string tenant for compatibility
}

std::string PathResolver::resolvePathToUUID(const std::string& path, const std::string& tenant) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = path_to_uuid_map_.find(getCacheKey(path, tenant));
    if (it != path_to_uuid_map_.end()) {
        return it->second;
    }

    // If not found and tenant is not empty, try with empty tenant (for default tenant)
    if (!tenant.empty()) {
        it = path_to_uuid_map_.find(getCacheKey(path, ""));
        if (it != path_to_uuid_map_.end()) {
            return it->second;
        }
    }

    // If not found and tenant is empty, try with "default" tenant
    if (tenant.empty()) {
        it = path_to_uuid_map_.find(getCacheKey(path, "default"));
        if (it != path_to_uuid_map_.end()) {
            return it->second;
        }
    }

    return "";
}

std::string PathResolver::resolveUUIDToPath(const std::string& uuid, const std::string& tenant) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = uuid_to_path_map_.find(getCacheKey(uuid, tenant));
    if (it != uuid_to_path_map_.end()) {
        return it->second;
    }

    // If not found and tenant is not empty, try with empty tenant (for default tenant)
    if (!tenant.empty()) {
        it = uuid_to_path_map_.find(getCacheKey(uuid, ""));
        if (it != uuid_to_path_map_.end()) {
            return it->second;
        }
    }

    // If not found and tenant is empty, try with "default" tenant
    if (tenant.empty()) {
        it = uuid_to_path_map_.find(getCacheKey(uuid, "default"));
        if (it != uuid_to_path_map_.end()) {
            return it->second;
        }
    }

    return "";
}

bool PathResolver::createPathMapping(const std::string& path, const std::string& uuid, const std::string& tenant) {
    std::lock_guard<std::mutex> lock(mutex_);
    std::string path_key = getCacheKey(path, tenant);
    std::string uuid_key = getCacheKey(uuid, tenant);
    
    path_to_uuid_map_[path_key] = uuid;
    uuid_to_path_map_[uuid_key] = path;
    
    return true;
}

bool PathResolver::removePathMapping(const std::string& path, const std::string& tenant) {
    std::lock_guard<std::mutex> lock(mutex_);
    std::string path_key = getCacheKey(path, tenant);
    
    auto path_it = path_to_uuid_map_.find(path_key);
    if (path_it != path_to_uuid_map_.end()) {
        std::string uuid = path_it->second;
        std::string uuid_key = getCacheKey(uuid, tenant);
        
        path_to_uuid_map_.erase(path_it);
        uuid_to_path_map_.erase(uuid_key);
    }
    
    return true;
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

} // namespace webdav