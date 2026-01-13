#ifndef GRPC_CLIENT_WRAPPER_H
#define GRPC_CLIENT_WRAPPER_H

#include <grpcpp/grpcpp.h>
#include <memory>
#include <string>

#include "fileservice.grpc.pb.h"
#include "utils.h"  // For logging functions

namespace webdav {

struct AuthenticationContext {
    std::string user;
    std::vector<std::string> roles;
    std::string tenant;
    std::map<std::string, std::string> claims;
};

class GRPCClientWrapper {
public:
    GRPCClientWrapper(const std::string& server_address);
    ~GRPCClientWrapper();

    // Directory operations
    fileengine_rpc::MakeDirectoryResponse makeDirectory(const fileengine_rpc::MakeDirectoryRequest& request);
    fileengine_rpc::RemoveDirectoryResponse removeDirectory(const fileengine_rpc::RemoveDirectoryRequest& request);
    fileengine_rpc::ListDirectoryResponse listDirectory(const fileengine_rpc::ListDirectoryRequest& request);
    fileengine_rpc::ListDirectoryWithDeletedResponse listDirectoryWithDeleted(const fileengine_rpc::ListDirectoryWithDeletedRequest& request);

    // File operations
    fileengine_rpc::TouchResponse touch(const fileengine_rpc::TouchRequest& request);
    fileengine_rpc::RemoveFileResponse removeFile(const fileengine_rpc::RemoveFileRequest& request);
    fileengine_rpc::UndeleteFileResponse undeleteFile(const fileengine_rpc::UndeleteFileRequest& request);
    fileengine_rpc::PutFileResponse putFile(const fileengine_rpc::PutFileRequest& request);
    fileengine_rpc::GetFileResponse getFile(const fileengine_rpc::GetFileRequest& request);

    // File information
    fileengine_rpc::StatResponse stat(const fileengine_rpc::StatRequest& request);
    fileengine_rpc::ExistsResponse exists(const fileengine_rpc::ExistsRequest& request);

    // File manipulation operations
    fileengine_rpc::RenameResponse rename(const fileengine_rpc::RenameRequest& request);
    fileengine_rpc::MoveResponse move(const fileengine_rpc::MoveRequest& request);
    fileengine_rpc::CopyResponse copy(const fileengine_rpc::CopyRequest& request);

    // Version operations
    fileengine_rpc::ListVersionsResponse listVersions(const fileengine_rpc::ListVersionsRequest& request);
    fileengine_rpc::GetVersionResponse getVersion(const fileengine_rpc::GetVersionRequest& request);
    fileengine_rpc::RestoreToVersionResponse restoreToVersion(const fileengine_rpc::RestoreToVersionRequest& request);

    // Metadata operations
    fileengine_rpc::SetMetadataResponse setMetadata(const fileengine_rpc::SetMetadataRequest& request);
    fileengine_rpc::GetMetadataResponse getMetadata(const fileengine_rpc::GetMetadataRequest& request);
    fileengine_rpc::GetAllMetadataResponse getAllMetadata(const fileengine_rpc::GetAllMetadataRequest& request);
    fileengine_rpc::DeleteMetadataResponse deleteMetadata(const fileengine_rpc::DeleteMetadataRequest& request);
    fileengine_rpc::GetMetadataForVersionResponse getMetadataForVersion(const fileengine_rpc::GetMetadataForVersionRequest& request);
    fileengine_rpc::GetAllMetadataForVersionResponse getAllMetadataForVersion(const fileengine_rpc::GetAllMetadataForVersionRequest& request);

    // ACL operations
    fileengine_rpc::GrantPermissionResponse grantPermission(const fileengine_rpc::GrantPermissionRequest& request);
    fileengine_rpc::RevokePermissionResponse revokePermission(const fileengine_rpc::RevokePermissionRequest& request);
    fileengine_rpc::CheckPermissionResponse checkPermission(const fileengine_rpc::CheckPermissionRequest& request);

    // Administrative operations
    fileengine_rpc::StorageUsageResponse getStorageUsage(const fileengine_rpc::StorageUsageRequest& request);
    fileengine_rpc::PurgeOldVersionsResponse purgeOldVersions(const fileengine_rpc::PurgeOldVersionsRequest& request);
    fileengine_rpc::TriggerSyncResponse triggerSync(const fileengine_rpc::TriggerSyncRequest& request);

    // ACL management
    bool ensureDefaultACLs(const fileengine_rpc::AuthenticationContext& auth_ctx);

private:
    std::unique_ptr<fileengine_rpc::FileService::Stub> stub_;
    grpc::ChannelArguments channel_args_;
};

} // namespace webdav

#endif // GRPC_CLIENT_WRAPPER_H