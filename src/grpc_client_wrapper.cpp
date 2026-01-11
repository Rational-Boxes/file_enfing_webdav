#include "grpc_client_wrapper.h"
#include <iostream>
#include <memory>

namespace webdav {

GRPCClientWrapper::GRPCClientWrapper(const std::string& server_address) {
    auto channel = grpc::CreateCustomChannel(server_address, grpc::InsecureChannelCredentials(), channel_args_);
    stub_ = fileengine_rpc::FileService::NewStub(channel);
}

GRPCClientWrapper::~GRPCClientWrapper() = default;

// Directory operations
fileengine_rpc::MakeDirectoryResponse GRPCClientWrapper::makeDirectory(const fileengine_rpc::MakeDirectoryRequest& request) {
    fileengine_rpc::MakeDirectoryResponse response;
    grpc::ClientContext context;
    
    grpc::Status status = stub_->MakeDirectory(&context, request, &response);
    if (!status.ok()) {
        std::cerr << "MakeDirectory failed: " << status.error_message() << std::endl;
    }
    
    return response;
}

fileengine_rpc::RemoveDirectoryResponse GRPCClientWrapper::removeDirectory(const fileengine_rpc::RemoveDirectoryRequest& request) {
    fileengine_rpc::RemoveDirectoryResponse response;
    grpc::ClientContext context;
    
    grpc::Status status = stub_->RemoveDirectory(&context, request, &response);
    if (!status.ok()) {
        std::cerr << "RemoveDirectory failed: " << status.error_message() << std::endl;
    }
    
    return response;
}

fileengine_rpc::ListDirectoryResponse GRPCClientWrapper::listDirectory(const fileengine_rpc::ListDirectoryRequest& request) {
    fileengine_rpc::ListDirectoryResponse response;
    grpc::ClientContext context;
    
    grpc::Status status = stub_->ListDirectory(&context, request, &response);
    if (!status.ok()) {
        std::cerr << "ListDirectory failed: " << status.error_message() << std::endl;
    }
    
    return response;
}

fileengine_rpc::ListDirectoryWithDeletedResponse GRPCClientWrapper::listDirectoryWithDeleted(const fileengine_rpc::ListDirectoryWithDeletedRequest& request) {
    fileengine_rpc::ListDirectoryWithDeletedResponse response;
    grpc::ClientContext context;
    
    grpc::Status status = stub_->ListDirectoryWithDeleted(&context, request, &response);
    if (!status.ok()) {
        std::cerr << "ListDirectoryWithDeleted failed: " << status.error_message() << std::endl;
    }
    
    return response;
}

// File operations
fileengine_rpc::TouchResponse GRPCClientWrapper::touch(const fileengine_rpc::TouchRequest& request) {
    fileengine_rpc::TouchResponse response;
    grpc::ClientContext context;
    
    grpc::Status status = stub_->Touch(&context, request, &response);
    if (!status.ok()) {
        std::cerr << "Touch failed: " << status.error_message() << std::endl;
    }
    
    return response;
}

fileengine_rpc::RemoveFileResponse GRPCClientWrapper::removeFile(const fileengine_rpc::RemoveFileRequest& request) {
    fileengine_rpc::RemoveFileResponse response;
    grpc::ClientContext context;
    
    grpc::Status status = stub_->RemoveFile(&context, request, &response);
    if (!status.ok()) {
        std::cerr << "RemoveFile failed: " << status.error_message() << std::endl;
    }
    
    return response;
}

fileengine_rpc::UndeleteFileResponse GRPCClientWrapper::undeleteFile(const fileengine_rpc::UndeleteFileRequest& request) {
    fileengine_rpc::UndeleteFileResponse response;
    grpc::ClientContext context;
    
    grpc::Status status = stub_->UndeleteFile(&context, request, &response);
    if (!status.ok()) {
        std::cerr << "UndeleteFile failed: " << status.error_message() << std::endl;
    }
    
    return response;
}

fileengine_rpc::PutFileResponse GRPCClientWrapper::putFile(const fileengine_rpc::PutFileRequest& request) {
    fileengine_rpc::PutFileResponse response;
    grpc::ClientContext context;
    
    grpc::Status status = stub_->PutFile(&context, request, &response);
    if (!status.ok()) {
        std::cerr << "PutFile failed: " << status.error_message() << std::endl;
    }
    
    return response;
}

fileengine_rpc::GetFileResponse GRPCClientWrapper::getFile(const fileengine_rpc::GetFileRequest& request) {
    fileengine_rpc::GetFileResponse response;
    grpc::ClientContext context;
    
    grpc::Status status = stub_->GetFile(&context, request, &response);
    if (!status.ok()) {
        std::cerr << "GetFile failed: " << status.error_message() << std::endl;
    }
    
    return response;
}

// File information
fileengine_rpc::StatResponse GRPCClientWrapper::stat(const fileengine_rpc::StatRequest& request) {
    fileengine_rpc::StatResponse response;
    grpc::ClientContext context;
    
    grpc::Status status = stub_->Stat(&context, request, &response);
    if (!status.ok()) {
        std::cerr << "Stat failed: " << status.error_message() << std::endl;
    }
    
    return response;
}

fileengine_rpc::ExistsResponse GRPCClientWrapper::exists(const fileengine_rpc::ExistsRequest& request) {
    fileengine_rpc::ExistsResponse response;
    grpc::ClientContext context;
    
    grpc::Status status = stub_->Exists(&context, request, &response);
    if (!status.ok()) {
        std::cerr << "Exists failed: " << status.error_message() << std::endl;
    }
    
    return response;
}

// File manipulation operations
fileengine_rpc::RenameResponse GRPCClientWrapper::rename(const fileengine_rpc::RenameRequest& request) {
    fileengine_rpc::RenameResponse response;
    grpc::ClientContext context;
    
    grpc::Status status = stub_->Rename(&context, request, &response);
    if (!status.ok()) {
        std::cerr << "Rename failed: " << status.error_message() << std::endl;
    }
    
    return response;
}

fileengine_rpc::MoveResponse GRPCClientWrapper::move(const fileengine_rpc::MoveRequest& request) {
    fileengine_rpc::MoveResponse response;
    grpc::ClientContext context;
    
    grpc::Status status = stub_->Move(&context, request, &response);
    if (!status.ok()) {
        std::cerr << "Move failed: " << status.error_message() << std::endl;
    }
    
    return response;
}

fileengine_rpc::CopyResponse GRPCClientWrapper::copy(const fileengine_rpc::CopyRequest& request) {
    fileengine_rpc::CopyResponse response;
    grpc::ClientContext context;
    
    grpc::Status status = stub_->Copy(&context, request, &response);
    if (!status.ok()) {
        std::cerr << "Copy failed: " << status.error_message() << std::endl;
    }
    
    return response;
}

// Version operations
fileengine_rpc::ListVersionsResponse GRPCClientWrapper::listVersions(const fileengine_rpc::ListVersionsRequest& request) {
    fileengine_rpc::ListVersionsResponse response;
    grpc::ClientContext context;
    
    grpc::Status status = stub_->ListVersions(&context, request, &response);
    if (!status.ok()) {
        std::cerr << "ListVersions failed: " << status.error_message() << std::endl;
    }
    
    return response;
}

fileengine_rpc::GetVersionResponse GRPCClientWrapper::getVersion(const fileengine_rpc::GetVersionRequest& request) {
    fileengine_rpc::GetVersionResponse response;
    grpc::ClientContext context;
    
    grpc::Status status = stub_->GetVersion(&context, request, &response);
    if (!status.ok()) {
        std::cerr << "GetVersion failed: " << status.error_message() << std::endl;
    }
    
    return response;
}

fileengine_rpc::RestoreToVersionResponse GRPCClientWrapper::restoreToVersion(const fileengine_rpc::RestoreToVersionRequest& request) {
    fileengine_rpc::RestoreToVersionResponse response;
    grpc::ClientContext context;
    
    grpc::Status status = stub_->RestoreToVersion(&context, request, &response);
    if (!status.ok()) {
        std::cerr << "RestoreToVersion failed: " << status.error_message() << std::endl;
    }
    
    return response;
}

// Metadata operations
fileengine_rpc::SetMetadataResponse GRPCClientWrapper::setMetadata(const fileengine_rpc::SetMetadataRequest& request) {
    fileengine_rpc::SetMetadataResponse response;
    grpc::ClientContext context;
    
    grpc::Status status = stub_->SetMetadata(&context, request, &response);
    if (!status.ok()) {
        std::cerr << "SetMetadata failed: " << status.error_message() << std::endl;
    }
    
    return response;
}

fileengine_rpc::GetMetadataResponse GRPCClientWrapper::getMetadata(const fileengine_rpc::GetMetadataRequest& request) {
    fileengine_rpc::GetMetadataResponse response;
    grpc::ClientContext context;
    
    grpc::Status status = stub_->GetMetadata(&context, request, &response);
    if (!status.ok()) {
        std::cerr << "GetMetadata failed: " << status.error_message() << std::endl;
    }
    
    return response;
}

fileengine_rpc::GetAllMetadataResponse GRPCClientWrapper::getAllMetadata(const fileengine_rpc::GetAllMetadataRequest& request) {
    fileengine_rpc::GetAllMetadataResponse response;
    grpc::ClientContext context;
    
    grpc::Status status = stub_->GetAllMetadata(&context, request, &response);
    if (!status.ok()) {
        std::cerr << "GetAllMetadata failed: " << status.error_message() << std::endl;
    }
    
    return response;
}

fileengine_rpc::DeleteMetadataResponse GRPCClientWrapper::deleteMetadata(const fileengine_rpc::DeleteMetadataRequest& request) {
    fileengine_rpc::DeleteMetadataResponse response;
    grpc::ClientContext context;
    
    grpc::Status status = stub_->DeleteMetadata(&context, request, &response);
    if (!status.ok()) {
        std::cerr << "DeleteMetadata failed: " << status.error_message() << std::endl;
    }
    
    return response;
}

fileengine_rpc::GetMetadataForVersionResponse GRPCClientWrapper::getMetadataForVersion(const fileengine_rpc::GetMetadataForVersionRequest& request) {
    fileengine_rpc::GetMetadataForVersionResponse response;
    grpc::ClientContext context;
    
    grpc::Status status = stub_->GetMetadataForVersion(&context, request, &response);
    if (!status.ok()) {
        std::cerr << "GetMetadataForVersion failed: " << status.error_message() << std::endl;
    }
    
    return response;
}

fileengine_rpc::GetAllMetadataForVersionResponse GRPCClientWrapper::getAllMetadataForVersion(const fileengine_rpc::GetAllMetadataForVersionRequest& request) {
    fileengine_rpc::GetAllMetadataForVersionResponse response;
    grpc::ClientContext context;
    
    grpc::Status status = stub_->GetAllMetadataForVersion(&context, request, &response);
    if (!status.ok()) {
        std::cerr << "GetAllMetadataForVersion failed: " << status.error_message() << std::endl;
    }
    
    return response;
}

// ACL operations
fileengine_rpc::GrantPermissionResponse GRPCClientWrapper::grantPermission(const fileengine_rpc::GrantPermissionRequest& request) {
    fileengine_rpc::GrantPermissionResponse response;
    grpc::ClientContext context;
    
    grpc::Status status = stub_->GrantPermission(&context, request, &response);
    if (!status.ok()) {
        std::cerr << "GrantPermission failed: " << status.error_message() << std::endl;
    }
    
    return response;
}

fileengine_rpc::RevokePermissionResponse GRPCClientWrapper::revokePermission(const fileengine_rpc::RevokePermissionRequest& request) {
    fileengine_rpc::RevokePermissionResponse response;
    grpc::ClientContext context;
    
    grpc::Status status = stub_->RevokePermission(&context, request, &response);
    if (!status.ok()) {
        std::cerr << "RevokePermission failed: " << status.error_message() << std::endl;
    }
    
    return response;
}

fileengine_rpc::CheckPermissionResponse GRPCClientWrapper::checkPermission(const fileengine_rpc::CheckPermissionRequest& request) {
    fileengine_rpc::CheckPermissionResponse response;
    grpc::ClientContext context;
    
    grpc::Status status = stub_->CheckPermission(&context, request, &response);
    if (!status.ok()) {
        std::cerr << "CheckPermission failed: " << status.error_message() << std::endl;
    }
    
    return response;
}

// Administrative operations
fileengine_rpc::StorageUsageResponse GRPCClientWrapper::getStorageUsage(const fileengine_rpc::StorageUsageRequest& request) {
    fileengine_rpc::StorageUsageResponse response;
    grpc::ClientContext context;
    
    grpc::Status status = stub_->GetStorageUsage(&context, request, &response);
    if (!status.ok()) {
        std::cerr << "GetStorageUsage failed: " << status.error_message() << std::endl;
    }
    
    return response;
}

fileengine_rpc::PurgeOldVersionsResponse GRPCClientWrapper::purgeOldVersions(const fileengine_rpc::PurgeOldVersionsRequest& request) {
    fileengine_rpc::PurgeOldVersionsResponse response;
    grpc::ClientContext context;
    
    grpc::Status status = stub_->PurgeOldVersions(&context, request, &response);
    if (!status.ok()) {
        std::cerr << "PurgeOldVersions failed: " << status.error_message() << std::endl;
    }
    
    return response;
}

fileengine_rpc::TriggerSyncResponse GRPCClientWrapper::triggerSync(const fileengine_rpc::TriggerSyncRequest& request) {
    fileengine_rpc::TriggerSyncResponse response;
    grpc::ClientContext context;
    
    grpc::Status status = stub_->TriggerSync(&context, request, &response);
    if (!status.ok()) {
        std::cerr << "TriggerSync failed: " << status.error_message() << std::endl;
    }
    
    return response;
}

} // namespace webdav