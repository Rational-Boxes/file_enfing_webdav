#include "grpc_client_wrapper.h"
#include <iostream>
#include <memory>

namespace webdav {

GRPCClientWrapper::GRPCClientWrapper(const std::string& server_address) {
    webdav::debugLog("GRPCClientWrapper: Creating gRPC channel to: " + server_address);
    auto channel = grpc::CreateCustomChannel(server_address, grpc::InsecureChannelCredentials(), channel_args_);
    webdav::debugLog("GRPCClientWrapper: Channel created, creating stub");
    stub_ = fileengine_rpc::FileService::NewStub(channel);
    webdav::debugLog("GRPCClientWrapper: gRPC client initialized successfully");
}

GRPCClientWrapper::~GRPCClientWrapper() = default;

// Directory operations
fileengine_rpc::MakeDirectoryResponse GRPCClientWrapper::makeDirectory(const fileengine_rpc::MakeDirectoryRequest& request) {
    webdav::debugLog("gRPC MakeDirectory called with parent_uid: " + request.parent_uid() +
                     ", name: " + request.name() +
                     ", tenant: " + request.auth().tenant() +
                     ", user: " + request.auth().user());

    fileengine_rpc::MakeDirectoryResponse response;
    grpc::ClientContext context;

    grpc::Status status = stub_->MakeDirectory(&context, request, &response);
    if (!status.ok()) {
        webdav::errorLog("MakeDirectory failed: " + std::string(status.error_message()));
        // Set response as failure
        response.set_success(false);
        response.set_error(status.error_message());
    } else {
        webdav::debugLog("MakeDirectory succeeded, returned uid: " + response.uid());
        response.set_success(true);
    }

    return response;
}

fileengine_rpc::RemoveDirectoryResponse GRPCClientWrapper::removeDirectory(const fileengine_rpc::RemoveDirectoryRequest& request) {
    webdav::debugLog("gRPC RemoveDirectory called with uid: " + request.uid() +
                     ", tenant: " + request.auth().tenant() +
                     ", user: " + request.auth().user());

    fileengine_rpc::RemoveDirectoryResponse response;
    grpc::ClientContext context;

    grpc::Status status = stub_->RemoveDirectory(&context, request, &response);
    if (!status.ok()) {
        webdav::errorLog("RemoveDirectory failed: " + std::string(status.error_message()));
    } else {
        webdav::debugLog("RemoveDirectory succeeded for uid: " + request.uid());
    }

    return response;
}

fileengine_rpc::ListDirectoryResponse GRPCClientWrapper::listDirectory(const fileengine_rpc::ListDirectoryRequest& request) {
    webdav::debugLog("gRPC ListDirectory called with uid: " + request.uid() +
                     ", tenant: " + request.auth().tenant() +
                     ", user: " + request.auth().user() +
                     ", roles count: " + std::to_string(request.auth().roles_size()));

    // Log all roles in the request
    for (int i = 0; i < request.auth().roles_size(); i++) {
        webdav::debugLog("gRPC ListDirectory - role[" + std::to_string(i) + "]: " + request.auth().roles(i));
    }

    fileengine_rpc::ListDirectoryResponse response;
    grpc::ClientContext context;

    grpc::Status status = stub_->ListDirectory(&context, request, &response);
    if (!status.ok()) {
        webdav::errorLog("ListDirectory failed: " + std::string(status.error_message()) +
                         ", error code: " + std::to_string(status.error_code()));

        // Check if this is a permission error that might be resolved by checking ACLs
        if (status.error_code() == grpc::PERMISSION_DENIED || status.error_code() == grpc::NOT_FOUND) {
            webdav::debugLog("ListDirectory failed with permission error, this might be resolved by proper ACL configuration");
        }

        // Set response as failure
        response.set_success(false);
        response.set_error(status.error_message());
    } else {
        webdav::debugLog("ListDirectory succeeded, returned " + std::to_string(response.entries_size()) + " entries");
        response.set_success(true);
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
        webdav::errorLog("Touch failed: " + std::string(status.error_message()));
        // Set response as failure
        response.set_success(false);
        response.set_error(status.error_message());
    } else {
        response.set_success(true);
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
    webdav::debugLog("gRPC PutFile called with uid: " + request.uid() +
                     ", data size: " + std::to_string(request.data().size()) + " bytes" +
                     ", tenant: " + request.auth().tenant() +
                     ", user: " + request.auth().user());

    fileengine_rpc::PutFileResponse response;
    grpc::ClientContext context;

    grpc::Status status = stub_->PutFile(&context, request, &response);
    if (!status.ok()) {
        webdav::errorLog("PutFile failed: " + std::string(status.error_message()));
        // Set response as failure
        response.set_success(false);
        response.set_error(status.error_message());
    } else {
        webdav::debugLog("PutFile succeeded for uid: " + request.uid());
        response.set_success(true);
    }

    return response;
}

fileengine_rpc::GetFileResponse GRPCClientWrapper::getFile(const fileengine_rpc::GetFileRequest& request) {
    webdav::debugLog("gRPC GetFile called with uid: " + request.uid() +
                     ", version: " + request.version_timestamp() +
                     ", tenant: " + request.auth().tenant() +
                     ", user: " + request.auth().user());

    fileengine_rpc::GetFileResponse response;
    grpc::ClientContext context;

    grpc::Status status = stub_->GetFile(&context, request, &response);
    if (!status.ok()) {
        webdav::errorLog("GetFile failed: " + std::string(status.error_message()));
        // Set response as failure
        response.set_success(false);
        response.set_error(status.error_message());
    } else {
        webdav::debugLog("GetFile succeeded, returned data of size: " + std::to_string(response.data().size()) + " bytes");
        response.set_success(true);
    }

    return response;
}

// File information
fileengine_rpc::StatResponse GRPCClientWrapper::stat(const fileengine_rpc::StatRequest& request) {
    fileengine_rpc::StatResponse response;
    grpc::ClientContext context;

    grpc::Status status = stub_->Stat(&context, request, &response);
    if (!status.ok()) {
        webdav::errorLog("Stat failed: " + std::string(status.error_message()));
        // Set response as failure
        response.set_success(false);
        response.set_error(status.error_message());
    } else {
        response.set_success(true);
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

