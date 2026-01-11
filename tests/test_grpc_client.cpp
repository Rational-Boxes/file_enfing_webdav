#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "../include/grpc_client_wrapper.h"

class MockGRPCClientWrapper : public webdav::GRPCClientWrapper {
public:
    MockGRPCClientWrapper() : GRPCClientWrapper("localhost:50051") {}
    
    MOCK_METHOD(fileengine_rpc::MakeDirectoryResponse, makeDirectory, 
                (const fileengine_rpc::MakeDirectoryRequest&), (override));
    MOCK_METHOD(fileengine_rpc::RemoveDirectoryResponse, removeDirectory, 
                (const fileengine_rpc::RemoveDirectoryRequest&), (override));
    MOCK_METHOD(fileengine_rpc::ListDirectoryResponse, listDirectory, 
                (const fileengine_rpc::ListDirectoryRequest&), (override));
    MOCK_METHOD(fileengine_rpc::ListDirectoryWithDeletedResponse, listDirectoryWithDeleted, 
                (const fileengine_rpc::ListDirectoryWithDeletedRequest&), (override));
    MOCK_METHOD(fileengine_rpc::TouchResponse, touch, 
                (const fileengine_rpc::TouchRequest&), (override));
    MOCK_METHOD(fileengine_rpc::RemoveFileResponse, removeFile, 
                (const fileengine_rpc::RemoveFileRequest&), (override));
    MOCK_METHOD(fileengine_rpc::UndeleteFileResponse, undeleteFile, 
                (const fileengine_rpc::UndeleteFileRequest&), (override));
    MOCK_METHOD(fileengine_rpc::PutFileResponse, putFile, 
                (const fileengine_rpc::PutFileRequest&), (override));
    MOCK_METHOD(fileengine_rpc::GetFileResponse, getFile, 
                (const fileengine_rpc::GetFileRequest&), (override));
    MOCK_METHOD(fileengine_rpc::StatResponse, stat, 
                (const fileengine_rpc::StatRequest&), (override));
    MOCK_METHOD(fileengine_rpc::ExistsResponse, exists, 
                (const fileengine_rpc::ExistsRequest&), (override));
    MOCK_METHOD(fileengine_rpc::RenameResponse, rename, 
                (const fileengine_rpc::RenameRequest&), (override));
    MOCK_METHOD(fileengine_rpc::MoveResponse, move, 
                (const fileengine_rpc::MoveRequest&), (override));
    MOCK_METHOD(fileengine_rpc::CopyResponse, copy, 
                (const fileengine_rpc::CopyRequest&), (override));
    MOCK_METHOD(fileengine_rpc::ListVersionsResponse, listVersions, 
                (const fileengine_rpc::ListVersionsRequest&), (override));
    MOCK_METHOD(fileengine_rpc::GetVersionResponse, getVersion, 
                (const fileengine_rpc::GetVersionRequest&), (override));
    MOCK_METHOD(fileengine_rpc::RestoreToVersionResponse, restoreToVersion, 
                (const fileengine_rpc::RestoreToVersionRequest&), (override));
    MOCK_METHOD(fileengine_rpc::SetMetadataResponse, setMetadata, 
                (const fileengine_rpc::SetMetadataRequest&), (override));
    MOCK_METHOD(fileengine_rpc::GetMetadataResponse, getMetadata, 
                (const fileengine_rpc::GetMetadataRequest&), (override));
    MOCK_METHOD(fileengine_rpc::GetAllMetadataResponse, getAllMetadata, 
                (const fileengine_rpc::GetAllMetadataRequest&), (override));
    MOCK_METHOD(fileengine_rpc::DeleteMetadataResponse, deleteMetadata, 
                (const fileengine_rpc::DeleteMetadataRequest&), (override));
    MOCK_METHOD(fileengine_rpc::GetMetadataForVersionResponse, getMetadataForVersion, 
                (const fileengine_rpc::GetMetadataForVersionRequest&), (override));
    MOCK_METHOD(fileengine_rpc::GetAllMetadataForVersionResponse, getAllMetadataForVersion, 
                (const fileengine_rpc::GetAllMetadataForVersionRequest&), (override));
    MOCK_METHOD(fileengine_rpc::GrantPermissionResponse, grantPermission, 
                (const fileengine_rpc::GrantPermissionRequest&), (override));
    MOCK_METHOD(fileengine_rpc::RevokePermissionResponse, revokePermission, 
                (const fileengine_rpc::RevokePermissionRequest&), (override));
    MOCK_METHOD(fileengine_rpc::CheckPermissionResponse, checkPermission, 
                (const fileengine_rpc::CheckPermissionRequest&), (override));
    MOCK_METHOD(fileengine_rpc::StorageUsageResponse, getStorageUsage, 
                (const fileengine_rpc::StorageUsageRequest&), (override));
    MOCK_METHOD(fileengine_rpc::PurgeOldVersionsResponse, purgeOldVersions, 
                (const fileengine_rpc::PurgeOldVersionsRequest&), (override));
    MOCK_METHOD(fileengine_rpc::TriggerSyncResponse, triggerSync, 
                (const fileengine_rpc::TriggerSyncRequest&), (override));
};

class GRPCClientWrapperTest : public ::testing::Test {
protected:
    void SetUp() override {
        client = std::make_unique<MockGRPCClientWrapper>();
    }

    void TearDown() override {
        client.reset();
    }

    std::unique_ptr<MockGRPCClientWrapper> client;
};

TEST_F(GRPCClientWrapperTest, MakeDirectoryTest) {
    // Create a mock request
    fileengine_rpc::MakeDirectoryRequest request;
    request.set_parent_uid("parent-uuid");
    request.set_name("test-dir");
    
    fileengine_rpc::AuthenticationContext* auth = request.mutable_auth();
    auth->set_user("test-user");
    auth->set_tenant("test-tenant");
    auth->add_roles("users");

    // Create a mock response
    fileengine_rpc::MakeDirectoryResponse response;
    response.set_success(true);
    response.set_uid("new-dir-uuid");

    // Set up the expectation
    EXPECT_CALL(*client, makeDirectory(::testing::_))
        .WillOnce(::testing::Return(response));

    // Call the method
    auto result = client->makeDirectory(request);

    // Verify the result
    EXPECT_TRUE(result.success());
    EXPECT_EQ(result.uid(), "new-dir-uuid");
}

TEST_F(GRPCClientWrapperTest, GetFileTest) {
    // Create a mock request
    fileengine_rpc::GetFileRequest request;
    request.set_uid("file-uuid");
    
    fileengine_rpc::AuthenticationContext* auth = request.mutable_auth();
    auth->set_user("test-user");
    auth->set_tenant("test-tenant");
    auth->add_roles("users");

    // Create a mock response
    fileengine_rpc::GetFileResponse response;
    response.set_success(true);
    std::string testData = "test file content";
    response.set_data(testData);

    // Set up the expectation
    EXPECT_CALL(*client, getFile(::testing::_))
        .WillOnce(::testing::Return(response));

    // Call the method
    auto result = client->getFile(request);

    // Verify the result
    EXPECT_TRUE(result.success());
    EXPECT_EQ(result.data(), testData);
}