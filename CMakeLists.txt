cmake_minimum_required(VERSION 3.15)
project(webdav_bridge)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_BUILD_TYPE Debug)

# Find required packages
find_package(PkgConfig REQUIRED)
find_package(Threads REQUIRED)

# Find gRPC
find_package(gRPC CONFIG REQUIRED)
find_package(Protobuf CONFIG REQUIRED)

# Find Poco
find_package(Poco COMPONENTS Foundation Util Net JSON Crypto )
if(NOT Poco_FOUND)
    message(FATAL_ERROR "Poco library not found")
endif()

# Find OpenLDAP
find_package(PkgConfig REQUIRED)
pkg_check_modules(LDAP REQUIRED ldap)
if(NOT LDAP_FOUND)
    message(FATAL_ERROR "OpenLDAP library not found")
endif()

# Find PostgreSQL
pkg_check_modules(PostgreSQL REQUIRED libpq)
if(NOT PostgreSQL_FOUND)
    message(FATAL_ERROR "PostgreSQL library not found")
endif()

# Include directories
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)
include_directories(${CMAKE_CURRENT_BINARY_DIR})
include_directories(${CMAKE_CURRENT_BINARY_DIR}/proto/include)

# Generate gRPC files from proto
set(proto_path "${CMAKE_CURRENT_SOURCE_DIR}/proto")
set(proto_file ${proto_path}/fileservice.proto)
set(proto_srcs_dir ${CMAKE_CURRENT_BINARY_DIR}/proto/src)
set(proto_hdrs_dir ${CMAKE_CURRENT_BINARY_DIR}/proto/include)

file(MAKE_DIRECTORY ${proto_srcs_dir})
file(MAKE_DIRECTORY ${proto_hdrs_dir})

# Generate gRPC code
add_custom_command(
    OUTPUT ${proto_srcs_dir}/fileservice.pb.cc ${proto_hdrs_dir}/fileservice.pb.h
           ${proto_srcs_dir}/fileservice.grpc.pb.cc ${proto_hdrs_dir}/fileservice.grpc.pb.h
    COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/generate_grpc.sh
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    DEPENDS ${proto_file}
    COMMENT "Generating gRPC code for FileService"
)

set(PROTO_SRCS 
    ${proto_srcs_dir}/fileservice.pb.cc
    ${proto_srcs_dir}/fileservice.grpc.pb.cc
)
set(PROTO_HDRS 
    ${proto_hdrs_dir}/fileservice.pb.h
    ${proto_hdrs_dir}/fileservice.grpc.pb.h
)

# Define the executable
add_executable(webdav_bridge
    src/main.cpp
    src/webdav_server.cpp
    src/grpc_client_wrapper.cpp
    src/path_resolver.cpp
    src/ldap_authenticator.cpp
    src/utils.cpp
    ${PROTO_SRCS}
)

# Link libraries
target_link_libraries(webdav_bridge
    gRPC::grpc++
    gRPC::grpc
    protobuf::libprotobuf
    Poco::Net
    Poco::Util
    Poco::JSON
    Poco::Crypto
    Poco::Foundation
    ${LDAP_LIBRARIES}
    ${PostgreSQL_LIBRARIES}
    pqxx
    Threads::Threads
)

# Install target
install(TARGETS webdav_bridge DESTINATION bin)

# Add test executable
# enable_testing()
# add_executable(test_webdav
#     tests/test_main.cpp
#     tests/test_grpc_client.cpp
#     tests/test_path_resolver.cpp
#     tests/test_ldap_authenticator.cpp
#     tests/test_webdav_server.cpp
#     ${PROTO_SRCS}
# )
#
# target_link_libraries(test_webdav
#     gRPC::grpc++
#     gRPC::grpc
#     protobuf::libprotobuf
#     Poco::Net
#     Poco::Util
#     Poco::JSON
#     Poco::Crypto
#     Poco::Foundation
#     ${LDAP_LIBRARIES}
#     ${PostgreSQL_LIBRARIES}
#     pqxx
#     Threads::Threads
#     gtest
#     gmock
# )
#
# add_test(NAME test_webdav COMMAND test_webdav)