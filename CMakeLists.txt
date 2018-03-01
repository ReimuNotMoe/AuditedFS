cmake_minimum_required(VERSION 2.8)
project(AuditedFS)

set(CMAKE_CXX_STANDARD 11)

set(SOURCE_FILES
        AuditedFS.cpp AuditedFS.hpp FuseOperations.cpp Audit.cpp API.cpp)

add_executable(AuditedFS ${SOURCE_FILES})