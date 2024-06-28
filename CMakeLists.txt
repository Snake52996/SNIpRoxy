cmake_minimum_required(VERSION 3.29)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(CMAKE_CXX_COMPILER clang++)

project(snir VERSION 0.1.0 LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# set compile options based on build type
set(CMAKE_CXX_FLAGS_DEBUG -g3)
set(CMAKE_CXX_FLAGS_RELEASE "-O3 -DNDEBUG -flto=full")
if(NOT DEFINED CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Debug)
endif()

add_compile_options(-fPIC -stdlib=libc++)
add_link_options(-fuse-ld=lld -stdlib=libc++)
add_compile_definitions(VERSION="${PROJECT_VERSION}")

find_package(GnuTLS REQUIRED)
find_package(c-ares REQUIRED)

find_package(ConfigurationsPP REQUIRED)
find_package(LogPP REQUIRED)

add_executable(snir connection.cc resolve.cc inbound.cc outbound.cc key_management.cc server.cc main.cc  thread_common.cc)
target_link_libraries(snir PRIVATE GnuTLS::GnuTLS c-ares::cares ConfigurationsPP LogPP)