cmake_minimum_required(VERSION 3.28)
project(osxiec)

set(CMAKE_C_STANDARD 11)
add_executable(osxiec
        osxiec.c)
find_package(CURL REQUIRED)
target_link_libraries(osxiec CURL::libcurl)
