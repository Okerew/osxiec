cmake_minimum_required(VERSION 3.27)
project(osxiec C)

set(CMAKE_C_STANDARD 11)

# Add executable
add_executable(osxiec osxiec.c
        plugin_manager/plugin.h
        plugin_manager/plugin_manager.h
        plugin_manager/plugin_manager.c)

# Find and link CURL
find_package(CURL REQUIRED)
target_link_libraries(osxiec PRIVATE CURL::libcurl)

# Manually specify Readline library and include paths
include_directories(/opt/homebrew/opt/readline/include)
link_directories(/opt/homebrew/opt/readline/lib)

# Link Readline library
target_link_libraries(osxiec PRIVATE readline)
