cmake_minimum_required(VERSION 3.27)
project(osxiec C)

set(CMAKE_C_STANDARD 11)

# Add executable
add_executable(osxiec
        osxiec.c
        plugin_manager/plugin.h
        plugin_manager/plugin_manager.h
        plugin_manager/plugin_manager.c
        osxiec_script/osxiec_script.h
        osxiec_script/osxiec_script.c
        osxiec.h
)

# Find and link CURL
find_package(CURL REQUIRED)
target_link_libraries(osxiec PRIVATE CURL::libcurl)

# Find and link Readline
target_include_directories(osxiec PRIVATE /usr/local/opt/readline/include)
target_link_directories(osxiec PRIVATE /usr/local/opt/readline/lib/)
target_link_libraries(osxiec PRIVATE readline)

# Find and link json-c
target_include_directories(osxiec PRIVATE /usr/local/Cellar/json-c/0.17/include)
target_link_directories(osxiec PRIVATE /usr/local/Cellar/json-c/0.17/lib)
target_link_libraries(osxiec PRIVATE json-c)
