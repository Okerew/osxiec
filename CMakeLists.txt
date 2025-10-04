cmake_minimum_required(VERSION 3.27)
project(osxiec C)

set(CMAKE_C_STANDARD 11)

# List shared sources
set(OSXIEC_SOURCES
    osxiec.c
    plugin_manager/plugin.h
    plugin_manager/plugin_manager.h
    plugin_manager/plugin_manager.c
    osxiec_script/osxiec_script.h
    osxiec_script/osxiec_script.c
    api_for_osxiec_script.h
)

# Build shared library (.dylib)
add_library(osxiec_shared SHARED
    ${OSXIEC_SOURCES}
)

set_target_properties(osxiec_shared PROPERTIES OUTPUT_NAME "osxiec")

# Build executable
add_executable(osxiec ${OSXIEC_SOURCES})

# Find and link CURL
find_package(CURL REQUIRED)
target_link_libraries(osxiec PRIVATE CURL::libcurl)
target_link_libraries(osxiec_shared PRIVATE CURL::libcurl)

# Find and link Readline
include_directories(/opt/homebrew/opt/readline/include)
target_link_directories(osxiec PRIVATE /opt/homebrew/opt/readline/lib)
target_link_directories(osxiec_shared PRIVATE /opt/homebrew/opt/readline/lib)

target_link_libraries(osxiec PRIVATE readline)
target_link_libraries(osxiec_shared PRIVATE readline)

# Find and link json-c
include_directories(/opt/homebrew/Cellar/json-c/0.18/include)
target_link_directories(osxiec PRIVATE /opt/homebrew/Cellar/json-c/0.18/lib)
target_link_directories(osxiec_shared PRIVATE /opt/homebrew/Cellar/json-c/0.18/lib)

target_link_libraries(osxiec PRIVATE json-c)
target_link_libraries(osxiec_shared PRIVATE json-c)
