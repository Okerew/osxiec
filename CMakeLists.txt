cmake_minimum_required(VERSION 3.27)
project(osxiec C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_FLAGS_RELEASE "-O2 -Wall -Wextra")
set(CMAKE_BUILD_TYPE Release)

set(OSXIEC_MODULE_SOURCES
    globals/globals.c
    container.c
    network.c
    exec.c
    reaper.c
    terminal.c
    deps.c
    util.c
    log/log.c
    log/log.h
    plugin_manager/plugin.h
    plugin_manager/plugin_manager.h
    plugin_manager/plugin_manager.c
    osxiec_script/osxiec_script.h
    osxiec_script/osxiec_script.c
    api_for_osxiec_script.h
)

set(EXECUTABLE_SOURCES
    main.c
)

find_package(CURL REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_check_modules(JSONC REQUIRED IMPORTED_TARGET json-c)
pkg_check_modules(READLINE IMPORTED_TARGET readline)

if(NOT READLINE_FOUND)
  if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    include_directories(
        /usr/local/Cellar/readline/include
    )
    link_directories(/usr/local/Cellar/readline/lib)
  else()
    include_directories(
        /opt/homebrew/opt/readline/include
    )
    link_directories(/opt/homebrew/opt/readline/lib)
  endif()
  set(READLINE_LIB readline)
else()
  set(READLINE_LIB PkgConfig::READLINE)
endif()

add_library(osxiec_shared SHARED ${OSXIEC_MODULE_SOURCES})
set_target_properties(osxiec_shared PROPERTIES
    OUTPUT_NAME "osxiec"
)

target_link_libraries(osxiec_shared PRIVATE
    PkgConfig::JSONC
    CURL::libcurl
    ${READLINE_LIB}
)

add_executable(osxiec ${EXECUTABLE_SOURCES})
target_link_libraries(osxiec PRIVATE
    osxiec_shared
    PkgConfig::JSONC
    CURL::libcurl
    ${READLINE_LIB}
)

set_target_properties(osxiec PROPERTIES
    BUILD_RPATH "${CMAKE_BINARY_DIR}"
    INSTALL_RPATH "${CMAKE_INSTALL_PREFIX}/lib"
)

install(TARGETS osxiec_shared osxiec
    RUNTIME DESTINATION bin
    LIBRARY DESTINATION lib
)

install(DIRECTORY include/ DESTINATION include/osxiec)
