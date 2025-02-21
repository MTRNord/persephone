cmake_minimum_required(VERSION 3.25)
project(persephone VERSION 0.1.0 LANGUAGES CXX C)

# Avoid warning about DOWNLOAD_EXTRACT_TIMESTAMP in CMake 3.24:
if (CMAKE_VERSION VERSION_GREATER_EQUAL "3.24.0")
    cmake_policy(SET CMP0135 NEW)
endif ()

# Set C++ and C standards
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_C_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)


# Set build type if not specified
if (NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif ()

include(FetchContent)
include(cmake/CPM.cmake)


set(CMAKE_MODULE_PATH
        "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

# nlohmann_json
FetchContent_Declare(json URL https://github.com/nlohmann/json/releases/download/v3.11.3/json.tar.xz)
FetchContent_MakeAvailable(json)

# Static linking as we dont have it on our target systems
set(AMQP-CPP_BUILD_SHARED OFF)
set(AMQP-CPP_LINUX_TCP ON)
# amqp-cpp
FetchContent_Declare(
        amqpcpp
        GIT_REPOSITORY https://github.com/CopernicaMarketingSoftware/AMQP-CPP.git
        GIT_TAG v4.3.27
        EXCLUDE_FROM_ALL
        SYSTEM
)
FetchContent_MakeAvailable(amqpcpp)
unset(AMQP-CPP_BUILD_SHARED)
unset(AMQP-CPP_LINUX_TCP)

#drogon
set(BUILD_CTL OFF)
set(BUILD_EXAMPLES OFF)
set(BUILD_SHARED_LIBS OFF)
set(BUILD_BROTLI OFF)
set(BUILD_YAML_CONFIG OFF)
set(BUILD_POSTGRESQL ON)
FetchContent_Declare(
        drogon
        GIT_REPOSITORY https://github.com/drogonframework/drogon.git
        GIT_TAG v1.9.9
        EXCLUDE_FROM_ALL
        SYSTEM
)
FetchContent_MakeAvailable(drogon)


# Dependencies
find_package(Sodium REQUIRED)
find_package(ZLIB REQUIRED)
find_package(yaml-cpp REQUIRED)
#  ldns
find_package(PkgConfig REQUIRED)
pkg_check_modules(LDNS REQUIRED IMPORTED_TARGET ldns)

# If the include directory of ldns is `/usr/include/ldns/ldns` we replace it with `/usr/include/ldns`. This is a packaging bug on fedora
if (LDNS_FOUND AND LDNS_INCLUDE_DIRS MATCHES "/usr/include/ldns/ldns")
    string(REGEX REPLACE "/usr/include/ldns/ldns" "/usr/include/ldns" LDNS_INCLUDE_DIRS ${LDNS_INCLUDE_DIRS})
endif ()
# Also ensure INTERFACE_INCLUDE_DIRECTORIES is fixed
if (LDNS_FOUND AND TARGET PkgConfig::LDNS)
    get_target_property(LDNS_INCLUDE_DIRS PkgConfig::LDNS INTERFACE_INCLUDE_DIRECTORIES)
    if (LDNS_INCLUDE_DIRS MATCHES "/usr/include/ldns/ldns")
        string(REGEX REPLACE "/usr/include/ldns/ldns" "/usr/include/ldns" LDNS_INCLUDE_DIRS ${LDNS_INCLUDE_DIRS})
        set_target_properties(PkgConfig::LDNS PROPERTIES INTERFACE_INCLUDE_DIRECTORIES ${LDNS_INCLUDE_DIRS})
    endif ()
endif ()

get_target_property(VAR PkgConfig::LDNS INTERFACE_INCLUDE_DIRECTORIES)
message(STATUS "INTERFACE_INCLUDE_DIRECTORIES: ${VAR}")
get_target_property(VAR PkgConfig::LDNS INTERFACE_LINK_LIBRARIES)
message(STATUS "INTERFACE_LINK_LIBRARIES: ${VAR}")
get_target_property(VAR PkgConfig::LDNS INTERFACE_LINK_DIRECTORIES)
message(STATUS "INTERFACE_LINK_DIRECTORIES: ${VAR}")


# icu for unicode support
find_package(ICU COMPONENTS uc REQUIRED)
# libevent
pkg_check_modules(libevent REQUIRED)


# Include directories
include_directories(
        PUBLIC
        ${sodium_INCLUDE_DIR}
        PRIVATE
        src
)

# Source files
set(SOURCES
        src/database/database.cpp
        src/database/migrations/migrator.cpp
        src/utils/config.cpp
        src/utils/json_utils.cpp
        src/utils/utils.cpp
        src/utils/state_res.cpp
        src/utils/room_utils.cpp
        src/webserver/client_server_api/ClientServerCtrl.cpp
        src/webserver/json.cpp
        src/webserver/server_server_api/ServerServerCtrl.cpp
        src/worker_queue/producer.cpp
        src/worker_queue/worker.cpp
        src/worker_queue/ReconnectingLibEventHandler.cpp
)

# Executable
add_executable(persephone ${SOURCES} src/main.cpp)
target_link_libraries(persephone PRIVATE
        drogon
        nlohmann_json::nlohmann_json
        yaml-cpp
        sodium
        ZLIB::ZLIB
        PkgConfig::LDNS
        ICU::uc
        amqpcpp
        event
)
# Default list of compile options applying to all compilers
set(COMPILE_OPTIONS
        -DJSON_DIAGNOSTICS=1
        -Wshadow
        -Wconversion
        -Wpedantic
        -Wuninitialized
        -Wall
        -Wextra
        -Werror
)

# If clang we have to ignore the unknown-warning-option check since it gets confused with gcc and werror
if (CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    list(APPEND COMPILE_OPTIONS
            -Wno-error=unknown-warning-option)
endif ()

# Set warning levels and other compiler options
target_compile_options(persephone PRIVATE
        ${COMPILE_OPTIONS}
)

# if debug building
if (CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_options(persephone PRIVATE
            -fsanitize=address
            -fsanitize=undefined
            -fsanitize=leak
    )
endif ()

# Install target
install(TARGETS persephone
        RUNTIME DESTINATION bin
)

# Packaging
set(CPACK_PACKAGE_NAME "persephone")
set(CPACK_PACKAGE_VERSION "0.1.0")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Persephone Project")
set(CPACK_PACKAGE_VENDOR "MTRNord")

# Specify the license file
set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_CURRENT_SOURCE_DIR}/LICENSE")

# Specify the readme file
set(CPACK_RESOURCE_FILE_README "${CMAKE_CURRENT_SOURCE_DIR}/README.md")

set(CPACK_PACKAGE_INSTALL_DIRECTORY ${CPACK_PACKAGE_NAME})
set(CPACK_VERBATIM_VARIABLES TRUE)
set(CPACK_STRIP_FILES TRUE)
set(CPACK_THREADS 0)

if (WIN32)
    set(CPACK_GENERATOR ZIP WIX NSIS)
elseif (APPLE)
    set(CPACK_GENERATOR TGZ productbuild PACKAGEMAKER DRAGNDROP BUNDLE)
elseif (CMAKE_SYSTEM_NAME STREQUAL "Linux")
    set(CPACK_GENERATOR TGZ RPM DEB)

    # Deb settings
    set(CPACK_DEBIAN_PACKAGE_MAINTAINER "MTRNord")
    set(CPACK_DEBIAN_PACKAGE_DEPENDS "uuid, libjsoncpp25, zlib1g, openssl, libldns3t64, libevent-2.1-7t64, libyaml-cpp0.8, libicu74, libsodium23")


    set(CPACK_RPM_PACKAGE_AUTOREQPROV no)
    set(CPACK_RPM_PACKAGE_REQUIRES "uuid, jsoncpp, zlib, openssl, ldns, libevent, yaml-cpp, icu, libsodium")

    # TODO: Make libdrogon work as a subpackage/direct dependency and statically link it
else ()
    set(CPACK_GENERATOR TGZ)
endif ()

include(CPack)

# Tests
option(DISABLE_TESTS "Disable tests" ON)
if (NOT DISABLE_TESTS)
    enable_testing()
    include(CTest)

    # DEV: Set clang-tidy
    # set(CMAKE_CXX_CLANG_TIDY "clang-tidy")
    include(code-coverage)
    if (DEFINED ENV{CPM_SOURCE_CACHE})
        # file(GLOB_RECURSE CCOV_EXCLUDES CONFIGURE_DEPENDS $ENV{CPM_SOURCE_CACHE}/*)
        set(CCOV_EXCLUDES $ENV{CPM_SOURCE_CACHE}/.* $ENV{CPM_SOURCE_CACHE}/*)
    endif ()
    # file(GLOB_RECURSE CCOV_EXCLUDES CONFIGURE_DEPENDS ${CMAKE_BINARY_DIR}/*)
    set(CCOV_EXCLUDES ${CMAKE_BINARY_DIR}/.* ${CMAKE_BINARY_DIR}/*)

    add_code_coverage_all_targets(EXCLUDE ${CCOV_EXCLUDES})

    FetchContent_Declare(snitch
            GIT_REPOSITORY https://github.com/snitch-org/snitch.git
            GIT_TAG v1.3.1)
    FetchContent_MakeAvailable(snitch)

    add_executable(utils_test tests/utils_test.cpp ${SOURCES})
    target_link_libraries(utils_test PRIVATE
            drogon
            nlohmann_json::nlohmann_json
            yaml-cpp
            sodium
            ZLIB::ZLIB
            PkgConfig::LDNS
            ICU::uc
            snitch::snitch
            amqpcpp
            event
    )
    target_link_options(utils_test PRIVATE
            ${COMPILE_OPTIONS}
    )

    add_executable(state_res_test tests/state_res_test.cpp ${SOURCES})
    target_link_libraries(state_res_test PRIVATE
            drogon
            nlohmann_json::nlohmann_json
            yaml-cpp
            sodium
            ZLIB::ZLIB
            PkgConfig::LDNS
            ICU::uc
            snitch::snitch
            amqpcpp
            event
    )
    target_link_options(state_res_test PRIVATE
            ${COMPILE_OPTIONS}
    )

    add_executable(config_test tests/config_test.cpp ${SOURCES})
    target_link_libraries(config_test PRIVATE
            drogon
            nlohmann_json::nlohmann_json
            yaml-cpp
            sodium
            ZLIB::ZLIB
            PkgConfig::LDNS
            ICU::uc
            snitch::snitch
            amqpcpp
            event
    )
    target_link_options(config_test PRIVATE
            ${COMPILE_OPTIONS}
    )


    add_executable(drogon_tests tests/drogon_tests.cpp ${SOURCES})
    target_link_libraries(drogon_tests PRIVATE
            drogon
            nlohmann_json::nlohmann_json
            yaml-cpp
            sodium
            ZLIB::ZLIB
            PkgConfig::LDNS
            ICU::uc
            snitch::snitch
            amqpcpp
            event
    )
    target_link_options(drogon_tests PRIVATE
            ${COMPILE_OPTIONS}
    )

    add_custom_target(tests
            COMMAND utils_test
            COMMAND state_res_test
            COMMAND config_test
            COMMAND drogon_tests
    )

    add_test(
            NAME utils_test
            COMMAND utils_test
    )
    add_test(
            NAME state_res_test
            COMMAND state_res_test
    )
    add_test(
            NAME config_test
            COMMAND config_test
    )
    add_test(
            NAME drogon_tests
            COMMAND drogon_tests
    )
    target_code_coverage(utils_test AUTO ALL EXTERNAL EXCLUDE ${CCOV_EXCLUDES})
    target_code_coverage(state_res_test AUTO ALL EXTERNAL EXCLUDE ${CCOV_EXCLUDES})
    target_code_coverage(config_test AUTO ALL EXTERNAL EXCLUDE ${CCOV_EXCLUDES})
    target_code_coverage(drogon_tests AUTO ALL EXTERNAL EXCLUDE ${CCOV_EXCLUDES})

endif ()

# Fuzz targets
option(BUILD_FUZZ_TARGETS "Build fuzz targets" OFF)
if (BUILD_FUZZ_TARGETS)
    add_executable(fuzz_json_sign src/fuzz_targets/json_sign.cpp ${SOURCES})

    target_link_libraries(fuzz_json_sign PRIVATE
            drogon
            nlohmann_json::nlohmann_json
            yaml-cpp
            sodium
            ZLIB::ZLIB
            PkgConfig::LDNS
            trantor
            jsoncpp
            ICU::uc
            amqpcpp
            event
    )
    add_custom_target(fuzz_targets
            COMMAND fuzz_json_sign
    )
endif ()