cmake_minimum_required(VERSION 3.10)
project(persephone VERSION 0.1.0 LANGUAGES CXX C)

# Avoid warning about DOWNLOAD_EXTRACT_TIMESTAMP in CMake 3.24:
if (CMAKE_VERSION VERSION_GREATER_EQUAL "3.24.0")
    cmake_policy(SET CMP0135 NEW)
endif ()

# Set C++ and C standards
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_C_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_C_EXTENSIONS OFF)

# Set build type if not specified
if (NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif ()

# LTO
include(CheckIPOSupported)
check_ipo_supported(RESULT supported OUTPUT error)

include(FetchContent)

set(CMAKE_MODULE_PATH
        "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

# nlohmann_json
FetchContent_Declare(json
        URL https://github.com/nlohmann/json/releases/download/v3.12.0/json.tar.xz
        EXCLUDE_FROM_ALL
        SYSTEM
)
FetchContent_MakeAvailable(json)

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
        GIT_TAG v1.9.12
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

# Debug output for LDNS (enable with -DCMAKE_DEBUG_OUTPUT=ON)
option(CMAKE_DEBUG_OUTPUT "Enable debug output during configuration" OFF)
if (CMAKE_DEBUG_OUTPUT)
    get_target_property(VAR PkgConfig::LDNS INTERFACE_INCLUDE_DIRECTORIES)
    message(STATUS "INTERFACE_INCLUDE_DIRECTORIES: ${VAR}")
    get_target_property(VAR PkgConfig::LDNS INTERFACE_LINK_LIBRARIES)
    message(STATUS "INTERFACE_LINK_LIBRARIES: ${VAR}")
    get_target_property(VAR PkgConfig::LDNS INTERFACE_LINK_DIRECTORIES)
    message(STATUS "INTERFACE_LINK_DIRECTORIES: ${VAR}")
endif ()


# icu for unicode support
find_package(ICU COMPONENTS uc REQUIRED)


# Source files
set(SOURCES
        src/database/database.cpp
        src/database/migrations/migrator.cpp
        src/database/state_ordering.cpp
        src/utils/config.cpp
        src/utils/json_utils.cpp
        src/utils/utils.cpp
        src/utils/state_res.cpp
        src/utils/room_utils.cpp
        src/webserver/client_server_api/ClientServerCtrl.cpp
        src/webserver/json.cpp
        src/webserver/server_server_api/ServerServerCtrl.cpp
        src/federation/federation_sender.cpp
)

# Create a static library to avoid recompiling sources for each target
add_library(persephone_lib STATIC ${SOURCES})
target_include_directories(persephone_lib
        PUBLIC ${sodium_INCLUDE_DIR}
        PUBLIC src
)
target_link_libraries(persephone_lib PUBLIC
        drogon
        nlohmann_json::nlohmann_json
        yaml-cpp
        sodium
        ZLIB::ZLIB
        PkgConfig::LDNS
        ICU::uc
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

# Test compile options - less strict to avoid issues with test frameworks
set(TEST_COMPILE_OPTIONS
        -DJSON_DIAGNOSTICS=1
        -Wall
        -Wextra
)

# If clang we have to ignore the unknown-warning-option check since it gets confused with gcc and werror
if (CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    list(APPEND COMPILE_OPTIONS
            -Wno-error=unknown-warning-option)
endif ()

# Set warning levels and other compiler options on the library
target_compile_options(persephone_lib PRIVATE
        ${COMPILE_OPTIONS}
)

option(SANITIZERS_ENABLED "Enable sanitizers" OFF)

# if sanitizers enabled
if (SANITIZERS_ENABLED)
    target_compile_options(persephone_lib PRIVATE
            -fsanitize=address
            -fsanitize=undefined
            -fsanitize=leak
    )
    target_link_options(persephone_lib PUBLIC
            -fsanitize=address
            -fsanitize=undefined
            -fsanitize=leak
    )
endif ()

# if gcc we add -fhardened
if (CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    target_compile_options(persephone_lib PRIVATE
            -fhardened
            -Wno-error=hardened
    )
else ()
    # Use generator expression for build-type specific flags
    target_compile_options(persephone_lib PRIVATE
            $<$<CONFIG:Release>:-D_FORTIFY_SOURCE=3>
            -D_GLIBCXX_ASSERTIONS
            -ftrivial-auto-var-init=zero
            -fPIE
            -fstack-protector-strong
            -fstack-clash-protection
    )
    # if x86 gnu/linux we add -fcf-protection=full
    if (CMAKE_SYSTEM_PROCESSOR STREQUAL "x86_64" AND CMAKE_SYSTEM_NAME STREQUAL "Linux")
        target_compile_options(persephone_lib PRIVATE
                -fcf-protection=full
        )
    endif ()
endif ()

# Executable
add_executable(persephone src/main.cpp)
target_link_libraries(persephone PRIVATE persephone_lib)

# LTO
if (supported)
    message(STATUS "IPO / LTO enabled")
    set_property(TARGET persephone_lib PROPERTY INTERPROCEDURAL_OPTIMIZATION TRUE)
    set_property(TARGET persephone PROPERTY INTERPROCEDURAL_OPTIMIZATION TRUE)
else ()
    message(STATUS "IPO / LTO not supported: <${error}>")
endif ()

# Install target
install(TARGETS persephone
        RUNTIME DESTINATION bin
)

# Packaging
set(CPACK_PACKAGE_NAME "persephone")
set(CPACK_PACKAGE_VERSION "${PROJECT_VERSION}")
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

    # Drogon is statically linked via FetchContent; its transitive runtime deps
    # (libevent, jsoncpp, hiredis, spdlog) are covered by the packages above.
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

    add_executable(utils_test tests/utils_test.cpp)
    target_link_libraries(utils_test PRIVATE
            persephone_lib
            snitch::snitch
    )
    target_compile_options(utils_test PRIVATE
            ${TEST_COMPILE_OPTIONS}
    )

    add_executable(state_res_test tests/state_res_test.cpp)
    target_link_libraries(state_res_test PRIVATE
            persephone_lib
            snitch::snitch
    )
    target_compile_options(state_res_test PRIVATE
            ${TEST_COMPILE_OPTIONS}
    )

    add_executable(config_test tests/config_test.cpp)
    target_link_libraries(config_test PRIVATE
            persephone_lib
            snitch::snitch
    )
    target_compile_options(config_test PRIVATE
            ${TEST_COMPILE_OPTIONS}
    )


    # drogon_tests moved to ENABLE_INTEGRATION_TESTS section below

    add_executable(sync_test tests/sync_test.cpp)
    target_link_libraries(sync_test PRIVATE
            persephone_lib
            snitch::snitch
    )
    target_compile_options(sync_test PRIVATE
            ${TEST_COMPILE_OPTIONS}
    )

    add_executable(json_serialization_test tests/json_serialization_test.cpp)
    target_link_libraries(json_serialization_test PRIVATE
            persephone_lib
            snitch::snitch
    )
    target_compile_options(json_serialization_test PRIVATE
            ${TEST_COMPILE_OPTIONS}
    )

    add_executable(room_utils_test tests/room_utils_test.cpp)
    target_link_libraries(room_utils_test PRIVATE
            persephone_lib
            snitch::snitch
    )
    target_compile_options(room_utils_test PRIVATE
            ${TEST_COMPILE_OPTIONS}
    )

    add_executable(state_ordering_test tests/state_ordering_test.cpp)
    target_link_libraries(state_ordering_test PRIVATE
            persephone_lib
            snitch::snitch
    )
    target_compile_options(state_ordering_test PRIVATE
            ${TEST_COMPILE_OPTIONS}
    )

    add_executable(send_join_test tests/send_join_test.cpp)
    target_link_libraries(send_join_test PRIVATE
            persephone_lib
            snitch::snitch
    )
    target_compile_options(send_join_test PRIVATE
            ${TEST_COMPILE_OPTIONS}
    )

    add_custom_target(tests
            COMMAND utils_test
            COMMAND state_res_test
            COMMAND config_test
            COMMAND sync_test
            COMMAND json_serialization_test
            COMMAND room_utils_test
            COMMAND state_ordering_test
            COMMAND send_join_test
            WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
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
            NAME sync_test
            COMMAND sync_test
    )
    add_test(
            NAME json_serialization_test
            COMMAND json_serialization_test
    )
    add_test(
            NAME room_utils_test
            COMMAND room_utils_test
    )
    add_test(
            NAME state_ordering_test
            COMMAND state_ordering_test
    )
    add_test(
            NAME send_join_test
            COMMAND send_join_test
    )
    target_code_coverage(persephone_lib AUTO ALL EXTERNAL EXCLUDE ${CCOV_EXCLUDES})
    target_code_coverage(utils_test AUTO ALL EXTERNAL EXCLUDE ${CCOV_EXCLUDES})
    target_code_coverage(state_res_test AUTO ALL EXTERNAL EXCLUDE ${CCOV_EXCLUDES})
    target_code_coverage(config_test AUTO ALL EXTERNAL EXCLUDE ${CCOV_EXCLUDES})
    target_code_coverage(sync_test AUTO ALL EXTERNAL EXCLUDE ${CCOV_EXCLUDES})
    target_code_coverage(json_serialization_test AUTO ALL EXTERNAL EXCLUDE ${CCOV_EXCLUDES})
    target_code_coverage(room_utils_test AUTO ALL EXTERNAL EXCLUDE ${CCOV_EXCLUDES})
    target_code_coverage(state_ordering_test AUTO ALL EXTERNAL EXCLUDE ${CCOV_EXCLUDES})
    target_code_coverage(send_join_test AUTO ALL EXTERNAL EXCLUDE ${CCOV_EXCLUDES})

    # Integration tests (require PostgreSQL)
    option(ENABLE_INTEGRATION_TESTS "Enable integration tests (requires PostgreSQL)" OFF)
    if (ENABLE_INTEGRATION_TESTS)
        add_executable(drogon_tests tests/drogon_tests.cpp)
        target_link_libraries(drogon_tests PRIVATE
                persephone_lib
                snitch::snitch
        )
        target_compile_options(drogon_tests PRIVATE
                ${TEST_COMPILE_OPTIONS}
        )

        add_executable(database_test tests/database_test.cpp)
        target_link_libraries(database_test PRIVATE
                persephone_lib
                snitch::snitch
        )
        target_compile_options(database_test PRIVATE
                ${TEST_COMPILE_OPTIONS}
        )

        add_test(
                NAME drogon_tests
                COMMAND drogon_tests
        )
        add_test(
                NAME database_test
                COMMAND database_test
        )
        target_code_coverage(drogon_tests AUTO ALL EXTERNAL EXCLUDE ${CCOV_EXCLUDES})
        target_code_coverage(database_test AUTO ALL EXTERNAL EXCLUDE ${CCOV_EXCLUDES})
    endif ()

endif ()

# Fuzz targets
option(BUILD_FUZZ_TARGETS "Build fuzz targets" OFF)
if (BUILD_FUZZ_TARGETS)
    add_executable(fuzz_json_sign src/fuzz_targets/json_sign.cpp)

    target_link_libraries(fuzz_json_sign PRIVATE
            persephone_lib
            trantor
            jsoncpp
    )
    add_custom_target(fuzz_targets
            COMMAND fuzz_json_sign
    )
endif ()
