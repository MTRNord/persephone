cmake_minimum_required(VERSION 3.16)
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

# Dependencies
find_package(Drogon 1.9.9 REQUIRED)
find_package(Sodium REQUIRED)
find_package(ZLIB REQUIRED)
find_package(yaml-cpp REQUIRED)
#  ldns
find_package(PkgConfig REQUIRED)
pkg_check_modules(LDNS REQUIRED IMPORTED_TARGET ldns)
# icu for unicode support
find_package(ICU COMPONENTS uc REQUIRED)
# libevent
pkg_check_modules(libevent REQUIRED)

# nlohmann_json
FetchContent_Declare(json URL https://github.com/nlohmann/json/releases/download/v3.11.3/json.tar.xz)
FetchContent_MakeAvailable(json)

# amqp-cpp
CPMAddPackage(
        NAME amqpcpp
        GITHUB_REPOSITORY CopernicaMarketingSoftware/AMQP-CPP
        VERSION 4.3.27
        OPTIONS "AMQP-CPP_BUILD_SHARED ON" "AMQP-CPP_LINUX_TCP ON"
)

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
        Drogon::Drogon
        nlohmann_json::nlohmann_json
        yaml-cpp
        sodium
        ZLIB::ZLIB
        PkgConfig::LDNS
        ICU::uc
        amqpcpp
        event
)
# Set warning levels and other compiler options
target_compile_options(persephone PRIVATE
        -DJSON_DIAGNOSTICS=1
        -Wshadow
        -Wconversion
        -Wpedantic
        -Wuninitialized
        -Wall
        -Wextra
        -Werror
)
target_link_options(persephone PRIVATE
        -fsanitize=address
        -fsanitize=undefined
        -fsanitize=leak
)

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
            Drogon::Drogon
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
            -fsanitize=address
            -fsanitize=undefined
            -fsanitize=leak
    )

    add_executable(state_res_test tests/state_res_test.cpp ${SOURCES})
    target_link_libraries(state_res_test PRIVATE
            Drogon::Drogon
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
            -fsanitize=address
            -fsanitize=undefined
            -fsanitize=leak
    )

    add_executable(config_test tests/config_test.cpp ${SOURCES})
    target_link_libraries(config_test PRIVATE
            Drogon::Drogon
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
            -fsanitize=address
            -fsanitize=undefined
            -fsanitize=leak
    )


    add_executable(drogon_tests tests/drogon_tests.cpp ${SOURCES})
    target_link_libraries(drogon_tests PRIVATE
            Drogon::Drogon
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
            -fsanitize=address
            -fsanitize=undefined
            -fsanitize=leak
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