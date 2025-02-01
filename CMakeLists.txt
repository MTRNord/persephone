cmake_minimum_required(VERSION 3.16)
project(persephone VERSION 0.1.0 LANGUAGES CXX C)

# Avoid warning about DOWNLOAD_EXTRACT_TIMESTAMP in CMake 3.24:
if (CMAKE_VERSION VERSION_GREATER_EQUAL "3.24.0")
    cmake_policy(SET CMP0135 NEW)
endif ()

enable_testing()
include(CTest)
include(FetchContent)
include(cmake/CPM.cmake)

# Set C++ and C standards
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_C_STANDARD 17)

# DEV: Set clang-tidy
# set(CMAKE_CXX_CLANG_TIDY "clang-tidy")

set(CMAKE_MODULE_PATH
        "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

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
        -Werror
        # sanitizer options
        -fsanitize=address
        -fsanitize=undefined
        -fsanitize=leak
)
target_link_options(persephone PRIVATE
        -fsanitize=address
        -fsanitize=undefined
        -fsanitize=leak
)

# Tests
option(DISABLE_TESTS " Disable tests" ON)
if (NOT DISABLE_TESTS)
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
    )

    add_custom_target(tests
            COMMAND utils_test
            COMMAND state_res_test
    )

    add_test(
            NAME utils_test
            COMMAND utils_test
    )
    add_test(
            NAME state_res_test
            COMMAND state_res_test
    )
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
    )
    add_custom_target(fuzz_targets
            COMMAND fuzz_json_sign
    )
endif ()