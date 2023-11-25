project(
    'persephone',
    'cpp',
    version: '0.1.0',
    default_options: [
        'cpp_std=c++20',
        'warning_level=3',
# Yaml-cpp breaks this with clang
#        'werror=true',
        'b_lto=true',
    ],
)
add_project_arguments(
    '-DCPPHTTPLIB_USE_POLL=true',
    '-DJSON_DIAGNOSTICS=1',
    '-DJSON_USE_IMPLICIT_CONVERSIONS=0',
    '-Wshadow',
    '-Wconversion',
    '-Wpedantic',
    '-D_FORTIFY_SOURCE=2',
    language: ['c', 'cpp'],
)

includes = include_directories('src')

####### Webserver/Matrix ############
cpp_httplib_dep = dependency('cpp-httplib')
thread_dep = dependency('threads')

json = dependency('nlohmann_json')

####### Database ############
soci_core = dependency('soci_core')
soci_postgresql = dependency('soci_postgresql')

###### Config #######
yaml_cpp_dep = dependency('yaml_cpp')

###### libsodium #######
libsodium_dep = dependency('libsodium')

####### Tests ############
snitch_dep = dependency('snitch')

src = files(
    'src/database/database.cpp',
    'src/utils/config.cpp',
    'src/utils/utils.cpp',
    'src/webserver/webserver.cpp',
)

executable(
    'persephone',
    src + 'src/main.cpp',
    include_directories: includes,
    dependencies: [
        cpp_httplib_dep,
        json,
        thread_dep,
        soci_core,
        soci_postgresql,
        yaml_cpp_dep,
        libsodium_dep
    ],
    install: true,
)
test(
    'utils',
    executable('utils_test', src + 'tests/utils_test.cpp',include_directories: includes, 
    dependencies: [
        cpp_httplib_dep,
        json,
        thread_dep,
        soci_core,
        soci_postgresql,
        yaml_cpp_dep,
        libsodium_dep,
        snitch_dep
    ],),
)
