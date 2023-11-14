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
httplib = subproject(
    'cpp-httplib',
    default_options: ['cpp-httplib_openssl=enabled'],
)
cpp_httplib_dep = httplib.get_variable('cpp_httplib_dep')
thread_dep = dependency('threads')

json = dependency('nlohmann_json')

####### Database ############
soci_core = dependency('soci_core')
soci_postgresql = dependency('soci_postgresql')

###### Config #######
yaml_cpp_dep = dependency('yaml_cpp')

# Globally override the C++ standard to c++20
opt_var.add_cmake_defines(
    {'CMAKE_CXX_STANDARD': '20', 'YAML_BUILD_SHARED_LIBS': true},
)

soci = cmake.subproject('yaml-cpp', options: opt_var)
yaml_cpp = soci.dependency('yaml_cpp')

####### Tests ############
snitch_dep = dependency('snitch')

src = files(
    'src/database/database.cpp',
    'src/main.cpp',
    'src/utils/config.cpp',
    'src/utils/utils.cpp',
    'src/webserver/webserver.cpp',
)

executable(
    'persephone',
    src,
    include_directories: includes,
    dependencies: [
        cpp_httplib_dep,
        json,
        thread_dep,
        soci_core,
        soci_postgresql,
        yaml_cpp,
        yaml_cpp_dep,
    ],
    install: true,
)
test(
    'utils',
    executable('utils_test', 'tests/utils_test.cpp', dependencies: snitch_dep),
)
