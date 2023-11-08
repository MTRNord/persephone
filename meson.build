project('persephone', 'cpp', version : '0.1.0', default_options : ['cpp_std=c++20', 'warning_level=3', 'werror=true'])
add_project_arguments('-DJSON_DIAGNOSTICS=1', '-DJSON_USE_IMPLICIT_CONVERSIONS=0', '-Wshadow', '-Wconversion', '-Wpedantic', language : ['c', 'cpp'])

includes = include_directories('src')

httplib = subproject('cpp-httplib', default_options: ['cpp-httplib_openssl=enabled', 'cpp-httplib_compile=true'])
cpp_httplib_dep = httplib.get_variable('cpp_httplib_dep')
thread_dep = dependency('threads')

json = dependency('nlohmann_json')

cmake = import('cmake')
opt_var = cmake.subproject_options()

# Globally override the C++ standard to c++20
opt_var.set_override_option('cpp_std', 'c++20')
opt_var.set_override_option('cpp_std', 'c++20', target: 'soci_core')
opt_var.set_override_option('cpp_std', 'c++20', target: 'soci_postgresql')
opt_var.add_cmake_defines({'WITH_BOOST': false, 'SOCI_ORACLE': false, 'SOCI_ODBC': false, 'SOCI_FIREBIRD': false, 'SOCI_STATIC': false, 'CMAKE_CXX_STANDARD': '20'})

soci = cmake.subproject('SOCI', options: opt_var)
soci_core = soci.dependency('soci_core')
soci_postgresql = soci.dependency('soci_postgresql')


src = files([
    'src/main.cpp',
    'src/utils/utils.cpp',
    'src/webserver/webserver.cpp'
])

executable('persephone', src, include_directories : includes, dependencies : [cpp_httplib_dep, json, thread_dep, soci_core, soci_postgresql], install: true)
