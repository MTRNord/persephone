project('persephone', 'cpp', version : '0.1.0', default_options : ['cpp_std=c++20', 'warning_level=3', 'strip=true'])
add_project_arguments('-DJSON_DIAGNOSTICS=1', '-DJSON_USE_IMPLICIT_CONVERSIONS=0', language : ['c', 'cpp'])

includes = include_directories('src')

httplib = subproject('cpp-httplib', default_options: ['cpp-httplib_openssl=enabled', 'cpp-httplib_compile=true'])
cpp_httplib_dep = httplib.get_variable('cpp_httplib_dep')
thread_dep = dependency('threads')

json = dependency('nlohmann_json')

src = files([
    'src/main.cpp',
    'src/utils/utils.cpp',
    'src/webserver/webserver.cpp'
])

executable('persephone', src, include_directories : includes, dependencies : [cpp_httplib_dep, json, thread_dep], install: true)
