project('persephone', 'cpp', version : '0.1.0', default_options : ['cpp_std=c++20', 'warning_level=3'])

includes = include_directories('src')

httplib = subproject('cpp-httplib', default_options: ['cpp-httplib_openssl=enabled'])
cpp_httplib_dep = httplib.get_variable('cpp_httplib_dep')

json = dependency('nlohmann_json')

src = [
    'src/main.cpp',
    'src/utils/utils.cpp',
    'src/webserver/webserver.cpp'
]

executable('persephone', src, include_directories : includes, dependencies : [cpp_httplib_dep, json], install: true)
