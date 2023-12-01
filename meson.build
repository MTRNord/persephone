project(
    'persephone',
    'cpp',
    version: '0.1.0',
    default_options: [
        'cpp_std=c++20',
        'c_std=c11',
        'warning_level=3',
        # SOCI and yaml_cpp break werror. Fixes appreciated
        #'werror=true',
        'b_lto=true',
        'b_thinlto_cache=true',
        # https://github.com/SOCI/soci/issues/1103
        #'b_sanitize=address,undefined',
        #        'b_sanitize=address',
        # Clang fails to link with sanatizers without this: https://github.com/mesonbuild/meson/issues/764
        #        'b_lundef=false',
    ],
)
#
add_project_arguments(
    '-DJSON_DIAGNOSTICS=1',
    '-DJSON_USE_IMPLICIT_CONVERSIONS=0',
    '-Wshadow',
    '-Wconversion',
    '-Wpedantic',
    '-DWITH_BOOST=OFF',
    '-D_FORTIFY_SOURCE=2',
    #'-fno-sanitize=vptr',
    language: ['c', 'cpp'],
)

includes = include_directories('src')

####### Webserver/Matrix ############
drogon_dep = dependency('Drogon')

json = dependency('nlohmann_json')

###### Config #######
yaml_cpp_dep = dependency('yaml_cpp')

###### libsodium #######
libsodium_dep = dependency('libsodium')
zlib_dep = dependency('zlib')

####### Tests ############
snitch_dep = dependency('snitch')

src = files(
    'src/database/database.cpp',
    'src/utils/config.cpp',
    'src/utils/json_utils.cpp',
    'src/utils/utils.cpp',
    'src/webserver/client_server_api/ClientServerCtrl.cpp',
    'src/webserver/json.cpp',
    'src/webserver/server_server_api/ServerServerCtrl.cpp',
)

deps = [
    drogon_dep,
    json,
    yaml_cpp_dep,
    libsodium_dep,
    zlib_dep,
]

executable(
    'persephone',
    src + 'src/main.cpp',
    include_directories: includes,
    dependencies: deps,
    install: true,
)

test(
    'utils',
    executable(
        'utils_test',
        src + 'tests/utils_test.cpp',
        include_directories: includes,
        dependencies: deps + snitch_dep,
        build_by_default: false,
    ),
)
