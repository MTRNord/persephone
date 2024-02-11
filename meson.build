project(
    'persephone',
    'cpp',
    version: '0.1.0',
    default_options: [
        'cpp_std=c++20',
        'c_std=c11',
        'warning_level=3',
        # yaml_cpp break werror. Fixes appreciated
        #'werror=true',
        'b_lto=true',
        'b_thinlto_cache=true',
        #'b_sanitize=address,undefined',
        # Clang fails to link with sanatizers without this: https://github.com/mesonbuild/meson/issues/764
        #'b_lundef=false',
    ],
)
#
add_project_arguments(
    '-DJSON_DIAGNOSTICS=0',
    '-DJSON_USE_IMPLICIT_CONVERSIONS=0',
    '-Wshadow',
    '-Wconversion',
    '-Wpedantic',
    '-Wuninitialized',
    #'-Wpadded',
    '-DWITH_BOOST=OFF',
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

###### DNS #######
c_ares = dependency('libcares')

####### Tests ############
snitch_dep = dependency('snitch')

src = files(
    'src/database/database.cpp',
    'src/database/migrations/migrator.cpp',
    'src/utils/config.cpp',
    'src/utils/json_utils.cpp',
    'src/utils/utils.cpp',
    'src/utils/state_res.cpp',
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
    c_ares,
]

executable(
    'persephone',
    src + 'src/main.cpp',
    include_directories: includes,
    dependencies: deps,
    install: true,
)

if not get_option('disable_tests')
test(
    'utils',
    executable(
        'utils_test',
        src + 'tests/utils_test.cpp',
        include_directories: includes,
        dependencies: deps + snitch_dep,
    ),
)

test(
    'state_res',
    executable(
        'state_res_test',
        src + 'tests/state_res_test.cpp',
        include_directories: includes,
        dependencies: deps + snitch_dep,
    ),
)
endif

if get_option('build_fuzz_targets')
    executable(
        'fuzz_json_sign',
        src + 'fuzz_targets/json_sign.cpp',
        include_directories: includes,
        dependencies: deps,
    )
endif
