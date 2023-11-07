project('persephone', 'cpp', version : '0.1.0', default_options : ['cpp_std=c++20', 'warning_level=3'])

includes = include_directories('src')
webserver = include_directories('uWebSockets/src')

executable('persephone', 'src/main.cpp', include_directories : [webserver,includes])
