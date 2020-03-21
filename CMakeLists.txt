cmake_minimum_required(VERSION 3.10)

# set the project name
project(pgc VERSION 0.1)

configure_file(pgcconfig.h.in config.h)

# add the executable
add_executable(pgc pgc.c)

target_include_directories(pgc PUBLIC
                           "${PROJECT_BINARY_DIR}"
                           )