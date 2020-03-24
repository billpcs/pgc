cmake_minimum_required(VERSION 3.10)

# usage:
#   $ cd build/
#   $ cmake -G "Unix Makefiles" ..
#   $ make

# set the project name
project(pgc VERSION 0.1)

configure_file(pgcconfig.h.in config.h)

# add the executable
add_executable(pgc pgc.c)

if(WIN32)
  target_link_libraries(pgc wsock32 ws2_32)
endif()

target_include_directories(pgc PUBLIC
                           "${PROJECT_BINARY_DIR}"
                           )