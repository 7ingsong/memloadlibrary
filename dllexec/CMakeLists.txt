cmake_minimum_required(VERSION 3.14)

add_library(dllexec dllexec.c dllimage.c)

add_executable(dllexec_example main.c)
target_link_libraries(dllexec_example dllexec minhook)

add_library(testdll SHARED testdll.cpp)
target_link_libraries(testdll dllexec minhook)