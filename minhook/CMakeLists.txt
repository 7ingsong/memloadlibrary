cmake_minimum_required(VERSION 3.14)
add_library(minhook buffer.c hde32.c hde64.c hook.c trampoline.c MinHook.def)