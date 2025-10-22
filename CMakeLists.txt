cmake_minimum_required(VERSION 3.5)
project(vm_course_02)

set(CMAKE_CXX_STANDARD 20)

add_subdirectory(runtime)

# add_compile_options(-fsanitize=address)
# add_link_options(-fsanitize=address)
add_executable(vm_course_02 main.cpp)
target_include_directories(vm_course_02 PRIVATE runtime)
target_link_libraries(vm_course_02 PRIVATE runtime)
