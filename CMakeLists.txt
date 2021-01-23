# We need version 3.12 to not have to rerun cmake when our glob changes
cmake_minimum_required(VERSION 3.12)

project(enku)

# Using C++ 17 as our standard, and requiring that standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# CONFIGURE_DEPENDS makes it so that whenever this changes, we can just
# run `make`, without having to rerun `cmake` all over again.
file(GLOB_RECURSE sources CONFIGURE_DEPENDS "src/*.cpp")

# Create a lox executable from the sources we've gathered
add_executable(enku ${sources})
# Standard, but strict compiler options
target_compile_options(enku PRIVATE -Werror -Wall -Wextra)
