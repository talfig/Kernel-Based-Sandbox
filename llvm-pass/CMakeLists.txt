
cmake_minimum_required(VERSION 3.15)
project(LibCallPolicy LANGUAGES CXX)

# Allow user to specify LLVM dir: -DLLVM_DIR=.../lib/cmake/llvm
find_package(LLVM REQUIRED CONFIG)
message(STATUS "Found LLVM ${LLVM_PACKAGE_VERSION}")
message(STATUS "Using LLVMConfig.cmake in: ${LLVM_DIR}")

include_directories(${LLVM_INCLUDE_DIRS})
add_definitions(${LLVM_DEFINITIONS})
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# New Pass Manager plugin (LLVM 14+ recommended)
add_library(LibCallPass SHARED
  src/LibCallPass.cpp
  src/LibCallGraph.cpp
)

# Export compile commands for clangd
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Ensure we can use LLVM's headers cleanly
if (MSVC)
  target_compile_options(LibCallPass PRIVATE /EHsc)
else()
  target_compile_options(LibCallPass PRIVATE -fno-rtti -fPIC)
endif()

# Link against LLVM
llvm_map_components_to_libnames(REQ_LLVM_LIBS
  Core
  IRReader
  Support
  Analysis
  TransformUtils
  ScalarOpts
  Passes
)

target_link_libraries(LibCallPass PRIVATE ${REQ_LLVM_LIBS})

# Install step (optional)
install(TARGETS LibCallPass LIBRARY DESTINATION lib)
