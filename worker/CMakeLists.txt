cmake_minimum_required(VERSION 3.24)
project(gri_worker VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
option(GRI_BUILD_CUDA "Build the CUDA worker (requires NVIDIA CUDA Toolkit)" OFF)

enable_testing()
add_executable(gri-known-answer-test tests/known_answer.cpp)
target_include_directories(gri-known-answer-test PRIVATE include)
target_compile_options(gri-known-answer-test PRIVATE -Wall -Wextra -Wpedantic)
add_test(NAME cpu-known-answers-and-synthetic-corruption COMMAND gri-known-answer-test)

if(GRI_BUILD_CUDA)
  enable_language(CUDA)
  find_package(CUDAToolkit 12.0 REQUIRED)
  add_executable(gri-cuda-worker src/main.cu)
  target_include_directories(gri-cuda-worker PRIVATE include)
  target_link_libraries(gri-cuda-worker PRIVATE CUDA::cudart CUDA::cublas)
  set_target_properties(gri-cuda-worker PROPERTIES
    CUDA_STANDARD 17 CUDA_STANDARD_REQUIRED YES
    CUDA_RUNTIME_LIBRARY Shared
    CUDA_ARCHITECTURES "90-real;90-virtual")
  target_compile_options(gri-cuda-worker PRIVATE
    $<$<COMPILE_LANGUAGE:CUDA>:--fmad=false;-lineinfo>)
  install(TARGETS gri-cuda-worker RUNTIME DESTINATION libexec)
endif()
