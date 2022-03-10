# Find google benchmark package
find_package(benchmark REQUIRED)

# Include all the ALCP Headers
INCLUDE_DIRECTORIES(
	"${CMAKE_SOURCE_DIR}/include" 
	"${CMAKE_SOURCE_DIR}/lib/include")

#include test inc files
INCLUDE_DIRECTORIES(
        "${CMAKE_SOURCE_DIR}/bench/cipher/include"
        "${CMAKE_SOURCE_DIR}/bench/cipher/test_data")

add_subdirectory(common)

file(GLOB src_common "${CMAKE_SOURCE_DIR}/bench/cipher/common/*.cc")

link_directories("${CMAKE_SOURCE_DIR}/bench/digest/common")

set(CMAKE_CXX_FLAGS  "${CMAKE_CXX_FLAGS} -Wall -Werror")

if(benchmark_FOUND)
    ADD_EXECUTABLE(bench_cipher bench_main.cc ${src_common})
    message(STATUS "Found google benchmark lib in ${benchmark_DIR}")
    target_link_libraries(bench_cipher alcp)
    target_link_libraries(bench_cipher benchmark::benchmark)
else(benchmark_FOUND)
    message(FATAL_ERROR "Google Benchmark not found, cannot proceed")
endif(benchmark_FOUND)
