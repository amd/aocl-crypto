# Find google benchmark package
find_package(benchmark REQUIRED)
find_package(GTest REQUIRED)

# Include all the ALCP Headers
INCLUDE_DIRECTORIES(
	"${CMAKE_SOURCE_DIR}/include" 
	"${CMAKE_SOURCE_DIR}/lib/include"
    "${CMAKE_CURRENT_SOURCE_DIR}/include")

#include test inc files
INCLUDE_DIRECTORIES(
        "${CMAKE_SOURCE_DIR}/bench/digest_new/include"
        "${CMAKE_SOURCE_DIR}/bench/digest_new/test_data"
        )

link_directories("${CMAKE_SOURCE_DIR}/bench/digest_new/")

set(CMAKE_CXX_FLAGS  "${CMAKE_CXX_FLAGS} -Wall -Werror")

if(benchmark_FOUND)
    ADD_EXECUTABLE(bench_digest 
                    base/alc_base.cc
                    base/base.cc
                    bench_main.cc)
    message(STATUS "Found google benchmark lib in ${benchmark_DIR}")
    target_link_libraries(bench_digest alcp)
    target_link_libraries(bench_digest gtest)
    target_link_libraries(bench_digest benchmark::benchmark)
    target_link_libraries(bench_digest pthread)
else(benchmark_FOUND)
    message(FATAL_ERROR "Google Benchmark not found, cannot proceed")
endif(benchmark_FOUND)
