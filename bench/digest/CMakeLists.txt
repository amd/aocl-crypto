# Find google benchmark package
find_package(benchmark REQUIRED)

# Include all the ALCP Headers
INCLUDE_DIRECTORIES(
	"${CMAKE_SOURCE_DIR}/include" 
	"${CMAKE_SOURCE_DIR}/lib/include"
    "${CMAKE_CURRENT_SOURCE_DIR}/include"
    "${CMAKE_SOURCE_DIR}/tests/digest/include")

link_directories("${CMAKE_CURRENT_SOURCE_DIR}")

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Werror")

if(benchmark_FOUND)
    ADD_EXECUTABLE(bench_digest
                    ../../tests/digest/base/alc_base.cc
                    ../../tests/digest/base/base.cc
                    bench_main.cc)
    message(STATUS "Found google benchmark lib in ${benchmark_DIR}")
    target_link_libraries(bench_digest alcp)
    target_link_libraries(bench_digest benchmark::benchmark)
    target_link_libraries(bench_digest pthread)
else(benchmark_FOUND)
    message(FATAL_ERROR "Google Benchmark not found, cannot proceed")
endif(benchmark_FOUND)
