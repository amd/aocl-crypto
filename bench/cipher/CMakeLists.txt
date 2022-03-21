# Find google benchmark package
find_package(benchmark REQUIRED)
find_package(GTest REQUIRED)
if(ENABLE_TESTS_IPP_API)
    find_package(ippcp)
endif(ENABLE_TESTS_IPP_API)

# Include all the ALCP Headers
INCLUDE_DIRECTORIES(
	"${CMAKE_SOURCE_DIR}/include" 
	"${CMAKE_SOURCE_DIR}/lib/include"
    "${CMAKE_CURRENT_SOURCE_DIR}/include"
    "${CMAKE_SOURCE_DIR}/tests/cipher/include")

link_directories("${CMAKE_CURRENT_SOURCE_DIR}")

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Werror")

if(ippcp_FOUND)
        message(STATUS "Found IPPCP: ${ippcp_DIR}")
        add_compile_options("-DUSE_IPP")
endif(ippcp_FOUND)

if(benchmark_FOUND)
    if(ippcp_FOUND)
        ADD_EXECUTABLE(bench_cipher 
                        ../../tests/cipher/base/alc_base.cc
                    ../../tests/cipher/base/base.cc
                    ../../tests/cipher/base/ipp_base.cc
                        bench_main.cc)
    else(ippcp_FOUND)
        ADD_EXECUTABLE(bench_cipher 
                        ../../tests/cipher/base/alc_base.cc
                    ../../tests/cipher/base/base.cc
                        bench_main.cc)
    endif(ippcp_FOUND)
    message(STATUS "Found google benchmark lib in ${benchmark_DIR}")
    if(ippcp_FOUND)
       target_link_libraries(bench_cipher ippcp)
    endif(ippcp_FOUND)
    target_link_libraries(bench_cipher alcp)
    target_link_libraries(bench_cipher gtest)
    target_link_libraries(bench_cipher benchmark::benchmark)
    target_link_libraries(bench_cipher pthread)
    
else(benchmark_FOUND)
    message(FATAL_ERROR "Google Benchmark not found, cannot proceed")
endif(benchmark_FOUND)
