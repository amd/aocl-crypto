include(FetchContent)
FetchContent_Declare(benchmark
        GIT_REPOSITORY https://github.com/google/benchmark.git
        GIT_TAG v1.6.1)
FetchContent_MakeAvailable(benchmark)

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

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall")

set(ALC_BASE_FILES ${ALC_BASE_FILES} ../../tests/cipher/base/alc_base.cc ../../tests/cipher/base/base.cc)
set(LIBS ${LIBS} benchmark alcp)
if(ippcp_FOUND)
    message(STATUS "Found IPPCP: ${ippcp_DIR}")
    add_compile_options("-DUSE_IPP")
    # If there is IPP, add IPP source and add IPP liberary
    set(EXTRA_SOURCES ${EXTRA_SOURCES} ../../tests/cipher/base/ipp_base.cc)
    set(LIBS ${LIBS} ippcp)
endif(ippcp_FOUND)

if(OPENSSL_INSTALL_DIR)
    add_compile_options("-DUSE_OSSL")
    # If there is OpenSSL, add OpenSSL source and add OpenSSL liberary
    set(EXTRA_SOURCES ${EXTRA_SOURCES} ../../tests/cipher/base/openssl_base.cc)
    set(LIBS ${LIBS} ${OPENSSL_INSTALL_DIR}/lib64/libcrypto.so)
endif(OPENSSL_INSTALL_DIR)

ADD_EXECUTABLE(bench_cipher bench_main.cc ${ALC_BASE_FILES} ${EXTRA_SOURCES})

target_link_libraries(bench_cipher ${LIBS})

