include(FetchContent)
FetchContent_Declare(gtest
    GIT_REPOSITORY https://github.com/google/googletest.git
    GIT_TAG 4523B6410BFCD3289597FA2B5B6E18DE)
FetchContent_MakeAvailable(gtest)
FetchContent_Declare(benchmark
    GIT_REPOSITORY https://github.com/google/benchmark.git
    GIT_TAG v1.6.1)
FetchContent_MakeAvailable(benchmark)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall")

set(ALC_BASE_FILES ${ALC_BASE_FILES} ../../tests/cipher/base/alc_base.cc ../../tests/cipher/base/base.cc)
set(LIBS ${LIBS} benchmark alcp)

if(ENABLE_TESTS_IPP_API)
    add_compile_options("-DUSE_IPP")
    # If there is IPP, add IPP source and add IPP liberary
    set(EXTRA_SOURCES ${EXTRA_SOURCES} ../../tests/cipher/base/ipp_base.cc)
    set(LIBS ${LIBS} ${IPP_INSTALL_DIR}/lib/intel64/libippcp.a)
endif(ENABLE_TESTS_IPP_API)

if(OPENSSL_INSTALL_DIR)
    add_compile_options("-DUSE_OSSL")
    # If there is OpenSSL, add OpenSSL source and add OpenSSL liberary
    set(EXTRA_SOURCES ${EXTRA_SOURCES} ../../tests/cipher/base/openssl_base.cc)
    set(LIBS ${LIBS} ${OPENSSL_INSTALL_DIR}/lib64/libcrypto.so)
endif(OPENSSL_INSTALL_DIR)

ADD_EXECUTABLE(bench_cipher bench_main.cc ${ALC_BASE_FILES} ${EXTRA_SOURCES})

target_include_directories(bench_cipher PRIVATE
	"${CMAKE_SOURCE_DIR}/include" 
	"${CMAKE_SOURCE_DIR}/lib/include"
    "${CMAKE_CURRENT_SOURCE_DIR}/include"
    "${CMAKE_SOURCE_DIR}/tests/cipher/include"
    "${CMAKE_SOURCE_DIR}/tests/common/include")

target_link_libraries(bench_cipher ${LIBS})

