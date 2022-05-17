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

set(ALC_BASE_FILES ${ALC_BASE_FILES} ../../tests/common/base/base_common.cc ../../tests/cipher/base/alc_base.cc ../../tests/cipher/base/base.cc)
set(LIBS ${LIBS} benchmark alcp)
set(EXTRA_INCLUDES "")

if(ENABLE_TESTS_IPP_API)
    add_compile_options("-DUSE_IPP")
    IF(IPP_INSTALL_DIR)
        MESSAGE(STATUS "IPP_INSTALL_DIR set, overriding fetch path")
    ELSE(IPP_INSTALL_DIR)
        SET(IPP_INSTALL_DIR "${CMAKE_SOURCE_DIR}/external")
        MESSAGE(STATUS "IPP_INSTALL_DIR not set, defaulting to external")
    ENDIF(IPP_INSTALL_DIR)
    # If there is IPP, add IPP source and add IPP liberary
    set(EXTRA_SOURCES ${EXTRA_SOURCES} ../../tests/cipher/base/ipp_base.cc)
    if(EXISTS ${IPP_INSTALL_DIR}/lib/intel64/libippcp.a)
        set(LIBS ${LIBS} ${IPP_INSTALL_DIR}/lib/intel64/libippcp.a)
    else(EXISTS ${IPP_INSTALL_DIR}/lib/intel64/libippcp.a)
        set(LIBS ${LIBS} ${IPP_INSTALL_DIR}/lib/intel/libippcp.a)
    endif(EXISTS ${IPP_INSTALL_DIR}/lib/intel64/libippcp.a)
    set(EXTRA_INCLUDES ${EXTRA_INCLUDES} ${IPP_INSTALL_DIR}/include)
endif(ENABLE_TESTS_IPP_API)

IF(ENABLE_TESTS_OPENSSL_API)
    add_compile_options("-DUSE_OSSL")
    IF(OPENSSL_INSTALL_DIR)
        MESSAGE(STATUS "OPENSSL_INSTALL_DIR set, overriding fetch path")
    ELSE(OPENSSL_INSTALL_DIR)
        SET(OPENSSL_INSTALL_DIR "${CMAKE_SOURCE_DIR}/external")
        MESSAGE(STATUS "OPENSSL_INSTALL_DIR not set, defaulting to external")
    ENDIF(OPENSSL_INSTALL_DIR)
    # If there is OpenSSL, add OpenSSL source and add OpenSSL liberary
    set(EXTRA_SOURCES ${EXTRA_SOURCES} ../../tests/cipher/base/openssl_base.cc)
    if(EXISTS ${OPENSSL_INSTALL_DIR}/lib64/libcrypto.so)
        set(LIBS ${LIBS} ${OPENSSL_INSTALL_DIR}/lib64/libcrypto.so)
    else(EXISTS ${OPENSSL_INSTALL_DIR}/lib64/libcrypto.so)
        set(LIBS ${LIBS} ${OPENSSL_INSTALL_DIR}/lib/libcrypto.so)
    endif(EXISTS ${OPENSSL_INSTALL_DIR}/lib64/libcrypto.so)
    set(EXTRA_INCLUDES ${EXTRA_INCLUDES} ${OPENSSL_INSTALL_DIR}/include)
endif(ENABLE_TESTS_OPENSSL_API)

ADD_EXECUTABLE(bench_cipher bench_main.cc ${ALC_BASE_FILES} ${EXTRA_SOURCES})

target_include_directories(bench_cipher PRIVATE
	"${CMAKE_SOURCE_DIR}/include" 
	"${CMAKE_SOURCE_DIR}/lib/include"
    "${CMAKE_CURRENT_SOURCE_DIR}/include"
    "${CMAKE_SOURCE_DIR}/tests/cipher/include"
    "${CMAKE_SOURCE_DIR}/tests/common/include"
    ${EXTRA_INCLUDES})

target_link_libraries(bench_cipher ${LIBS})

