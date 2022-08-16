INCLUDE(FetchContent)
FetchContent_Declare(gtest
    GIT_REPOSITORY https://github.com/google/googletest.git
    GIT_TAG 4523B6410BFCD3289597FA2B5B6E18DE)
FetchContent_MakeAvailable(gtest)
FetchContent_Declare(benchmark
    GIT_REPOSITORY https://github.com/google/benchmark.git
    GIT_TAG v1.6.1)
FetchContent_MakeAvailable(benchmark)

SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}")

SET(ALC_BASE_FILES ${ALC_BASE_FILES} ../../tests/common/base/base_common.cc ../../tests/cipher/base/alc_base.cc ../../tests/cipher/base/base.cc)
SET(LIBS ${LIBS} benchmark alcp)
SET(EXTRA_INCLUDES "")

IF(ENABLE_TESTS_IPP_API)
    ADD_COMPILE_OPTIONS("-DUSE_IPP")
    IF(IPP_INSTALL_DIR)
        MESSAGE(STATUS "IPP_INSTALL_DIR set, overriding fetch path")
    ELSE(IPP_INSTALL_DIR)
        SET(IPP_INSTALL_DIR "${CMAKE_SOURCE_DIR}/external")
        MESSAGE(STATUS "IPP_INSTALL_DIR not set, defaulting to external")
    ENDIF(IPP_INSTALL_DIR)
    # If there is IPP, add IPP source and add IPP liberary
    SET(EXTRA_SOURCES ${EXTRA_SOURCES} ../../tests/cipher/base/ipp_base.cc)
    IF(EXISTS ${IPP_INSTALL_DIR}/lib/intel64/libippcp.so)
        set(LIBS ${LIBS} ${IPP_INSTALL_DIR}/lib/intel64/libippcp.so)
    ELSE(EXISTS ${IPP_INSTALL_DIR}/lib/intel/libippcp.so)
        set(LIBS ${LIBS} ${IPP_INSTALL_DIR}/lib/intel/libippcp.so)
    ENDIF(EXISTS ${IPP_INSTALL_DIR}/lib/intel64/libippcp.so)

    SET(EXTRA_INCLUDES ${EXTRA_INCLUDES} ${IPP_INSTALL_DIR}/include)
ENDIF(ENABLE_TESTS_IPP_API)

IF(ENABLE_TESTS_OPENSSL_API)
    ADD_COMPILE_OPTIONS("-DUSE_OSSL")
    IF(OPENSSL_INSTALL_DIR)
        MESSAGE(STATUS "OPENSSL_INSTALL_DIR set, overriding fetch path")
    ELSE(OPENSSL_INSTALL_DIR)
        SET(OPENSSL_INSTALL_DIR "${CMAKE_SOURCE_DIR}/external")
        MESSAGE(STATUS "OPENSSL_INSTALL_DIR not set, defaulting to external")
    ENDIF(OPENSSL_INSTALL_DIR)
    # If there is OpenSSL, add OpenSSL source and add OpenSSL liberary
    SET(EXTRA_SOURCES ${EXTRA_SOURCES} ../../tests/cipher/base/openssl_base.cc)
    IF(EXISTS ${OPENSSL_INSTALL_DIR}/lib64/libcrypto.so)
        SET(LIBS ${LIBS} ${OPENSSL_INSTALL_DIR}/lib64/libcrypto.so)
    ELSEIF(EXISTS ${OPENSSL_INSTALL_DIR}/lib/libcrypto.so)
        SET(LIBS ${LIBS} ${OPENSSL_INSTALL_DIR}/lib/libcrypto.so)
    ELSE()
        SET(LIBS ${LIBS} ${OPENSSL_INSTALL_DIR}/lib/x86_64-linux-gnu/libcrypto.so)
    ENDIF()
    SET(EXTRA_INCLUDES ${EXTRA_INCLUDES} ${OPENSSL_INSTALL_DIR}/include)
ENDIF(ENABLE_TESTS_OPENSSL_API)

ADD_EXECUTABLE(bench_cipher bench_main.cc ${ALC_BASE_FILES} ${EXTRA_SOURCES})

TARGET_INCLUDE_DIRECTORIES(bench_cipher PRIVATE
	"${CMAKE_SOURCE_DIR}/include" 
	"${CMAKE_SOURCE_DIR}/lib/include"
    "${CMAKE_CURRENT_SOURCE_DIR}/include"
    "${CMAKE_SOURCE_DIR}/tests/include"
    "${CMAKE_SOURCE_DIR}/tests/common/include"
    ${EXTRA_INCLUDES})

TARGET_COMPILE_OPTIONS(bench_cipher PUBLIC ${ALCP_WARNINGS})
TARGET_LINK_LIBRARIES(bench_cipher ${LIBS})

