INCLUDE(FetchContent)
INCLUDE(GoogleTest)
FetchContent_Declare(gtest
    GIT_REPOSITORY https://github.com/google/googletest.git
    GIT_TAG 4523B6410BFCD3289597FA2B5B6E18DE)
FetchContent_MakeAvailable(gtest)

# Basic sources and libs needed for ALCP
SET(ALC_BASE_FILES ${ALC_BASE_FILES} ../common/base/rng_base.cc ../common/base/base_common.cc base/alc_base.cc base/base.cc)
SET(LIBS ${LIBS} gtest alcp)
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
    SET(EXTRA_SOURCES ${EXTRA_SOURCES} base/ipp_base.cc)

    IF(EXISTS ${IPP_INSTALL_DIR}/lib/intel64/libippcp.so)
        SET(LIBS ${LIBS} ${IPP_INSTALL_DIR}/lib/intel64/libippcp.so)
    ELSE(EXISTS ${IPP_INSTALL_DIR}/lib/intel/libippcp.so)
        SET(LIBS ${LIBS} ${IPP_INSTALL_DIR}/lib/intel/libippcp.so)
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
    SET(EXTRA_SOURCES ${EXTRA_SOURCES} base/openssl_base.cc)

    IF(EXISTS ${OPENSSL_INSTALL_DIR}/lib64/libcrypto.so)
        SET(LIBS ${LIBS} ${OPENSSL_INSTALL_DIR}/lib64/libcrypto.so)
    ELSEIF(EXISTS ${OPENSSL_INSTALL_DIR}/lib/libcrypto.so)
        SET(LIBS ${LIBS} ${OPENSSL_INSTALL_DIR}/lib/libcrypto.so)
    ELSE()
        SET(LIBS ${LIBS} ${OPENSSL_INSTALL_DIR}/lib/x86_64-linux-gnu/libcrypto.so)
    ENDIF()
ENDIF(ENABLE_TESTS_OPENSSL_API)

SET(LIBS ${LIBS} pthread)

ADD_EXECUTABLE(test_digest test_main.cc ${ALC_BASE_FILES} ${EXTRA_SOURCES})

TARGET_INCLUDE_DIRECTORIES(test_digest PRIVATE
	"${CMAKE_SOURCE_DIR}/include" 
	"${CMAKE_SOURCE_DIR}/lib/include"
    "${CMAKE_CURRENT_SOURCE_DIR}/../include"
    "${CMAKE_CURRENT_SOURCE_DIR}/../common/include"
    ${EXTRA_INCLUDES})

target_compile_options(test_digest PUBLIC -Wall -Werror)
TARGET_LINK_LIBRARIES(test_digest ${LIBS})

ADD_EXECUTABLE(test_digest_cross test_cross.cc ${ALC_BASE_FILES} ${EXTRA_SOURCES})

TARGET_INCLUDE_DIRECTORIES(test_digest_cross PRIVATE
	"${CMAKE_SOURCE_DIR}/include"
	"${CMAKE_SOURCE_DIR}/lib/include"
    "${CMAKE_CURRENT_SOURCE_DIR}/../include"
    "${CMAKE_CURRENT_SOURCE_DIR}/../common/include"
    ${EXTRA_INCLUDES})

target_compile_options(test_digest_cross PUBLIC -Wall -Werror)
TARGET_LINK_LIBRARIES(test_digest_cross ${LIBS})

FUNCTION(TEST_DATA_LINK SHA_ALG)
    # Link dataset to the root dir
    FILE(CREATE_LINK ${CMAKE_CURRENT_SOURCE_DIR}/test_data/dataset_${SHA_ALG}.csv ${CMAKE_BINARY_DIR}/dataset_${SHA_ALG}.csv SYMBOLIC)

    # Link dataset to the actual place of test binary
    FILE(CREATE_LINK ${CMAKE_CURRENT_SOURCE_DIR}/test_data/dataset_${SHA_ALG}.csv ${CMAKE_CURRENT_BINARY_DIR}/dataset_${SHA_ALG}.csv SYMBOLIC)
ENDFUNCTION(TEST_DATA_LINK SHA_ALG)

TEST_DATA_LINK(SHA_224)
TEST_DATA_LINK(SHA_256)
TEST_DATA_LINK(SHA_384)
TEST_DATA_LINK(SHA_512)

gtest_add_tests(TARGET test_digest)

IF(ENABLE_TESTS_OPENSSL_API)
    gtest_add_tests(TARGET test_digest_cross)
ENDIF(ENABLE_TESTS_OPENSSL_API)
