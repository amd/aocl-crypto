INCLUDE(FetchContent)
INCLUDE(GoogleTest)
FetchContent_Declare(gtest
    GIT_REPOSITORY https://github.com/google/googletest.git
    GIT_TAG release-1.12.1)
FetchContent_MakeAvailable(gtest)

# Basic sources and libs needed for ALCP
#SET(ALC_BASE_FILES ${ALC_BASE_FILES} openssl_ecdh.cc )
SET(LIBS ${LIBS} gtest alcp)

# add this if asan is used
if (ALCP_USE_ASAN)
    SET(LIBS ${LIBS} asan)
endif()

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
    SET(EXTRA_SOURCES ${EXTRA_SOURCES} ippcp_curve25519.cc)
    SET(EXTRA_SOURCES ${EXTRA_SOURCES} alcp_curve25519.cc)

    IF(UNIX)
        IF(EXISTS ${IPP_INSTALL_DIR}/lib/intel64/libippcp.so)
            SET(LIBS ${LIBS} ${IPP_INSTALL_DIR}/lib/intel64/libippcp.so)
        ELSE(EXISTS ${IPP_INSTALL_DIR}/lib/intel/libippcp.so)
            SET(LIBS ${LIBS} ${IPP_INSTALL_DIR}/lib/intel/libippcp.so)
        ENDIF(EXISTS ${IPP_INSTALL_DIR}/lib/intel64/libippcp.so)

        IF(EXISTS ${IPP_INSTALL_DIR}/lib/intel64/libcrypto_mb.so)
            SET(LIBS ${LIBS} ${IPP_INSTALL_DIR}/lib/intel64/libcrypto_mb.so)
        ELSE(EXISTS ${IPP_INSTALL_DIR}/lib/intel/libcrypto_mb.so)
            SET(LIBS ${LIBS} ${IPP_INSTALL_DIR}/lib/intel/libcrypto_mb.so)
        ENDIF(EXISTS ${IPP_INSTALL_DIR}/lib/intel64/libcrypto_mb.so)
    ENDIF(UNIX)

    IF(WIN32)
	    IF(EXISTS ${IPP_INSTALL_DIR}/lib/intel64/ippcp.lib)
            SET(LIBS ${LIBS} ${IPP_INSTALL_DIR}/lib/intel64/ippcp.lib)
	    ELSEIF(EXISTS ${IPP_INSTALL_DIR}/lib/intel/ippcp.lib)
            SET(LIBS ${LIBS} ${IPP_INSTALL_DIR}/lib/intel/ippcp.lib)
	    ELSE(EXISTS ${IPP_INSTALL_DIR}/lib/ippcp.lib)
	        SET(LIBS ${LIBS} ${IPP_INSTALL_DIR}/lib/ippcp.lib)
	    ENDIF()

        IF(EXISTS ${IPP_INSTALL_DIR}/lib/intel64/crypto_mb.lib)
            SET(LIBS ${LIBS} ${IPP_INSTALL_DIR}/lib/intel64/crypto_mb.lib)
        ELSEIF(EXISTS ${IPP_INSTALL_DIR}/lib/intel/crypto_mb.lib)
            SET(LIBS ${LIBS} ${IPP_INSTALL_DIR}/lib/intel/crypto_mb.lib)
        ELSE(EXISTS ${IPP_INSTALL_DIR}/lib/crypto_mb.lib)
	        SET(LIBS ${LIBS} ${IPP_INSTALL_DIR}/lib/crypto_mb.lib)
        ENDIF()
	ENDIF(WIN32)

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
    SET(EXTRA_SOURCES ${EXTRA_SOURCES} openssl_curve25519.cc)
    IF(UNIX)
        IF(EXISTS ${OPENSSL_INSTALL_DIR}/lib64/libcrypto.so)
            SET(LIBS ${LIBS} ${OPENSSL_INSTALL_DIR}/lib64/libcrypto.so)
        ELSEIF(EXISTS ${OPENSSL_INSTALL_DIR}/lib/libcrypto.so)
            SET(LIBS ${LIBS} ${OPENSSL_INSTALL_DIR}/lib/libcrypto.so)
        ELSE()
            SET(LIBS ${LIBS} ${OPENSSL_INSTALL_DIR}/lib/x86_64-linux-gnu/libcrypto.so)
        ENDIF()
    ENDIF(UNIX)

    IF(WIN32)
		IF(EXISTS ${OPENSSL_INSTALL_DIR}/lib/libcrypto.lib)
			INCLUDE_DIRECTORIES(${OPENSSL_INSTALL_DIR}/include)
			INCLUDE_DIRECTORIES(${OPENSSL_INSTALL_DIR}/bin)
			SET(LIBS ${LIBS} ${OPENSSL_INSTALL_DIR}/lib/libcrypto.lib)
		ENDIF()
	ENDIF(WIN32)

    SET(EXTRA_INCLUDES ${EXTRA_INCLUDES} ${OPENSSL_INSTALL_DIR}/include)
ENDIF(ENABLE_TESTS_OPENSSL_API)

IF(UNIX)
SET(LIBS ${LIBS} pthread)
ENDIF()


#ADD_EXECUTABLE(test_ecdh test_ecdh_kat.cc ${ALC_BASE_FILES} ${EXTRA_SOURCES})
ADD_EXECUTABLE(test_curve25519 test_curve25519.cc  ${EXTRA_SOURCES})

TARGET_INCLUDE_DIRECTORIES(test_curve25519 PRIVATE
	"${CMAKE_SOURCE_DIR}/include"
	"${CMAKE_SOURCE_DIR}/lib/include"
    "${CMAKE_CURRENT_SOURCE_DIR}/../include"
    "${CMAKE_CURRENT_SOURCE_DIR}/../common/include"
    ${EXTRA_INCLUDES})

TARGET_COMPILE_OPTIONS(test_curve25519 PUBLIC ${ALCP_WARNINGS})
TARGET_LINK_LIBRARIES(test_curve25519 ${LIBS})

gtest_add_tests(TARGET test_curve25519)

#[[
IF(ENABLE_TESTS_OPENSSL_API)
    gtest_add_tests(TARGET test_ecdh_cross)
ENDIF(ENABLE_TESTS_OPENSSL_API)
]]