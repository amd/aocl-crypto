# Copyright (C) 2023-2026, Advanced Micro Devices. All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
# 1. Redistributions of source code must retain the above copyright notice,
#    this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
# 3. Neither the name of the copyright holder nor the names of its contributors
#    may be used to endorse or promote products derived from this software
# without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

INCLUDE(FetchContent)
INCLUDE(GoogleTest)
FetchContent_Declare(gtest
    GIT_REPOSITORY https://github.com/google/googletest.git
    GIT_TAG release-1.12.1)
FetchContent_MakeAvailable(gtest)

if(WIN32)
    foreach(_t gtest gtest_main gmock gmock_main)
        if(TARGET ${_t})
            target_compile_options(${_t} PRIVATE -w)
        endif()
    endforeach()
endif()

find_package(Threads)

# KAT test data files are tracked by git-lfs.  Detect files that are absent
# or still LFS pointer stubs (e.g. when cloning without git-lfs installed or
# when the source was obtained as a zip archive without a .git directory).
# Discover all test_data sub-directories under tests/ that carry a
# .gitattributes file marking *.csv as LFS objects.
file(GLOB _LFS_TEST_DATA_DIRS
     LIST_DIRECTORIES true
     "${CMAKE_SOURCE_DIR}/tests/*/test_data")
set(_LFS_PROBLEM_FILES "")
foreach(_lfs_dir ${_LFS_TEST_DATA_DIRS})
    if(NOT IS_DIRECTORY "${_lfs_dir}")
        continue()
    endif()
    if(NOT EXISTS "${_lfs_dir}/.gitattributes")
        continue()
    endif()
    file(GLOB _lfs_csvs "${_lfs_dir}/*.csv")
    if(NOT _lfs_csvs)
        list(APPEND _LFS_PROBLEM_FILES "${_lfs_dir}/*.csv  <-- directory has no CSV files>")
    else()
        foreach(_lfs_csv ${_lfs_csvs})
            file(READ "${_lfs_csv}" _lfs_header LIMIT 64)
            if("${_lfs_header}" MATCHES "version https://git-lfs\\.github\\.com")
                list(APPEND _LFS_PROBLEM_FILES "${_lfs_csv}  <-- git-lfs pointer stub>")
            endif()
        endforeach()
    endif()
endforeach()
unset(_lfs_dir)
unset(_lfs_csvs)
unset(_lfs_csv)
unset(_lfs_header)
unset(_LFS_TEST_DATA_DIRS)
if(_LFS_PROBLEM_FILES)
    string(REPLACE ";" "\n    " _LFS_PROBLEM_LIST "${_LFS_PROBLEM_FILES}")
    message(WARNING
        "One or more KAT test data files are missing or are git-lfs pointer stubs:\n\n"
        "    ${_LFS_PROBLEM_LIST}\n"
        "\nThese CSV files are managed by git-lfs and must be fetched separately.\n"
        "To resolve:\n"
        "  1. Install git-lfs from https://git-lfs.github.com\n"
        "  2. Run the following from the repository root:\n"
        "         git lfs install\n"
        "         git lfs pull\n"
        "  Or, if cloning fresh, install git-lfs first and then clone:\n"
        "         git lfs install\n"
        "         git clone <repo-url>\n"
        "KAT tests that depend on missing data files will fail at runtime.")
else()
    message(STATUS "KAT test data: all LFS-tracked CSV files are present and valid.")
endif()
unset(_LFS_PROBLEM_FILES)
unset(_LFS_PROBLEM_LIST)

FILE(GLOB COMMON_SRCS ${CMAKE_SOURCE_DIR}/tests/common/base/*.cc)

IF(ALCP_BUILD_SHARED)
    SET(LIBS ${LIBS} gtest alcp)
ELSE()
    SET(LIBS ${LIBS} gtest alcp_static)
ENDIF()

# as per discussion: https://discourse.cmake.org/t/target-link-libraries-for-lpthread-ldl-and-lutils/1235/3
IF(Threads_FOUND AND UNIX)
    SET(LIBS ${LIBS} pthread)
ENDIF()

SET(ALCP_TEST_INCLUDES "${CMAKE_SOURCE_DIR}/include"
                       "${CMAKE_SOURCE_DIR}/lib/include"
                       "${CMAKE_SOURCE_DIR}/tests/include"
                       "${CMAKE_SOURCE_DIR}/tests/common/include"
    )

IF (POLICY CMP0079) # Visibility
  cmake_policy(SET CMP0079 NEW)
ENDIF (POLICY CMP0079)

IF(WIN32)
target_link_libraries(gmock PUBLIC gtest)
target_link_libraries(gmock_main PUBLIC gtest_main)
set(CMAKE_GTEST_DISCOVER_TESTS_DISCOVERY_MODE PRE_TEST)
ENDIF()

function(add_openssl)
    IF(ENABLE_TESTS_OPENSSL_API)
    ADD_COMPILE_OPTIONS("-DUSE_OSSL")

    IF(OPENSSL_INSTALL_DIR)
        MESSAGE(STATUS "OPENSSL_INSTALL_DIR set, overriding fetch path")
    ELSE(OPENSSL_INSTALL_DIR)
        SET(OPENSSL_INSTALL_DIR "${CMAKE_SOURCE_DIR}/external")
        MESSAGE(STATUS "OPENSSL_INSTALL_DIR not set, defaulting to external")
    ENDIF(OPENSSL_INSTALL_DIR)

    # If there is OpenSSL, add OpenSSL source and add OpenSSL liberary
    SET(OPENSSL_SOURCES ${OPENSSL_CIPHER_FWK_SRCS} PARENT_SCOPE)
    IF(UNIX)
        IF(EXISTS ${OPENSSL_INSTALL_DIR}/lib64/libcrypto.so)
            INCLUDE_DIRECTORIES(${OPENSSL_INSTALL_DIR}/include)
            SET(OPENSSL_LIBS ${OPENSSL_LIBS} ${OPENSSL_INSTALL_DIR}/lib64/libcrypto.so)
        ELSEIF(EXISTS ${OPENSSL_INSTALL_DIR}/lib/libcrypto.so)
            SET(OPENSSL_LIBS ${OPENSSL_LIBS} ${OPENSSL_INSTALL_DIR}/lib/libcrypto.so)
        ELSE()
            SET(OPENSSL_LIBS ${OPENSSL_LIBS} ${OPENSSL_INSTALL_DIR}/lib/x86_64-linux-gnu/libcrypto.so)
        ENDIF()
    ENDIF(UNIX)
    IF(WIN32)
        IF(EXISTS ${OPENSSL_INSTALL_DIR}/lib/libcrypto.lib)
            INCLUDE_DIRECTORIES(${OPENSSL_INSTALL_DIR}/include)
            INCLUDE_DIRECTORIES(${OPENSSL_INSTALL_DIR}/bin)
            SET(OPENSSL_LIBS ${OPENSSL_LIBS} ${OPENSSL_INSTALL_DIR}/lib/libcrypto.lib)
            ADD_COMPILE_OPTIONS(-Wno-microsoft-cast -Wno-deprecated-declarations)
        ENDIF()
    ENDIF(WIN32)
    SET(OPENSSL_INCLUDES ${OPENSSL_INSTALL_DIR}/include PARENT_SCOPE)
    SET(OPENSSL_LIBS ${OPENSSL_LIBS} PARENT_SCOPE)
    ENDIF(ENABLE_TESTS_OPENSSL_API)
endfunction(add_openssl)

function(add_ipp)
    IF(ENABLE_TESTS_IPP_API)
        ADD_COMPILE_OPTIONS("-DUSE_IPP")

        IF(IPP_INSTALL_DIR)
            MESSAGE(STATUS "IPP_INSTALL_DIR set, overriding fetch path")
        ELSE(IPP_INSTALL_DIR)
            SET(IPP_INSTALL_DIR "${CMAKE_SOURCE_DIR}/external")
            MESSAGE(STATUS "IPP_INSTALL_DIR not set, defaulting to external")
        ENDIF(IPP_INSTALL_DIR)

        # If there is IPP, add IPP source and add IPP liberary
        SET(IPP_SOURCES ${IPP_CIPHER_FWK_SRCS} PARENT_SCOPE)
        IF(UNIX)
            IF(EXISTS ${IPP_INSTALL_DIR}/lib/intel64/libippcp.so)
                SET(IPP_LIBS ${IPP_LIBS} ${IPP_INSTALL_DIR}/lib/intel64/libippcp.so)
            ELSE(EXISTS ${IPP_INSTALL_DIR}/lib/intel/libippcp.so)
                SET(IPP_LIBS ${IPP_LIBS} ${IPP_INSTALL_DIR}/lib/intel/libippcp.so)
            ENDIF(EXISTS ${IPP_INSTALL_DIR}/lib/intel64/libippcp.so)
        ENDIF(UNIX)
        IF(WIN32)
        IF(EXISTS ${IPP_INSTALL_DIR}/lib/intel64/ippcp.lib)
            set(IPP_LIBS ${IPP_LIBS} ${IPP_INSTALL_DIR}/lib/intel64/ippcp.lib)
        ELSEIF(EXISTS ${IPP_INSTALL_DIR}/lib/intel/ippcp.lib)
            set(IPP_LIBS ${IPP_LIBS} ${IPP_INSTALL_DIR}/lib/intel/ippcp.lib)
        ELSE(EXISTS ${IPP_INSTALL_DIR}/lib/ippcp.lib)
            set(IPP_LIBS ${IPP_LIBS} ${IPP_INSTALL_DIR}/lib/ippcp.lib)
        ENDIF()
        ENDIF(WIN32)
        SET(IPP_INCLUDES ${IPP_INSTALL_DIR}/include PARENT_SCOPE)
        SET(IPP_LIBS ${IPP_LIBS} PARENT_SCOPE)
    ENDIF(ENABLE_TESTS_IPP_API)
endfunction(add_ipp)

# Function to dynamically generate compilation of each test cases
FUNCTION(AES_TEST TYPE MOD)
    ADD_EXECUTABLE(aes_${MOD}_experimental_${TYPE} test_${MOD}_${TYPE}.cc 
                                                   ${COMMON_SRCS} 
                                                   ${ALC_CIPHER_FWK_SRCS} 
                                                   ${EXTRA_SOURCES} 
                                                   ${OPENSSL_SOURCES}
                                                   ${IPP_SOURCES})
    # Below code must be enabled once we merge completely
    # Depending on the person, they are gonna run from root dir or binary directory
    # Link dataset to the root dir
    # LINK_IF_EXISTS(${CMAKE_CURRENT_SOURCE_DIR}/dataset/dataset_${MOD}.csv ${CMAKE_BINARY_DIR}/dataset_${MOD}.csv SYMBOLIC)

    # Link dataset to the actual place of test binary
    # LINK_IF_EXISTS(${CMAKE_CURRENT_SOURCE_DIR}/dataset/dataset_${MOD}.csv ${CMAKE_CURRENT_BINARY_DIR}/dataset_${MOD}.csv SYMBOLIC)

    TARGET_INCLUDE_DIRECTORIES(aes_${MOD}_experimental_${TYPE} PRIVATE
        ${ALCP_TEST_INCLUDES}
        ${OPENSSL_INCLUDES}
        ${IPP_INCLUDES})

    TARGET_COMPILE_OPTIONS(aes_${MOD}_experimental_${TYPE} PUBLIC ${ALCP_WARNINGS})
    TARGET_LINK_LIBRARIES(aes_${MOD}_experimental_${TYPE} ${LIBS} 
                                                      ${OPENSSL_LIBS} 
                                                      ${IPP_LIBS})
    gtest_discover_tests(aes_${MOD}_experimental_${TYPE} NO_PRETTY_VALUES NO_PRETTY_TYPES
        PROPERTIES LABELS "cipher")
ENDFUNCTION()

FUNCTION(LINK_IF_EXISTS SOURCE DESTINATION LINK_TYPE)
    # Check if the source file exists
    if(EXISTS ${SOURCE})
        # Create a symbolic link if the source file exists
        # COPY_ON_ERROR: fall back to copying on Windows when symlink privileges are missing
        FILE(CREATE_LINK ${SOURCE} ${DESTINATION} ${LINK_TYPE} COPY_ON_ERROR)
    else()
        string(TOUPPER "${CMAKE_BUILD_TYPE}" BUILD_TYPE_UPPER)
        if("${BUILD_TYPE_UPPER}" STREQUAL "DEBUG")
            message(WARNING "Link Helper failed, no such file as ${SOURCE}")
        endif("${BUILD_TYPE_UPPER}" STREQUAL "DEBUG")
    endif()
ENDFUNCTION(LINK_IF_EXISTS SOURCE DESTINATION)
