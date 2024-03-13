# Copyright (C) 2022-2024, Advanced Micro Devices. All rights reserved.
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

include(CMakeParseArguments)
include(GoogleTest)

macro(alcp_module NAME)
    set(ALCP_MODULE ${NAME})
endmacro()

# Declare a test using googletest.
#
# Parameters:
#   NAME           name of the test.
#   SOURCES        list of test source files, headers included.
#   HEADERS        list of headers to depend on
#   DEPENDS        list of dependencies
#   CONTENTS       list of non-code dependencies, such as test vectors.
#
# Attributes:
#   BROKEN            Known to fail
#   SKIP              Dont add to targets
#   HANGING           Test might hang(such as looking for Entropy)
#   WINDOWS_DISABLED  Dont run on Windows (Why ? you'll know)
#
# Tests added with this macro are automatically registered.
# Each test produces a build target named alcp_test_<MODULE>_<NAME>.
#
#
#   alcp_cc_test(
#     DIRECTORY test/
#       TEST BufferTest WINDOWS_DISABLED
#         SOURCES BufferTest.cc
#         HEADERS BufferTest.hh
#         CONTENTS data/
#   )

function(alcp_cc_test testName working_dir)
    if(NOT ALCP_ENABLE_TESTS)
        return()
    endif()

    if (NOT DEFINED ALCP_MODULE)
        message(FATAL_ERROR "alcp module name not defined")
    endif()

    # We replace :: with __ in targets, because :: may not appear in target names.
    # However, the module name should still span multiple name spaces.
    STRING(REPLACE "::" "__" _ESCAPED_ALCP_MODULE ${ALCP_MODULE})
  
    set(testPrefix test)
    set(options BROKEN SKIP WINDOWS_DISABLED)
    set(oneValueArgs CONTENTS DIRECTORY)
    set(multiValueArgs SOURCES HEADERS DEPENDS)
    cmake_parse_arguments(PARSE_ARGV 0 
      ${testPrefix}
      "${options}"
      "${oneValueArgs}"
      "${multiValueArgs}"
    )

    set(_target_name "${_ESCAPED_ALCP_MODULE}_${testName}")
  
    if(${${testPrefix}_SKIP} OR ${${testPrefix}_BROKEN} )
        message("Test : " ${testName} "[SKIPPED]")
        return()
    endif()
  
    if(${${testPrefix}_WINDOWS_DISABLED} AND WIN32)
        message("Test : " ${testName} "[WIN32-DISABLED]")
        return()
    endif()

    if(${${testPrefix}_SLOW})
        if(STREQUAL "${alcp_ENABLE_SLOW_TESTS}" "OFF" )
            message("Test : " ${testName} "[SKIPPED] SLOW")
            return()
        endif()
    endif()

    file(GLOB TEST_COMMON_SRC ${CMAKE_SOURCE_DIR}/tests/common/base/*.cc)

    if(${ALCP_MODULE} STREQUAL "Cipher")
        SET(TEST_COMMON_SRC ${TEST_COMMON_SRC}
                            ${CMAKE_SOURCE_DIR}/tests/cipher/base/alc_cipher.cc
                            ${CMAKE_SOURCE_DIR}/tests/cipher/base/alc_cipher_aead.cc
                            ${CMAKE_SOURCE_DIR}/tests/cipher/base/cipher.cc
                            ${UNIT_TEST_COMMON_SRCS}
        )
    endif()

    if(WIN32)
  	    add_compile_options(-Wno-missing-field-initializers)
    endif()

    include_directories(${CMAKE_CURRENT_SOURCE_DIR})
    add_executable(${_target_name}
        ${${testPrefix}_SOURCES}
        ${TEST_COMMON_SRC}
    )

    target_link_libraries(${_target_name}
        gtest_main
        gmock_main
        alcp
        ${${testPrefix}_DEPENDS}
    )

    # FIXME: Remove this and replace with equavalent files outside the integration testing area.
    target_include_directories(${_target_name} PRIVATE ${CMAKE_SOURCE_DIR}/tests/include)
    target_include_directories(${_target_name} PRIVATE ${CMAKE_SOURCE_DIR}/tests/common/include)
    target_include_directories(${_target_name} PRIVATE ${CMAKE_SOURCE_DIR}/lib/include)
    target_include_directories(${_target_name} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/common/include)

    add_test(${_target_name}, ${working_dir}/${_target_name})
    # Add valgrind test based on the cmake option
    IF(ALCP_MEMCHECK_VALGRIND)
        Include(${CMAKE_SOURCE_DIR}/cmake/AlcpTestUtils.cmake)
        alcp_add_valgrind_check_test(${_target_name}_valgrind ${working_dir}/${_target_name})
    ENDIF(ALCP_MEMCHECK_VALGRIND)
endfunction(alcp_cc_test)
