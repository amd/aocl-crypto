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
 
Include(${CMAKE_SOURCE_DIR}/cmake/AlcpTests.cmake)

# Enforcing File Name
set(TEST_FILES
  bignum_test.cc
  copy_test.cc
  )

# FIXME this unit test is failing with aocc, disabled for now
if (CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
	list(FILTER TEST_FILES EXCLUDE REGEX "array_view_test.cc")
ENDIF()

alcp_module("Utils")

#message(STATUS "Cipher Unit Tests Imported ${TEST_FILES}")

foreach(testFile IN LISTS TEST_FILES)
    get_filename_component(currentTestName ${testFile} NAME_WLE)
    get_filename_component(currentTestFile ${testFile} NAME)
    message("Test-> " ${currentTestName} " file " ${currentTestFile} )
    alcp_cc_test(${currentTestName} ${CMAKE_BINARY_DIR}/lib/utils/tests
             DIRECTORY tests/
             SOURCES   "${currentTestFile}"
             DEPENDS   ${_module_lib}
    )
endforeach()

