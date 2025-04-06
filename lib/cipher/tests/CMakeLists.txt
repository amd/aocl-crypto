 # Copyright (C) 2022-2025, Advanced Micro Devices. All rights reserved.
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
file(GLOB TEST_FILES "*_unit_test.cc")
# You can rename files to another name and wont be included

alcp_module("Cipher")

file(GLOB UNIT_TEST_COMMON_SRCS "${CMAKE_CURRENT_SOURCE_DIR}/common/*.cc")

foreach(testFile IN LISTS TEST_FILES)
    get_filename_component(currentTestName ${testFile} NAME_WLE)
    get_filename_component(currentTestFile ${testFile} NAME)
    alcp_cc_test(${currentTestName} ${CMAKE_BINARY_DIR}/lib/cipher/tests
             DIRECTORY tests/
             SOURCES   "${currentTestFile}"
             DEPENDS   ${_module_lib}
    )
    
    IF(ALCP_ENABLE_CIPHER_MULTI_UPDATE)
        set_property(SOURCE ${currentTestFile} APPEND_STRING PROPERTY COMPILE_FLAGS " -DAES_MULTI_UPDATE")
    ENDIF(ALCP_ENABLE_CIPHER_MULTI_UPDATE)
    
    IF(ALCP_ENABLE_CBC_INPLACE_BUFFER)
        set_property(SOURCE ${currentTestFile} APPEND_STRING PROPERTY COMPILE_FLAGS " -DCBC_INPLACE_BUFFER")
    ENDIF(ALCP_ENABLE_CBC_INPLACE_BUFFER)
endforeach()


IF(ALCP_ENABLE_OFB_MULTI_UPDATE)
	SET_SOURCE_FILES_PROPERTIES(ofb_unit_test.cc PROPERTIES COMPILE_FLAGS "-DOFB_MULTI_UPDATE")
ENDIF(ALCP_ENABLE_OFB_MULTI_UPDATE)