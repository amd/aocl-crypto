# Copyright (C) 2024, Advanced Micro Devices. All rights reserved.
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

SET(LIBS ${LIBS} alcp)

SET (ALCP_FUZZ_WARNINGS -Wall -Werror)
SET (ALCP_FUZZ_CFLAGS -g -O1 -fsanitize=fuzzer,address)
SET (ALCP_FUZZ_LINK_FLAGS -fsanitize=fuzzer,address)

SET(ALC_FUZZER_INCLUDES "${CMAKE_SOURCE_DIR}/tests/Fuzz/include"
    "${ALCP_INCLUDES}")

# common sources
file(GLOB ALCP_FUZZ_SRC_COMMON ${CMAKE_SOURCE_DIR}/tests/Fuzz/Common/*.cc)

FUNCTION(ADD_FUZZ_TARGET FUZZ_TARGET FUZZ_TARGET_SRC)
    message(STATUS "Creating Fuzz target: ${FUZZ_TARGET}")
    ADD_EXECUTABLE(${FUZZ_TARGET} ${FUZZ_TARGET_SRC} ${ALCP_FUZZ_SRC_COMMON})
    TARGET_INCLUDE_DIRECTORIES(${FUZZ_TARGET} PRIVATE ${ALC_FUZZER_INCLUDES})
    TARGET_COMPILE_OPTIONS(${FUZZ_TARGET} PUBLIC ${ALCP_FUZZ_CFLAGS} ${ALCP_FUZZ_WARNINGS})
    TARGET_LINK_OPTIONS(${FUZZ_TARGET} PUBLIC ${ALCP_FUZZ_LINK_FLAGS})
    TARGET_LINK_LIBRARIES(${FUZZ_TARGET} ${LIBS})
ENDFUNCTION()