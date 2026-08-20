# Copyright (C) 2023-2025, Advanced Micro Devices. All rights reserved.
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

find_package(Threads REQUIRED)
FUNCTION(ADD_EXAMPLE EXAMPLE_SOURCE)
    # Dynamic Example
    # FIXME: to suppress false warnings from gcc (known issue, re-check with newer gcc versions)
    if(CMAKE_COMPILER_IS_GCC)
        set (ALCP_WARNINGS ${ALCP_WARNINGS} -Wno-format-overflow)
    endif()

    # generate target with the source file name
    if(EXAMPLE_SOURCE MATCHES "\\.cc$")
        string(REGEX REPLACE "\\.cc$" "_cpp"  EXAMPLE_TARGET "${EXAMPLE_SOURCE}")
    elseif(EXAMPLE_SOURCE MATCHES "\\.c$")
        string(REGEX REPLACE "\\.c$" ""  EXAMPLE_TARGET "${EXAMPLE_SOURCE}")
    else()
        set(EXAMPLE_TARGET "${EXAMPLE_SOURCE}")
    endif()

    # Dynamic example -- only built when the shared lib is built. Skipping
    # avoids dragging the SHARED alcp target into the build.
    IF(ALCP_BUILD_SHARED)
        add_executable(${EXAMPLE_TARGET} ${EXAMPLE_SOURCE})
        target_compile_options(${EXAMPLE_TARGET} PUBLIC ${ALCP_WARNINGS})
        target_link_libraries(${EXAMPLE_TARGET} PRIVATE alcp)
    ENDIF()

    # Static Example -- only built when the static lib is built.
    IF(ALCP_BUILD_STATIC)
        add_executable(${EXAMPLE_TARGET}-static ${EXAMPLE_SOURCE})
        target_link_libraries(${EXAMPLE_TARGET}-static PRIVATE alcp_static Threads::Threads)
    ENDIF()
ENDFUNCTION()
