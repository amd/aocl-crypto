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

# add_compile_options_config(<CONFIG> <option> ...)
FUNCTION(ADD_COMPILE_OPTIONS_CONFIG CONFIG)
	FOREACH(opt ${ARGN})
		ADD_COMPILE_OPTIONS("$<$<CONFIG:${CONFIG}>:${opt}>")
	ENDFOREACH()
ENDFUNCTION()


FUNCTION (INVERTBOOLEAN VARNAME VARVALUE)
  IF(${VARVALUE})
    SET(${VARNAME} OFF PARENT_SCOPE)
  ELSE()
    SET(${VARNAME} ON PARENT_SCOPE)
  ENDIF()
ENDFUNCTION()

# ---------------------------------------------------------------------------
# Helpers that forward a cmake command to both alcp (shared) and alcp_static
# (static) library targets, silently skipping whichever does not exist. This
# avoids repeating IF(TARGET alcp) / IF(TARGET alcp_static) guards in every
# sub-CMakeLists that contributes sources, link libraries, etc.
#
#   ALCP_TARGET_SOURCES(PRIVATE src1.cc src2.cc)
#   ALCP_TARGET_LINK_LIBRARIES(PRIVATE some_lib)
#   ALCP_TARGET_INCLUDE_DIRECTORIES(PRIVATE ${dir})
#   ALCP_TARGET_COMPILE_OPTIONS(PRIVATE -Wall)
#   ALCP_TARGET_COMPILE_DEFINITIONS(PRIVATE SOME_DEFINE)
# ---------------------------------------------------------------------------
FUNCTION(ALCP_TARGET_SOURCES)
    IF(TARGET alcp)
        TARGET_SOURCES(alcp ${ARGN})
    ENDIF()
    IF(TARGET alcp_static)
        TARGET_SOURCES(alcp_static ${ARGN})
    ENDIF()
ENDFUNCTION()

FUNCTION(ALCP_TARGET_LINK_LIBRARIES)
    IF(TARGET alcp)
        TARGET_LINK_LIBRARIES(alcp ${ARGN})
    ENDIF()
    IF(TARGET alcp_static)
        TARGET_LINK_LIBRARIES(alcp_static ${ARGN})
    ENDIF()
ENDFUNCTION()

FUNCTION(ALCP_TARGET_INCLUDE_DIRECTORIES)
    IF(TARGET alcp)
        TARGET_INCLUDE_DIRECTORIES(alcp ${ARGN})
    ENDIF()
    IF(TARGET alcp_static)
        TARGET_INCLUDE_DIRECTORIES(alcp_static ${ARGN})
    ENDIF()
ENDFUNCTION()

FUNCTION(ALCP_TARGET_COMPILE_OPTIONS)
    IF(TARGET alcp)
        TARGET_COMPILE_OPTIONS(alcp ${ARGN})
    ENDIF()
    IF(TARGET alcp_static)
        TARGET_COMPILE_OPTIONS(alcp_static ${ARGN})
    ENDIF()
ENDFUNCTION()

FUNCTION(ALCP_TARGET_COMPILE_DEFINITIONS)
    IF(TARGET alcp)
        TARGET_COMPILE_DEFINITIONS(alcp ${ARGN})
    ENDIF()
    IF(TARGET alcp_static)
        TARGET_COMPILE_DEFINITIONS(alcp_static ${ARGN})
    ENDIF()
ENDFUNCTION()
