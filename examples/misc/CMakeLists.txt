 # Copyright (C) 2022-2026, Advanced Micro Devices. All rights reserved.
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
 

ADD_EXAMPLE(cpuid.cc)
# cpuid example directly uses Au::X86Cpu for microarchitecture detection. The
# cpuid module is compiled into the main aocl-utils library (au_cpuid is a
# strict subset of aoclutils), so link the single aoclutils binary here -- the
# same one alcp links -- instead of a separate au_cpuid dependency. Library
# file names (AU_*_LIBNAME) are defined once in AoclUtils.cmake and already
# carry the Debug "-dbg" suffix when needed.
IF(ENABLE_AOCL_UTILS AND AOCL_UTILS_INSTALL_DIR)
    IF(MSVC)
        SET(_AU_UTILS_DYN ${AOCL_UTILS_INSTALL_DIR}/lib/${AU_UTILS_IMPORT_LIBNAME})
        # Shared ALCP is /MD: link the -static example via the aoclutils DLL
        # import (CRT-isolated), not the static archive.
        IF(ALCP_BUILD_SHARED)
            SET(_AU_UTILS_STA ${AOCL_UTILS_INSTALL_DIR}/lib/${AU_UTILS_IMPORT_LIBNAME})
        ELSE()
            SET(_AU_UTILS_STA ${AOCL_UTILS_INSTALL_DIR}/lib/${AU_UTILS_STATIC_WINLIB})
        ENDIF()
    ELSE()
        SET(_AU_UTILS_DYN ${AOCL_UTILS_INSTALL_DIR}/${CMAKE_INSTALL_LIBDIR}/${AU_UTILS_SHARED_LIBNAME})
        SET(_AU_UTILS_STA ${AOCL_UTILS_INSTALL_DIR}/${CMAKE_INSTALL_LIBDIR}/${AU_UTILS_STATIC_LIBNAME})
    ENDIF()
    IF(ALCP_BUILD_SHARED)
        target_link_libraries(cpuid_cpp PRIVATE ${_AU_UTILS_DYN})
    ENDIF()
    IF(ALCP_BUILD_STATIC)
        target_link_libraries(cpuid_cpp-static PRIVATE ${_AU_UTILS_STA})
    ENDIF()
ENDIF()
ADD_EXAMPLE(filecrypt.cc)
