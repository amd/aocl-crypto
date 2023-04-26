 # Copyright (C) 2022-2023, Advanced Micro Devices. All rights reserved.
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
 
FILE(GLOB COMPAT_SRCS "*.cc")

SET(COMPAT_SRCS ${COMPAT_SRCS} PARENT_SCOPE)

# TODO: Move below detection code to something global
# So that there will not be a need to parse it multiple times
SET(ENABLE_OPENSSL_COMPAT FALSE)
SET(ENABLE_IPP_COMPAT FALSE)

IF (AOCL_COMPAT_LIBS)
	# Make comma seperated values (CSV), semicolen seperated values (SSV)
	STRING (REPLACE "," ";" AOCL_COMPAT_LIBS ${AOCL_COMPAT_LIBS})
	# Iterate through each value as it is a proper list
	FOREACH ( value ${AOCL_COMPAT_LIBS} )
		# Compare the value to openssl
		string(COMPARE EQUAL "${value}" "openssl" result)
		IF (result)
			# If comparision true then enable openssl-compat
			SET(ENABLE_OPENSSL_COMPAT TRUE)
			MESSAGE("-- Enabled OpenSSL Compatibility SHIM Layer")
		ENDIF()
		# Compare the value to ipp
		string(COMPARE EQUAL "${value}" "ipp" result)
		IF (result)
			# If comparision true then enable ipp-compat
			SET(ENABLE_IPP_COMPAT TRUE)
			MESSAGE("-- Enabled IPP Compatibility SHIM Layer")
		ENDIF(result)
	ENDFOREACH(value ${AOCL_COMPAT_LIBS})
ENDIF(AOCL_COMPAT_LIBS)

IF (ENABLE_OPENSSL_COMPAT)
    # Adding openssl-compat as a seperate liberary
    ADD_SUBDIRECTORY(openssl)
ENDIF (ENABLE_OPENSSL_COMPAT)

IF (ENABLE_IPP_COMPAT)
	# Adding ipp-compat as a seperate liberary
	ADD_SUBDIRECTORY(ipp)
ENDIF (ENABLE_IPP_COMPAT)

