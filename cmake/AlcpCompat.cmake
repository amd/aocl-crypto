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

# check compat lib compilation options
FUNCTION(alcp_check_compat_option)
    # check if valid option passed
	if(NOT("${AOCL_COMPAT_LIBS}" STREQUAL "openssl"
		OR "${AOCL_COMPAT_LIBS}" STREQUAL "ipp"
		OR "${AOCL_COMPAT_LIBS}" STREQUAL "openssl,ipp"
		OR "${AOCL_COMPAT_LIBS}" STREQUAL "ipp,openssl"))
		message(FATAL_ERROR "Invalid option: Supported options are: openssl/ipp/openssl,ipp")
	endif()
	# Make comma seperated values (CSV), semicolen seperated values (SSV)
	STRING (REPLACE "," ";" AOCL_COMPAT_LIBS ${AOCL_COMPAT_LIBS})
	# Iterate through each value as it is a proper list
	FOREACH ( value ${AOCL_COMPAT_LIBS} )
		# Compare the value to openssl
		string(COMPARE EQUAL "${value}" "openssl" result)
		IF (result)
			# If comparision true then enable openssl-compat
			SET(ENABLE_OPENSSL_COMPAT TRUE PARENT_SCOPE)
			MESSAGE("-- Enabled OpenSSL Compatibility SHIM Layer")
		ENDIF()
		# Compare the value to ipp
		string(COMPARE EQUAL "${value}" "ipp" result)
		IF (result)
			# If comparision true then enable ipp-compat
			SET(ENABLE_IPP_COMPAT TRUE PARENT_SCOPE)
			MESSAGE("-- Enabled IPP Compatibility SHIM Layer")
		ENDIF(result)
	ENDFOREACH(value ${AOCL_COMPAT_LIBS})
ENDFUNCTION(alcp_check_compat_option)