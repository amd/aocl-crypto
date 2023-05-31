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
 

SET(UTILS_SRCS
  bignum.cc
  logger.cc
  #mempool.cc
  console_logger.cc
  cpuid.cc
  )

IF (ALCP_ENABLE_TESTS)
  ADD_SUBDIRECTORY(tests)
ENDIF()

TARGET_SOURCES(alcp
	PRIVATE
		${UTILS_SRCS}
	)

TARGET_SOURCES(alcp_static
	PRIVATE
		${UTILS_SRCS}
	)

IF(UNIX)
  IF(EXISTS ${OPENSSL_INSTALL_DIR}/lib64/libcrypto.so)
    TARGET_LINK_LIBRARIES(alcp PUBLIC ${OPENSSL_INSTALL_DIR}/lib64/libcrypto.so)
    TARGET_LINK_LIBRARIES(alcp_static PUBLIC ${OPENSSL_INSTALL_DIR}/lib64/libcrypto.so)
  ELSEIF(EXISTS ${OPENSSL_INSTALL_DIR}/lib/libcrypto.so)
    TARGET_LINK_LIBRARIES(alcp PUBLIC ${OPENSSL_INSTALL_DIR}/lib/libcrypto.so)
    TARGET_LINK_LIBRARIES(alcp_static PUBLIC ${OPENSSL_INSTALL_DIR}/lib/libcrypto.so)
  ELSEIF(EXISTS ${OPENSSL_INSTALL_DIR}/lib/x86_64-linux-gnu/libcrypto.so)
    TARGET_LINK_LIBRARIES(alcp PUBLIC ${OPENSSL_INSTALL_DIR}/lib/x86_64-linux-gnu/libcrypto.so)
    TARGET_LINK_LIBRARIES(alcp_static PUBLIC ${OPENSSL_INSTALL_DIR}/lib/x86_64-linux-gnu/libcrypto.so)
  ELSE()
    TARGET_LINK_LIBRARIES(alcp PUBLIC ${OPENSSL_INSTALL_DIR}/x86_64-linux-gnu/libcrypto.so)
    TARGET_LINK_LIBRARIES(alcp_static PUBLIC ${OPENSSL_INSTALL_DIR}/x86_64-linux-gnu/libcrypto.so)
  ENDIF()
ENDIF(UNIX)


