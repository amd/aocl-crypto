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

#################### Reasons for disabling some providers ##############################
# 1. AES-CBC Disabled due to failures in copy                                         ##
# 2. AES-CCM Disabled due to performance limitations                                  ##
# 3. HMAC Provider disabled due to digests performance limitations                    ##
# 4. Digest Provider is disabled by default as there is currently a provider overhead ##
########################################################################################


OPTION(ALCP_COMPAT_ENABLE_OPENSSL_DIGEST "ENABLE SUPPORT FOR OPENSSL DIGEST PROVIDER" OFF)
OPTION(ALCP_COMPAT_ENABLE_OPENSSL_CIPHER "ENABLE SUPPORT FOR OPENSSL CIPHER PROVIDER" ON)
OPTION(ALCP_COMPAT_ENABLE_OPENSSL_RSA    "ENABLE SUPPORT FOR OPENSSL RSA PROVIDER" ON)
OPTION(ALCP_COMPAT_ENABLE_OPENSSL_MAC    "ENABLE SUPPORT FOR OPENSSL MAC PROVIDER" ON)

# Sub options for DIGEST
OPTION(ALCP_COMPAT_ENABLE_OPENSSL_DIGEST_SHA2  "ENABLE SUPPORT FOR OPENSSL DIGEST-SHA2 PROVIDER" ON)
OPTION(ALCP_COMPAT_ENABLE_OPENSSL_DIGEST_SHA3  "ENABLE SUPPORT FOR OPENSSL DIGEST-SHA2 PROVIDER" ON)
OPTION(ALCP_COMPAT_ENABLE_OPENSSL_DIGEST_SHAKE "ENABLE SUPPORT FOR OPENSSL DIGEST-SHA2 PROVIDER" ON)
IF(NOT ALCP_COMPAT_ENABLE_OPENSSL_DIGEST)
    SET(ALCP_COMPAT_ENABLE_OPENSSL_DIGEST_SHA2 OFF)
    SET(ALCP_COMPAT_ENABLE_OPENSSL_DIGEST_SHA3 OFF)
    SET(ALCP_COMPAT_ENABLE_OPENSSL_DIGEST_SHAKE OFF)
ENDIF(NOT ALCP_COMPAT_ENABLE_OPENSSL_DIGEST)

# SUb options for CIPHER
OPTION(ALCP_COMPAT_ENABLE_OPENSSL_CIPHER_CBC "ENABLE SUPPORT FOR OPENSSL CIPHER-AES-CBC PROVIDER" OFF)
OPTION(ALCP_COMPAT_ENABLE_OPENSSL_CIPHER_OFB "ENABLE SUPPORT FOR OPENSSL CIPHER-AES-OFB PROVIDER" ON)
OPTION(ALCP_COMPAT_ENABLE_OPENSSL_CIPHER_CFB "ENABLE SUPPORT FOR OPENSSL CIPHER-AES-CFB PROVIDER" ON)
OPTION(ALCP_COMPAT_ENABLE_OPENSSL_CIPHER_CTR "ENABLE SUPPORT FOR OPENSSL CIPHER-AES-CTR PROVIDER" ON)
OPTION(ALCP_COMPAT_ENABLE_OPENSSL_CIPHER_XTS "ENABLE SUPPORT FOR OPENSSL CIPHER-AES-XTS PROVIDER" ON)
OPTION(ALCP_COMPAT_ENABLE_OPENSSL_CIPHER_GCM "ENABLE SUPPORT FOR OPENSSL CIPHER-AES-GCM PROVIDER" ON)
OPTION(ALCP_COMPAT_ENABLE_OPENSSL_CIPHER_CCM "ENABLE SUPPORT FOR OPENSSL CIPHER-AES-CCM PROVIDER" OFF)
OPTION(ALCP_COMPAT_ENABLE_OPENSSL_CIPHER_SIV "ENABLE SUPPORT FOR OPENSSL CIPHER-AES-SIV PROVIDER" ON)
IF(NOT ALCP_COMPAT_ENABLE_OPENSSL_CIPHER)
    SET(ALCP_COMPAT_ENABLE_OPENSSL_CIPHER_CBC OFF)
    SET(ALCP_COMPAT_ENABLE_OPENSSL_CIPHER_OFB OFF)
    SET(ALCP_COMPAT_ENABLE_OPENSSL_CIPHER_CFB OFF)
    SET(ALCP_COMPAT_ENABLE_OPENSSL_CIPHER_CTR OFF)
    SET(ALCP_COMPAT_ENABLE_OPENSSL_CIPHER_XTS OFF)
    SET(ALCP_COMPAT_ENABLE_OPENSSL_CIPHER_GCM OFF)
    SET(ALCP_COMPAT_ENABLE_OPENSSL_CIPHER_CCM OFF)
    SET(ALCP_COMPAT_ENABLE_OPENSSL_CIPHER_SIV OFF)
ENDIF(NOT ALCP_COMPAT_ENABLE_OPENSSL_CIPHER)

# Sub options for MAC
OPTION(ALCP_COMPAT_ENABLE_OPENSSL_MAC_HMAC     "ENABLE SUPPORT FOR OPENSSL MAC-HMAC PROVIDER" OFF)
OPTION(ALCP_COMPAT_ENABLE_OPENSSL_MAC_CMAC     "ENABLE SUPPORT FOR OPENSSL MAC-CMAC PROVIDER" ON)
OPTION(ALCP_COMPAT_ENABLE_OPENSSL_MAC_POLY1305 "ENABLE SUPPORT FOR OPENSSL MAC-CMAC PROVIDER" ON)
IF(NOT ALCP_COMPAT_ENABLE_OPENSSL_MAC)
    SET(ALCP_COMPAT_ENABLE_OPENSSL_MAC_HMAC OFF)
    SET(ALCP_COMPAT_ENABLE_OPENSSL_MAC_CMAC OFF)
    SET(ALCP_COMPAT_ENABLE_OPENSSL_MAC_POLY1305 OFF)
ENDIF(NOT ALCP_COMPAT_ENABLE_OPENSSL_MAC)

FUNCTION(GEN_PROV_CONF)

    IF(${CMAKE_SYSTEM_NAME} STREQUAL "Linux")
        SET(ALCP_BUILD_OS_LINUX ON)
        SET(ALCP_BUILD_OS_WINDOWS OFF)
    ELSE()
        SET(ALCP_BUILD_OS_LINUX OFF)
        SET(ALCP_BUILD_OS_WINDOWS ON)
    ENDIF(${CMAKE_SYSTEM_NAME} STREQUAL "Linux")

    IF(ALCP_BUILD_OS_LINUX)
        configure_file(${CMAKE_CURRENT_SOURCE_DIR}/include/provider/config.h.in ${CMAKE_CURRENT_SOURCE_DIR}/include/provider/config.h UNIX)
    ENDIF(ALCP_BUILD_OS_LINUX)
    IF(ALCP_BUILD_OS_WINDOWS)
        configure_file(${CMAKE_CURRENT_SOURCE_DIR}/include/provider/config.h.in ${CMAKE_CURRENT_SOURCE_DIR}/include/provider/config.h WIN32)
    ENDIF(ALCP_BUILD_OS_WINDOWS)

ENDFUNCTION(GEN_PROV_CONF)