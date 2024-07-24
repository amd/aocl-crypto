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

INCLUDE(${CMAKE_SOURCE_DIR}/cmake/AlcpFuzzTests.cmake)

ADD_FUZZ_TARGET(test_fuzz_rsa_encrypt_nopadding.cc)
ADD_FUZZ_TARGET(test_fuzz_rsa_decrypt_nopadding.cc)

ADD_FUZZ_TARGET(test_fuzz_rsa_encrypt_oaep.cc)
ADD_FUZZ_TARGET(test_fuzz_rsa_decrypt_oaep.cc)

ADD_FUZZ_TARGET(test_fuzz_rsa_sign_pkcs.cc)
ADD_FUZZ_TARGET(test_fuzz_rsa_sign_pss.cc)

ADD_FUZZ_TARGET(test_fuzz_rsa_verify_pkcs.cc)
ADD_FUZZ_TARGET(test_fuzz_rsa_verify_pss.cc)

ADD_FUZZ_TARGET(test_fuzz_rsa_encrypt_nopadding_lifecycle.cc)
ADD_FUZZ_TARGET(test_fuzz_rsa_decrypt_nopadding_lifecycle.cc)

ADD_FUZZ_TARGET(test_fuzz_rsa_encrypt_oaep_lifecycle.cc)
ADD_FUZZ_TARGET(test_fuzz_rsa_decrypt_oaep_lifecycle.cc)

ADD_FUZZ_TARGET(test_fuzz_rsa_sign_pkcs_lifecycle.cc)
ADD_FUZZ_TARGET(test_fuzz_rsa_sign_pss_lifecycle.cc)

ADD_FUZZ_TARGET(test_fuzz_rsa_verify_pkcs_lifecycle.cc)
ADD_FUZZ_TARGET(test_fuzz_rsa_verify_pss_lifecycle.cc)

ADD_FUZZ_TARGET(test_fuzz_rsa_encrypt_pkcs.cc)
ADD_FUZZ_TARGET(test_fuzz_rsa_decrypt_pkcs.cc)

ADD_FUZZ_TARGET(test_fuzz_rsa_digest_sign_pkcs.cc)



