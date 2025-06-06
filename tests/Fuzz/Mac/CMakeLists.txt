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

ADD_FUZZ_TARGET(test_fuzz_hmac_sha2_224.cc)
ADD_FUZZ_TARGET(test_fuzz_hmac_sha2_256.cc)
ADD_FUZZ_TARGET(test_fuzz_hmac_sha2_384.cc)
ADD_FUZZ_TARGET(test_fuzz_hmac_sha2_512.cc)
ADD_FUZZ_TARGET(test_fuzz_hmac_sha3_224.cc)
ADD_FUZZ_TARGET(test_fuzz_hmac_sha3_256.cc)
ADD_FUZZ_TARGET(test_fuzz_hmac_sha3_384.cc)
ADD_FUZZ_TARGET(test_fuzz_hmac_sha3_512.cc)

ADD_FUZZ_TARGET(test_fuzz_hmac_sha2_512_224.cc)
ADD_FUZZ_TARGET(test_fuzz_hmac_sha2_512_256.cc)

ADD_FUZZ_TARGET(test_fuzz_poly1305.cc)
ADD_FUZZ_TARGET(test_fuzz_cmac.cc)

ADD_FUZZ_TARGET(test_fuzz_hmac_sha2_224_lifecycle.cc)
ADD_FUZZ_TARGET(test_fuzz_hmac_sha2_256_lifecycle.cc)
ADD_FUZZ_TARGET(test_fuzz_hmac_sha2_384_lifecycle.cc)
ADD_FUZZ_TARGET(test_fuzz_hmac_sha2_512_lifecycle.cc)
ADD_FUZZ_TARGET(test_fuzz_hmac_sha3_224_lifecycle.cc)
ADD_FUZZ_TARGET(test_fuzz_hmac_sha3_256_lifecycle.cc)
ADD_FUZZ_TARGET(test_fuzz_hmac_sha3_384_lifecycle.cc)
ADD_FUZZ_TARGET(test_fuzz_hmac_sha3_512_lifecycle.cc)

ADD_FUZZ_TARGET(test_fuzz_hmac_sha2_512_224_lifecycle.cc)
ADD_FUZZ_TARGET(test_fuzz_hmac_sha2_512_256_lifecycle.cc)

ADD_FUZZ_TARGET(test_fuzz_poly1305_lifecycle.cc)
ADD_FUZZ_TARGET(test_fuzz_cmac_lifecycle.cc)

