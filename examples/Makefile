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

# Output directory
OBJ := bin

# link to static or shared lib
LIB_TYPE = dynamic #default value

INCLUDE_DIR := include

LIB_DIR := lib

CFLAGS := -I$(INCLUDE_DIR)

# if linking to shared lib
LFLAGS := -L $(LIB_DIR) -lalcp -laoclutils

# if linking to static lib
ifeq ($(LIB_TYPE), static)
    LFLAGS = -no-pie -L$(LIB_DIR) -L$(OPENSSL_INSTALL_DIR) -Wl,-Bstatic -l:libalcp.a -l:libaoclutils.a -lcrypto -Wl,-Bdynamic -lcrypto -lstdc++ -lpthread -ldl
endif

# Add more targets as they come.
TARGETS := cipher/aes-cfb cipher/aes-speed-cipher cipher/aes-speed-gcm cipher/aes-siv cipher/aes-xts cipher/aes-ccm cipher/aes-gcm \
			cipher/chacha20 cipher/chacha20-poly1305 \
			digest/sha2_224_example digest/sha2_256_example digest/sha2_384_example digest/sha2_512_example \
			digest/sha2_512_224_example digest/sha2_512_256_example \
			digest/sha3_224_example digest/sha3_256_example digest/sha3_384_example digest/sha3_512_example \
			digest/shake_128_example digest/shake_256_example \
			rng/rng-demo \
			rng/hmac_drbg-demo \
			rng/ctr_drbg-demo \
			rng/drbg-test \
			mac/hmac mac/cmac mac/poly1305 \
			ecdh/x25519_example ecdh/p256_example \
			rsa/rsa_peer rsa/rsa_encrypt rsa/rsa_decrypt rsa/rsa_2048 rsa/rsa_oaep_2048 rsa/rsa_oaep \
			rsa/rsa_pkcs1-v1_5_sign_verify rsa/rsa_pss_sign_verify rsa/rsa_padding_big_num_keys \
			version/version-demo

define MULTILINE_PYTHON_SCRIPT
from packaging.version import Version
import os
import re
output = os.popen("openssl version").read()
print ("Checking openssl version")
ossl_version = re.findall('[0-9]+\.[0-9]+\.?[0-9]*', output)[0]
if Version(ossl_version) < Version('3.0.7'):
	print("Warning!, Using openssl version " + ossl_version)
	print("Use openssl version > 3.0.7")
endef

export MULTILINE_PYTHON_SCRIPT
EMBEDDED_PY := python3 -c "$$MULTILINE_PYTHON_SCRIPT"

.PHONY: all

all: banner create build

banner:
	@echo "Building examples for AOCL Cryptography"
	$(EMBEDDED_PY)

create:
	@mkdir -p  $(OBJ)/cipher
	@mkdir -p  $(OBJ)/digest
	@mkdir -p  $(OBJ)/rng
	@mkdir -p $(OBJ)/mac
	@mkdir -p $(OBJ)/ecdh
	@mkdir -p $(OBJ)/version
	@mkdir -p $(OBJ)/rsa

build: $(TARGETS)
	@echo "Build Success"

$(TARGETS):
	@$(CC) examples/$@.c -o $(OBJ)/$@ $(CFLAGS) $(LFLAGS)
	@echo "Building "$@

clean:
	@echo "Removing Build Dir"
	@if [ -d $(OBJ) ]; then \
		rm -rf $(OBJ); \
	fi
