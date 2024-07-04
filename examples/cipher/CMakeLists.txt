 # Copyright (C) 2021-2024, Advanced Micro Devices. All rights reserved.
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

ADD_EXAMPLE(aes-cfb aes-cfb.c)

ADD_EXAMPLE(aes-gcm aes-gcm.c)

ADD_EXAMPLE(aes-gcmcpp aes-gcm.cc)

ADD_EXAMPLE(aes-cbccpp aes-cbc.cc)

ADD_EXAMPLE(aes-xts aes-xts.c)

ADD_EXAMPLE(aes-ccm aes-ccm.c)

ADD_EXAMPLE(aes-siv aes-siv.c)

#temporarily disabled reference kernel support to be added in next PR
#ADD_EXAMPLE(chacha20 chacha20.c)

ADD_EXAMPLE(aes-speed-cipher aes-speed-cipher.c)

ADD_EXAMPLE(aes-speed-gcm aes-speed-gcm.c)

#temporarily disabled reference kernel support to be added in next PR
#ADD_EXAMPLE(chacha20-poly1305 chacha20-poly1305.c)
