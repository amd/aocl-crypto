/*
 * Copyright (C) 2024, Advanced Micro Devices. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 3. Neither the name of the copyright holder nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 * without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include "Fuzz/alcp_fuzz_test.hh"

using namespace alcp::testing;

int
FuzzerTestOneInput(const Uint8* buf, size_t len)
{
    FuzzedDataProvider stream(buf, len);

    /* Using Uint16 here to avoid empty second_part */
    Uint32 size1 = stream.ConsumeIntegral<Uint16>(); // Key
    size_t size2 = stream.ConsumeIntegral<Uint16>(); // PT and CT

    /* Splitting the fuzzed input into 3 parts   */
    std::vector<Uint8> fuzz_in1 = stream.ConsumeBytes<Uint8>(size1); // Key
    std::vector<Uint8> fuzz_in2 =
        stream.ConsumeBytes<Uint8>(size2); // Plain_Text
    std::vector<Uint8> fuzz_in3 =
        stream.ConsumeBytes<Uint8>(size2);                     // Cipher_Text
    std::vector<Uint8> fuzz_in4 = std::vector<Uint8>{ 16, 0 }; // IV
    fuzz_in4.reserve(16);

    /* Initializing the fuzz seeds  */
    const Uint8* key       = fuzz_in1.data();
    Uint32       keySize   = size1;
    const Uint8* plaintxt  = fuzz_in2.data();
    Uint8*       ciphertxt = fuzz_in3.data();
    const Uint32 PT_len    = size2;
    const Uint8* iv        = fuzz_in4.data();

    std::unique_ptr<Uint8[]> CT = std::make_unique<Uint8[]>(PT_len);

    alcp_dc_ex_t data;
    data.m_in   = plaintxt;
    data.m_inl  = fuzz_in2.size();
    data.m_out  = CT.get();
    data.m_outl = fuzz_in2.size();
    data.m_iv   = iv;
    data.m_ivl  = fuzz_in4.size();

    alc_cipher_type_t type = ALC_CIPHER_TYPE_AES;
    alc_cipher_mode_t mode = ALC_AES_MODE_CBC;

    std::unique_ptr<CipherBase> cb =
        std::make_unique<AlcpCipherBase>(type, mode, iv);

    bool ret = cb->init(key, keySize);
    if (!ret) {
        std::cout << "ERROR: CBC_Init failed." << std::endl;
        goto OUT;
    }

    ret = cb->encrypt(data);
    if (!ret) {
        std::cout << "ERROR: CBC_Encrypt failed." << std::endl;
        goto OUT;
    }

    cb->reset();

    ret = cb->decrypt(data);
    if (!ret) {
        std::cout << "ERROR: CBC_Decrypt failed." << std::endl;
        goto OUT;
    }

OUT:
    return 0;
}

extern "C" int
LLVMFuzzerTestOneInput(const uint8_t* Data, size_t Size)
{
    return FuzzerTestOneInput(Data, Size);
}