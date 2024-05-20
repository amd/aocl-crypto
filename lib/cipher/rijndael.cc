/*
 * Copyright (C) 2022-2024, Advanced Micro Devices. All rights reserved.
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
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS!
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include "alcp/error.h"

#include "alcp/base.hh"
#include "alcp/cipher/aes.hh"
#include "alcp/cipher/cipher_wrapper.hh"
#include "alcp/utils/bits.hh"
#include "alcp/utils/constants.hh"
#include "alcp/utils/copy.hh"
#include "alcp/utils/cpuid.hh"

#include <map>

#define ROR(inp, n) ((inp >> n) | (inp << (32 - n)))

using namespace alcp::base;  // for Status
using namespace alcp::utils; // for CpuId

static inline void
mix_column_exchange(Uint8* inp, Uint8* out)
{
    (out)[0] = (inp)[0];
    (out)[1] = (inp)[4];
    (out)[2] = (inp)[8];
    (out)[3] = (inp)[12];
    (out)[4] = (inp)[7];
    (out)[5] = (inp)[11];
    (out)[6] = (inp)[15];
    (out)[7] = (inp)[3];

    (out)[8]  = (inp)[10];
    (out)[9]  = (inp)[14];
    (out)[10] = (inp)[2];
    (out)[11] = (inp)[6];

    (out)[12] = (inp)[13];
    (out)[13] = (inp)[1];
    (out)[14] = (inp)[5];
    (out)[15] = (inp)[9];
}

static inline void
mix_column_last_exchange(Uint8* inp, Uint8* out)
{
    (out)[0] = (inp)[0];
    (out)[1] = (inp)[5];
    (out)[2] = (inp)[10];
    (out)[3] = (inp)[15];
    (out)[4] = (inp)[4];
    (out)[5] = (inp)[9];
    (out)[6] = (inp)[14];
    (out)[7] = (inp)[3];

    (out)[8]  = (inp)[8];
    (out)[9]  = (inp)[13];
    (out)[10] = (inp)[2];
    (out)[11] = (inp)[7];

    (out)[12] = (inp)[12];
    (out)[13] = (inp)[1];
    (out)[14] = (inp)[6];
    (out)[15] = (inp)[11];
}

static inline void
inv_mix_column_exchange(Uint8* inp, Uint8* out)
{
    (out)[0] = (inp)[0];
    (out)[1] = (inp)[4];
    (out)[2] = (inp)[8];
    (out)[3] = (inp)[12];
    (out)[4] = (inp)[1];
    (out)[5] = (inp)[5];
    (out)[6] = (inp)[9];
    (out)[7] = (inp)[13];

    (out)[8]  = (inp)[2];
    (out)[9]  = (inp)[6];
    (out)[10] = (inp)[10];
    (out)[11] = (inp)[14];

    (out)[12] = (inp)[3];
    (out)[13] = (inp)[7];
    (out)[14] = (inp)[11];
    (out)[15] = (inp)[15];
}
static inline void
inv_mix_column_last_exchange(Uint8* inp, Uint8* out)
{
    (out)[0] = (inp)[0];
    (out)[1] = (inp)[13];
    (out)[2] = (inp)[10];
    (out)[3] = (inp)[7];
    (out)[4] = (inp)[4];
    (out)[5] = (inp)[1];
    (out)[6] = (inp)[14];
    (out)[7] = (inp)[11];

    (out)[8]  = (inp)[8];
    (out)[9]  = (inp)[5];
    (out)[10] = (inp)[2];
    (out)[11] = (inp)[15];

    (out)[12] = (inp)[12];
    (out)[13] = (inp)[9];
    (out)[14] = (inp)[6];
    (out)[15] = (inp)[3];
}
namespace alcp::cipher {

/*
 * FIPS-197  Chapter5, Figure-4
 *                Key Length         Block Size     No. of Rounds
 *                (Nk words)         (Nb words)      (Nr)
 *   AES-128         4               4               10
 *   AES-192         6               4               12
 *   AES-256         8               4               14
 *
 */
static const std::map<BlockSize, Params> ParamsMap = {
    { eBits128, { 4, 4, 10 } },
    { eBits192, { 6, 4, 12 } },
    { eBits256, { 8, 4, 14 } },
};

static BlockSize
BitsToBlockSize(int iVal)
{
    BlockSize bs;
    // clang-format off
        switch (iVal) {
            case 128: bs = eBits128; break;
            case 192: bs = eBits192; break;
            case 256: bs = eBits256; break;
            default:
                bs = eBits0;
                assert(false); break;
        }
    // clang-format on
    return bs;
}

static Uint8
GetSbox(Uint8 offset, bool use_invsbox = false)
{
    return utils::GetSbox(offset, use_invsbox);
}

static Uint8
gmulx2(Uint8 val)
{
    return ((val + val) & 0xfe)
           ^ ((((val & 0x80) << 1) - ((val & 0x80) >> 7)) & 0x11b);
}

static Uint32
gmulx2(Uint32 val)
{
    /*

        Reference Link & Source for Understanding:
        https://en.wikipedia.org/wiki/Finite_field_arithmetic
        4th topic Multiplication


        galois Multiple of val*2 for 32 bit

        val (32bit) = 4 val (8bit); 0xfefefefe to be used so that 8 bits
       don't interact with each other and last bit will always be zero as
       val+val used

        val & 0x80808080 GF modulo: if val has a nonzero term x^7, then must
       be reduced when it becomes x^8

        Primitive polynomial x^8 + x^4 + x^3 + x + 1
        (0b1_0001_1011) 0x11b so for 8bit 0x1b corresponds to the
       irreducible polynomial with the high term eliminated – you can change
       it but it must be irreducible

    */

    return ((val + val) & 0xfefefefe)
           ^ ((((val & 0x80808080) << 1) - ((val & 0x80808080) >> 7))
              & 0x1b1b1b1b);
}

static inline Uint32
InvMixColumns(const Uint32& val)
{
    Uint32 val_2 = gmulx2(val);           // val_2 = galois Multiple of val*2;
    Uint32 val_4 = gmulx2(val_2);         // val_4 = galois Multiple of val*4;
    Uint32 val_8 = gmulx2(val_4);         // val_8 = galois Multiple of val*8;
    Uint32 val_9 = val_8 ^ val;           // val_9 = galois Multiple of val*9;
    Uint32 val_b = val_8 ^ val_2 ^ val;   // val_b = galois Multiple of val*11;
    Uint32 val_d = val_8 ^ val_4 ^ val;   // val_d = galois Multiple of val*13;
    Uint32 val_e = val_8 ^ val_4 ^ val_2; // val_e = galois Multiple of val*14;

    // InvMixColumn is calulated using {0b}x^3 + {0d}x^2 + {09}x + {0e}
    return val_e ^ ((val_b >> 8) | (val_b << 24))
           ^ ((val_d >> 16) | (val_d << 16)) ^ ((val_9 >> 24) | (val_9 << 8));
}

static inline void
InvMixColumnsx8(Uint8* inp)
{
    Uint8 states[16];

    utils::CopyBytes(states, inp, 16);

    for (int i = 0; i < 4; i++) {
        Uint8 t0, t1, t2, t3;
        t0 = states[i + 4] ^ states[i + 8] ^ states[i + 12];
        t1 = states[i] ^ states[i + 8] ^ states[i + 12];
        t2 = states[i] ^ states[i + 4] ^ states[i + 12];
        t3 = states[i] ^ states[i + 4] ^ states[i + 8];

        states[i] = gmulx2(states[i]); // state = galois Multiple of state*2;
        states[i + 4] =
            gmulx2(states[i + 4]); // state = galois Multiple of state*2;
        states[i + 8] =
            gmulx2(states[i + 8]); // state = galois Multiple of state*2;
        states[i + 12] =
            gmulx2(states[i + 12]); // state = galois Multiple of state*2;

        t0 ^= states[i] ^ states[i + 4];
        t1 ^= states[i + 4] ^ states[i + 8];
        t2 ^= states[i + 8] ^ states[i + 12];
        t3 ^= states[i + 12] ^ states[i];

        Uint8 tm1, tm2, tm3;

        tm1 = states[i] ^ states[i + 8];
        tm2 = states[i + 4] ^ states[i + 12];
        tm1 = gmulx2(tm1);
        tm2 = gmulx2(tm2);

        tm3 = tm1 ^ tm2;
        tm3 = gmulx2(tm3);

        states[i]      = t0 ^ tm1 ^ tm3;
        states[i + 4]  = t1 ^ tm2 ^ tm3;
        states[i + 8]  = t2 ^ tm1 ^ tm3;
        states[i + 12] = t3 ^ tm2 ^ tm3;
    }
    inv_mix_column_exchange(states, inp);
}

static inline void
MixColumnsx8(Uint8* inp)
{
    Uint8 states[16];

    utils::CopyBytes(states, inp, 16);

    for (int i = 0; i < 4; i++) {
        Uint8 t0, t1, t2, t3;
        t0 = states[i + 4] ^ states[i + 8] ^ states[i + 12];
        t1 = states[i + 8] ^ states[i + 12] ^ states[i];
        t2 = states[i + 12] ^ states[i] ^ states[i + 4];
        t3 = states[i] ^ states[i + 4] ^ states[i + 8];

        states[i] = gmulx2(states[i]); // state = galois Multiple of state*2;
        states[i + 4] =
            gmulx2(states[i + 4]); // state = galois Multiple of state*2;
        states[i + 8] =
            gmulx2(states[i + 8]); // state = galois Multiple of state*2;
        states[i + 12] =
            gmulx2(states[i + 12]); // state = galois Multiple of state*2;

        t0 ^= states[i] ^ states[i + 4];
        t1 ^= states[i + 4] ^ states[i + 8];
        t2 ^= states[i + 8] ^ states[i + 12];
        t3 ^= states[i + 12] ^ states[i];
        states[i]      = t0;
        states[i + 4]  = t1;
        states[i + 8]  = t2;
        states[i + 12] = t3;
    }
    mix_column_exchange(states, inp);
}

static inline void
SubBytes(Uint8* inp)
{
    using namespace utils;
    for (int b = 0; b < 16; b++) {
        inp[b] = GetSbox(inp[b]);
    }
}

static inline void
InvSubBytes(Uint8* inp)
{
    using namespace utils;
    for (int b = 0; b < 16; b++) {
        inp[b] = GetSbox(inp[b], true);
    }
}

static Uint32
AddRoundKey(Uint32 input, Uint32 key)
{
    return input ^ key;
}

void
Rijndael::setKey(const Uint8* key, int len)
{
    m_block_size      = BitsToBlockSize(len);
    const Params& prm = ParamsMap.at(m_block_size);
    m_nrounds         = prm.Nr;
    m_key_size        = len / utils::BitsPerByte;

    /* Encryption and Decryption keys */
    m_enc_key = m_round_key_enc;
    m_dec_key = m_round_key_dec;
    expandKeys(key);
}

/*
 * FIPS-197 Section 5.1 Psuedo-code for Encryption
 *
 * Cipher(byte in[4*Nb], byte out[4*Nb], word w[Nb*(Nr+1)])
 *  begin
 *
 *       byte state[4,Nb]
 *
 *       state = in
 *
 *       AddRoundKey(state, w[0, Nb-1]) // See Sec. 5.1.4
 *
 *       for round = 1 step 1 to Nr–1
 *           SubBytes(state) // See Sec. 5.1.1
 *           ShiftRows(state) // See Sec. 5.1.2
 *           MixColumns(state) // See Sec. 5.1.3
 *           AddRoundKey(state, w[round*Nb, (round+1)*Nb-1])
 *       end for
 *
 *       SubBytes(state)
 *       ShiftRows(state)
 *       AddRoundKey(state, w[Nr*Nb, (Nr+1)*Nb-1])
 *
 *       out = state
 *
 *  end
 */
static void
encryptBlockKernel(const Uint32 (&blk0)[4],
                   Uint32 (&dst)[4],
                   const Uint8* pkey,
                   int          nr)
{

    using utils::MakeWord;
    auto p_key32 = reinterpret_cast<const Uint32*>(pkey);

    Uint32 state[4];
    memcpy(state, blk0, 16);

    auto p_state = reinterpret_cast<Uint8*>(state);

    state[0] = state[0] ^ p_key32[0];
    state[1] = state[1] ^ p_key32[1];
    state[2] = state[2] ^ p_key32[2];
    state[3] = state[3] ^ p_key32[3];

    p_key32 += 4;

    for (int r = 1; r < nr; r++) {

        SubBytes(p_state);

        state[1] = ROR(state[1], 8);
        state[2] = ROR(state[2], 16);
        state[3] = ROR(state[3], 24);

        MixColumnsx8(p_state);

        state[0] = state[0] ^ p_key32[0];
        state[1] = state[1] ^ p_key32[1];
        state[2] = state[2] ^ p_key32[2];
        state[3] = state[3] ^ p_key32[3];

        p_key32 += 4;
    }
    Uint8 temp[16];

    SubBytes(p_state);
    utils::CopyBytes(temp, p_state, 16);
    mix_column_last_exchange(temp, p_state);

    state[0] = AddRoundKey(state[0], p_key32[0]);
    state[1] = state[1] ^ p_key32[1];
    state[2] = state[2] ^ p_key32[2];
    state[3] = state[3] ^ p_key32[3];

    utils::CopyBytes(dst, state, sizeof(state));
}

/*
 * FIPS-197 Section 5.3 Psuedo-code for Decryption
 * InvCipher(byte in[4*Nb], byte out[4*Nb], word w[Nb*(Nr+1)])
 *  begin
 *
 *   byte state[4,Nb]
 *
 *   state = in
 *
 *   AddRoundKey(state, w[Nr*Nb, (Nr+1)*Nb-1]) // See Sec. 5.1.4
 *
 *   for round = Nr-1 step -1 downto 1
 *         InvShiftRows(state) // See Sec. 5.3.1
 *         InvSubBytes(state) // See Sec. 5.3.2
 *         AddRoundKey(state, w[round*Nb, (round+1)*Nb-1])
 *         InvMixColumns(state) // See Sec. 5.3.3
 *   end for
 *
 *   InvShiftRows(state)
 *   InvSubBytes(state)
 *   AddRoundKey(state, w[0, Nb-1])
 *
 *   out = state
 *
 *  end
 */

void
Rijndael::AesDecrypt(Uint32* blk0, const Uint8* pkey, int nr) const
{

    using utils::MakeWord;
    auto p_key32 = reinterpret_cast<const Uint32*>(pkey);

    Uint32 state[4];
    memcpy(state, blk0, 16);

    auto p_state = reinterpret_cast<Uint8*>(state);

    state[0] = state[0] ^ p_key32[0];
    state[1] = state[1] ^ p_key32[1];
    state[2] = state[2] ^ p_key32[2];
    state[3] = state[3] ^ p_key32[3];

    p_key32 += 4;

    for (int r = 1; r < nr; r++) {
        Uint8 tmp[16];
        memcpy(tmp, p_state, 16);
        inv_mix_column_exchange(tmp, p_state);

        state[1] = ROR(state[1], 24);
        state[2] = ROR(state[2], 16);
        state[3] = ROR(state[3], 8);

        InvSubBytes(p_state);

        InvMixColumnsx8(p_state);

        state[0] = state[0] ^ p_key32[0];
        state[1] = state[1] ^ p_key32[1];
        state[2] = state[2] ^ p_key32[2];
        state[3] = state[3] ^ p_key32[3];

        p_key32 += 4;
    }
    Uint8 temp[16];

    InvSubBytes(p_state);
    utils::CopyBytes(temp, p_state, 16);
    inv_mix_column_last_exchange(temp, p_state);

    state[0] = AddRoundKey(state[0], p_key32[0]);
    state[1] = state[1] ^ p_key32[1];
    state[2] = state[2] ^ p_key32[2];
    state[3] = state[3] ^ p_key32[3];

    utils::CopyBytes(blk0, state, 16);
}

/*
 * FIPS-197 Section 5.3 Psuedo-code for Decryption
 * InvCipher(byte in[4*Nb], byte out[4*Nb], word w[Nb*(Nr+1)])
 *  begin
 *
 *   byte state[4,Nb]
 *
 *   state = in
 *
 *   AddRoundKey(state, w[Nr*Nb, (Nr+1)*Nb-1]) // See Sec. 5.1.4
 *
 *   for round = Nr-1 step -1 downto 1
 *         InvShiftRows(state) // See Sec. 5.3.1
 *         InvSubBytes(state) // See Sec. 5.3.2
 *         AddRoundKey(state, w[round*Nb, (round+1)*Nb-1])
 *         InvMixColumns(state) // See Sec. 5.3.3
 *   end for
 *
 *   InvShiftRows(state)
 *   InvSubBytes(state)
 *   AddRoundKey(state, w[0, Nb-1])
 *
 *   out = state
 *
 *  end
 */
alc_error_t
Rijndael::decrypt(alc_cipher_data_t* ctx,
                  const Uint8*       pSrc,
                  Uint8*             pDst,
                  Uint64             len) const
{
#if 0
    Uint32 nb = cBlockSizeWord;
    Uint8  state[4][cBlockSizeWord];
#endif
    return ALC_ERROR_NONE;
}

/*
 * FIPS-197 Section 5.2 Psuedo-code key expansion
 *
 * KeyExpansion(byte key[4*Nk], word w[Nb*(Nr+1)], Nk)
 *  begin
 *    word temp
 *
 *     i = 0
 *     while (i < Nk)
 *          w[i] = word(key[4*i], key[4*i+1], key[4*i+2], key[4*i+3])
 *          i = i+1
 *     end while
 *
 *     i = Nk
 *
 *    while (i < Nb * (Nr+1)]
 *          temp = w[i-1]
 *          if (i mod Nk = 0)
 *                  temp = SubWord(RotWord(temp)) xor Rcon[i/Nk]
 *          else if (Nk > 6 and i mod Nk = 4)
 *                  temp = SubWord(temp)
 *          end if
 *          w[i] = w[i-Nk] xor temp
 *          i = i + 1
 *     end while
 *
 *  end
 *
 * Note:  Nk = 4,6,or 8 do not all have to be implemented;
 * they are all included in the conditional statement above for
 * conciseness.
 */
void
Rijndael::expandKeys(const Uint8* pUserKey) noexcept
{
    using utils::GetByte, utils::MakeWord;

    Uint8        dummy_key[Rijndael::cMaxKeySize] = { 0 };
    const Uint8* key     = pUserKey ? pUserKey : &dummy_key[0];
    Uint8 *      pEncKey = nullptr, *pDecKey = nullptr;

    pEncKey = m_enc_key;
    pDecKey = m_dec_key;

    if (CpuId::cpuHasAesni()) {
        aesni::ExpandKeys(key, pEncKey, pDecKey, m_nrounds);
        return;
    }

    Uint32 i;
    Uint32 nb = Rijndael::cBlockSizeWord, nr = m_nrounds,
           nk          = m_key_size / utils::BytesPerWord;
    const Uint32* rtbl = utils::s_round_constants;
    Uint32*       p_enc_key32;
    // auto            p_key32     = reinterpret_cast<const Uint32*>(key);
    p_enc_key32 = reinterpret_cast<Uint32*>(pEncKey);

    for (i = 0; i < nk; i++) {
        p_enc_key32[i] = MakeWord(
            key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]);
    }

    for (i = nk; i < nb * (nr + 1); i++) {
        Uint32 temp = p_enc_key32[i - 1];
        if (i % nk == 0) {
            temp = MakeWord(GetSbox(GetByte(temp, 1)),
                            GetSbox(GetByte(temp, 2)),
                            GetSbox(GetByte(temp, 3)),
                            GetSbox(GetByte(temp, 0)));

            temp ^= *rtbl++;
        } else if (nk > 6 && (i % nk == 4)) {
            temp = MakeWord(GetSbox(GetByte(temp, 0)),
                            GetSbox(GetByte(temp, 1)),
                            GetSbox(GetByte(temp, 2)),
                            GetSbox(GetByte(temp, 3)));
        }

        p_enc_key32[i] = p_enc_key32[i - nk] ^ temp;
    }

    utils::CopyBlock(pDecKey, pEncKey, m_key_size * 8);

    auto p_dec_key32  = reinterpret_cast<Uint32*>(pDecKey);
    auto p_dec_key128 = reinterpret_cast<__m128i*>(pDecKey);

    for (i = 4; i < nb * (nr + 1); i++) {
        p_dec_key32[i] = InvMixColumns(p_enc_key32[i]);
    }

    for (int i = 0, j = nr; i < j; i += 1, j -= 1) {
        __m128i temp    = p_dec_key128[i];
        p_dec_key128[i] = p_dec_key128[j];
        p_dec_key128[j] = temp;
    }
    (p_dec_key128)[0] = ((__m128i*)p_enc_key32)[nr];
}

void
Rijndael::initRijndael(const Uint8* pKey, const Uint64 keyLen)
{
    setKeyLen(keyLen);
    setKey(pKey);
    setUp();
}

Rijndael::~Rijndael() {}

#define BYTE0O_WORD(x) utils::BytesToWord<Uint8>((x), 0, 0, 0)

void
Rijndael::setDecryptKey(const Uint8*, Uint64)
{
    NotImplementedException(ALCP_SOURCE_LOCATION());
}

void
Rijndael::setEncryptKey(const Uint8*, Uint64)
{
    NotImplementedException(ALCP_SOURCE_LOCATION());
}

Uint32
Rijndael::getNr() const
{
    return getRounds();
}

Uint32
Rijndael::getNk() const
{
    /* getKeySize() returns length in bytes */
    return getKeySize() / utils::BytesPerWord;
}

alc_error_t
Rijndael::encrypt(alc_cipher_data_t* ctx,
                  const Uint8*       pPlaintxt,
                  Uint8*             pCiphertxt,
                  Uint64             len) const
{
    auto n_words = len / Rijndael::cBlockSizeWord;

    ALCP_ASSERT(len % Rijndael::cBlockSize == 0,
                "Plaintext length is not a multiple of cBlockSize");

    while (n_words >= 4) {
        auto   pt = reinterpret_cast<const Uint32(*)[4]>(&pPlaintxt);
        Uint32 ct[4];

        encryptBlockKernel(*pt, ct, getEncryptKeys(), getRounds());
        utils::CopyBytes(pCiphertxt, ct, sizeof(ct));

        pPlaintxt += cBlockSize;
        pCiphertxt += cBlockSize;
        n_words -= 4;
    }

    return ALC_ERROR_NONE;
}

void Rijndael::encryptBlock(Uint32 (&blk0)[4], const Uint8* pkey, int nr) const
{
    encryptBlockKernel(blk0, blk0, pkey, nr);
}

} // namespace alcp::cipher
