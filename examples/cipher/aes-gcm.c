/*
 * Copyright (C) 2023-2024, Advanced Micro Devices. All rights reserved.
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

#include <assert.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h> /* for malloc */
#include <string.h>

#ifdef __linux__
#include <sys/time.h>
#elif WIN32
#include <windows.h>
#endif

#include "alcp/alcp.h"

static alc_cipher_handle_t handle;

// #define DEBUG_PRINT 1

static inline void
printText(Uint8* I, Uint64 len, char* s, bool print)
{
    if (print) {
        printf("\n %s ", s);
        for (int x = 0; x < len; x++) {
            if ((x % (16 * 4) == 0)) {
                printf("\n");
            }
            if (x % 16 == 0) {
                printf("   ");
            }
            printf(" %2x", *(I + x));
        }
    }
}

struct timeval begin, end;
long           seconds;
long           microseconds;
double         elapsed;
double         totalTimeElapsed;

#if WIN32
int
gettimeofday(struct timeval* tv, struct timeval* tv1)
{
    FILETIME   f_time;
    Uint64     time;
    SYSTEMTIME s_time;
    // define UNIX EPOCH time for windows
    static const Uint64 EPOCH = ((Uint64)116444736000000000ULL);
    GetSystemTimeAsFileTime(&f_time);
    FileTimeToSystemTime(&f_time, &s_time);
    time = ((Uint64)f_time.dwLowDateTime);
    time += ((Uint64)f_time.dwHighDateTime) << 32;
    tv->tv_sec  = (long)((time - EPOCH) / 10000000L);
    tv->tv_usec = (long)(s_time.wMilliseconds * 1000);
    return 0;
}
#endif

#define ALCP_CRYPT_TIMER_START gettimeofday(&begin, 0);

static inline void
alcp_get_time(int x, char* y)
{
    gettimeofday(&end, 0);
    seconds      = end.tv_sec - begin.tv_sec;
    microseconds = end.tv_usec - begin.tv_usec;
    elapsed      = seconds + microseconds * 1e-6;
    totalTimeElapsed += elapsed;
    if (x) {
        printf("%s\t", y);
        printf(" %2.2f ms ", elapsed * 1000);
    }
}

void
getinput(Uint8* output, int inputLen, int seed)
{
    // generate same random input based on seed value.
    srand(seed);
    for (int i = 0; i < inputLen; i++) {
        *output = (Uint8)rand();
        output++;
    }
}

// clang-format off

/*    GCM Encrypt test vector
 *    Test vector from gcmEncryptExtIV128.rsp file in below path
 *    http://csrc.nist.gov/groups/STM/cavp/documents/mac/gcmtestvectors.zip
 *
 */
#define TEST_VECTOR_COUNT          9 //9 encrypt test vectors added.

/*
// gcm test vector without additional data
Test_vector_num :0 (pt + no additional data)
        [Keylen = 128]
        [IVlen = 96]
        [PTlen = 256]
        [AADlen = 0]
        [Taglen = 112]
        Count = 0
        Key = c75116c19f5ea4ed1b10bf0eaaebe5a1
        IV = 48a53fc17d4300f4a23a5a39
        PT = 4569944fcde5b3f4ae4d50eb7a0e3ef88dab44b684c737b90aa88cf579bf0558
        AAD =
        CT = d58b89300c62e0b0ea729d6de39545ea35ddc5a04e22b709f45af532bc67d90d
        Tag = c428abd4bf85468d57236ed16d36
// gcm test vector with additional data and without plaintext
Test_vector_num :1 (no pt + additional data)
        [Keylen = 128]
        [IVlen = 96]
        [PTlen = 0]
        [AADlen = 128]
        [Taglen = 120]
        Count = 0
        Key = da0b615656135194ba6d3c851099bc48
        IV = d39d4b4d3cc927885090e6c3
        PT =
        AAD = e7e5e6f8dac913036cb2ff29e8625e0e
        CT =
        Tag = ab967711a5770461724460b07237e2
Test_vector_num :2 (pt + additional data )
        [Keylen = 128]
        [IVlen = 96]
        [PTlen = 128]
        [AADlen = 384]
        [Taglen = 32]
        Count = 0
        Key = 99e8e1861e55cf4e853a910c70901f2d
        IV = 437b73e624906652956bd2fb
        PT = fd239ba3aeef41608fc7013c472b581d
        AAD = 41e328808d081b677d8f51bdaedf0aa7b42e4de88c1a9004196d7ca5e0e4f9aab3a78f26cf01d60deec62dad8f9fd62b
        CT = 8ccc27bca436f983c761d5c5ef28138a
        Tag = a2f11ce5
Test_vector_num :3 ( pt not aligned to 128bit )
        [Keylen = 128]
        [IVlen = 96]
        [PTlen = 104]
        [AADlen = 128]
        [Taglen = 104]
        Count = 0
        Key = 27e3626a8347f252519f3a391712f65a
        IV = e50b6bbe4ac7307f75421a71
        PT = bf386209503082f15ed8461ddd
        AAD = 96fe6e72597f596ae93907a820ba79a8
        CT = 34d347fa1b56d2cf691f1ce062
        Tag = cb083ec9d63075bea3bba1c0d4
Test_vector_num :4 (pt and ad not aligend to 128bit )
        [Keylen = 128]
        [IVlen = 96]
        [PTlen = 408]
        [AADlen = 160]
        [Taglen = 128]
        Count = 0
        Key = fe47fcce5fc32665d2ae399e4eec72ba
        IV = 5adb9609dbaeb58cbd6e7275
        PT = 7c0e88c88899a779228465074797cd4c2e1498d259b54390b85e3eef1c02df60e743f1b840382c4bccaf3bafb4ca8429bea063
        AAD = 88319d6e1d3ffa5f987199166c8a9b56c2aeba5a
        CT = 98f4826f05a265e6dd2be82db241c0fbbbf9ffb1c173aa83964b7cf5393043736365253ddbc5db8778371495da76d269e5db3e
        Tag = 291ef1982e4defedaa2249f898556b47
Test_vector_num :5
        [Keylen = 128]
        [IVlen = 8]
        [PTlen = 128]
        [AADlen = 160]
        [Taglen = 64]
        Count = 0
        Key = 90e625f18f04122c3e0657a2dfe0e1b8
        IV = d9
        PT = e2d381298318a2135ca6d01a24d0dfab
        AAD = a7f88b0e07672401f86f515404fe5af3e53edcca
        CT = 87cbfc064d5584ac1c2b385adc02fde5
        Tag = f0260a089fdaaa12
Test_vector_num :6
        [Keylen = 128]
        [IVlen = 1024]
        [PTlen = 128]
        [AADlen = 128]
        [Taglen = 120]
        Count = 0
        Key = ec20b2dd5a4d6f8d2aa49086a7ef9080
        IV = d15fd1d8ba90275826c6b085d9d2a3856e2359e41f2ab3033b6c4a61e412177233afbdd0897d113652e72e37d711627eb43636fd7d7513f213f458d89597e330e487adde840c245ce21f3e45d14075c86ee6f70a7dde573dd320786d1ff28ea026c07bfe904dfb904a990123f79a0a32febcc57d2fe529ccd2a393856757065c
        PT = 7ca608d6dac77682def3e129499d1575
        AAD = 3abfac97f5e569ed960638002ae32738
        CT = f7c5704950a6b03a77db660769e1204b
        Tag = a0d98b0c38599c1bb16354f61b0f00
Test_vector_num :7
        [Keylen = 128]
        [IVlen = 8]
        [PTlen = 256]
        [AADlen = 128]
        [Taglen = 104]
        Count = 0
        Key = be07c4a0725cc27da0221b4892c959b5
        IV = 15
        PT = e4f618a23e93cde8b9480a63e0bcb0806f66f47e36f0cb86c932f43291ca4d52
        AAD = 6f65e713c455988a256d59c754b44f4f
        CT = 6c21f6f08e77a9cb2e4b7a702270cc07bb1c7225cffaaa9d6a310c1dfd5adf4b
        Tag = d3770bc1706d83cd4e936d32bc
*/

static int test_iv_len[TEST_VECTOR_COUNT]  = {12,  12, 12, 12, 12, 1, 128, 1, 19};
static int test_pt_len[TEST_VECTOR_COUNT]  = {32,  0, 16, 13, 51, 16, 16, 32, 48};
static int test_ad_len[TEST_VECTOR_COUNT]  = { 0, 16, 48, 16, 20, 20, 16, 16, 32};
static int test_tag_len[TEST_VECTOR_COUNT] = {14, 15, 4,  13, 16, 8 , 15, 13, 16};

static Uint8 test_tag[TEST_VECTOR_COUNT][16] = {
                                                {0xc4, 0x28, 0xab, 0xd4, 0xbf, 0x85, 0x46, 0x8d, 0x57, 0x23, 0x6e, 0xd1, 0x6d, 0x36 },
                                                {0xab, 0x96, 0x77, 0x11, 0xa5, 0x77, 0x04, 0x61, 0x72, 0x44, 0x60, 0xb0, 0x72, 0x37, 0xe2 },
                                                {0xa2, 0xf1, 0x1c, 0xe5 },
                                                {0xcb, 0x08, 0x3e, 0xc9, 0xd6, 0x30, 0x75, 0xbe, 0xa3, 0xbb, 0xa1, 0xc0, 0xd4 },
                                                {0x29, 0x1e, 0xf1, 0x98, 0x2e, 0x4d, 0xef, 0xed, 0xaa, 0x22, 0x49, 0xf8, 0x98, 0x55, 0x6b, 0x47 },
                                                {0xf0, 0x26, 0x0a, 0x08, 0x9f, 0xda, 0xaa, 0x12 },
                                                {0xa0, 0xd9, 0x8b, 0x0c, 0x38, 0x59, 0x9c, 0x1b, 0xb1, 0x63, 0x54, 0xf6, 0x1b, 0x0f, 0x00 },
                                                {0xd3, 0x77, 0x0b, 0xc1, 0x70, 0x6d, 0x83, 0xcd, 0x4e, 0x93, 0x6d, 0x32, 0xbc },
                                                {0x77, 0xf6, 0xc4, 0x7b, 0x5, 0x40, 0xf0, 0xb9, 0xff, 0x3c, 0x3b, 0x7, 0xa2, 0x4c, 0x62, 0xfe}
                                                };

static Uint8 test_key[TEST_VECTOR_COUNT][16] = {
                                                  {0xc7, 0x51, 0x16, 0xc1, 0x9f, 0x5e, 0xa4, 0xed, 0x1b, 0x10, 0xbf, 0x0e, 0xaa, 0xeb, 0xe5, 0xa1 },
                                                  {0xda, 0x0b, 0x61, 0x56, 0x56, 0x13, 0x51, 0x94, 0xba, 0x6d, 0x3c, 0x85, 0x10, 0x99, 0xbc, 0x48 },
                                                  {0x99, 0xe8, 0xe1, 0x86, 0x1e, 0x55, 0xcf, 0x4e, 0x85, 0x3a, 0x91, 0x0c, 0x70, 0x90, 0x1f, 0x2d },
                                                  {0x27, 0xe3, 0x62, 0x6a, 0x83, 0x47, 0xf2, 0x52, 0x51, 0x9f, 0x3a, 0x39, 0x17, 0x12, 0xf6, 0x5a },
                                                  {0xfe, 0x47, 0xfc, 0xce, 0x5f, 0xc3, 0x26, 0x65, 0xd2, 0xae, 0x39, 0x9e, 0x4e, 0xec, 0x72, 0xba },
                                                  {0x90, 0xe6, 0x25, 0xf1, 0x8f, 0x04, 0x12, 0x2c, 0x3e, 0x06, 0x57, 0xa2, 0xdf, 0xe0, 0xe1, 0xb8 },
                                                  {0xec, 0x20, 0xb2, 0xdd, 0x5a, 0x4d, 0x6f, 0x8d, 0x2a, 0xa4, 0x90, 0x86, 0xa7, 0xef, 0x90, 0x80 },
                                                  {0xbe, 0x07, 0xc4, 0xa0, 0x72, 0x5c, 0xc2, 0x7d, 0xa0, 0x22, 0x1b, 0x48, 0x92, 0xc9, 0x59, 0xb5 },
                                                  {0xfe, 0xc7, 0x2f, 0xee, 0x8f, 0xc3, 0x88, 0x33, 0xe0, 0xdb, 0x47, 0xd2, 0x0d, 0x69, 0x22, 0x36 }
                                                  };

static Uint8 test_iv[TEST_VECTOR_COUNT][148]  = {{0x48, 0xa5, 0x3f, 0xc1, 0x7d, 0x43, 0x00, 0xf4, 0xa2, 0x3a, 0x5a, 0x39 },
                                                  {0xd3, 0x9d, 0x4b, 0x4d, 0x3c, 0xc9, 0x27, 0x88, 0x50, 0x90, 0xe6, 0xc3 },
                                                  {0x43, 0x7b, 0x73, 0xe6, 0x24, 0x90, 0x66, 0x52, 0x95, 0x6b, 0xd2, 0xfb },
                                                  {0xe5, 0x0b, 0x6b, 0xbe, 0x4a, 0xc7, 0x30, 0x7f, 0x75, 0x42, 0x1a, 0x71 },
                                                  {0x5a, 0xdb, 0x96, 0x09, 0xdb, 0xae, 0xb5, 0x8c, 0xbd, 0x6e, 0x72, 0x75 },
                                                  {0xd9},
                                                  {0xd1, 0x5f, 0xd1, 0xd8, 0xba, 0x90, 0x27, 0x58, 0x26, 0xc6, 0xb0, 0x85,
                                                   0xd9, 0xd2, 0xa3, 0x85, 0x6e, 0x23, 0x59, 0xe4, 0x1f, 0x2a, 0xb3, 0x03,
                                                   0x3b, 0x6c, 0x4a, 0x61, 0xe4, 0x12, 0x17, 0x72, 0x33, 0xaf, 0xbd, 0xd0,
                                                   0x89, 0x7d, 0x11, 0x36, 0x52, 0xe7, 0x2e, 0x37, 0xd7, 0x11, 0x62, 0x7e,
                                                   0xb4, 0x36, 0x36, 0xfd, 0x7d, 0x75, 0x13, 0xf2, 0x13, 0xf4, 0x58, 0xd8,
                                                   0x95, 0x97, 0xe3, 0x30, 0xe4, 0x87, 0xad, 0xde, 0x84, 0x0c, 0x24, 0x5c,
                                                   0xe2, 0x1f, 0x3e, 0x45, 0xd1, 0x40, 0x75, 0xc8, 0x6e, 0xe6, 0xf7, 0x0a,
                                                   0x7d, 0xde, 0x57, 0x3d, 0xd3, 0x20, 0x78, 0x6d, 0x1f, 0xf2, 0x8e, 0xa0,
                                                   0x26, 0xc0, 0x7b, 0xfe, 0x90, 0x4d, 0xfb, 0x90, 0x4a, 0x99, 0x01, 0x23,
                                                   0xf7, 0x9a, 0x0a, 0x32, 0xfe, 0xbc, 0xc5, 0x7d, 0x2f, 0xe5, 0x29, 0xcc,
                                                   0xd2, 0xa3, 0x93, 0x85, 0x67, 0x57, 0x06, 0x5c},
                                                  {0x15},
                                                  {0x39, 0x8c, 0x22, 0x07, 0x78, 0xa3, 0x13, 0xa0, 0x0c, 0x35, 0x6e, 0x65,
                                                   0x31, 0x99, 0x74, 0x82, 0x2c, 0x7e, 0x17}
                                                  };

static Uint8 test_pt[TEST_VECTOR_COUNT][60]  = {{0x45, 0x69, 0x94, 0x4f, 0xcd, 0xe5, 0xb3,
                                                   0xf4, 0xae, 0x4d, 0x50, 0xeb, 0x7a, 0x0e,
                                                   0x3e, 0xf8, 0x8d, 0xab, 0x44, 0xb6, 0x84,
                                                   0xc7, 0x37, 0xb9, 0x0a, 0xa8, 0x8c, 0xf5,
                                                   0x79, 0xbf, 0x05, 0x58 },
                                                  { },
                                                  {0xfd, 0x23, 0x9b, 0xa3, 0xae, 0xef, 0x41, 0x60, 0x8f, 0xc7, 0x01, 0x3c, 0x47, 0x2b, 0x58, 0x1d},
                                                  {0xbf, 0x38, 0x62, 0x09, 0x50, 0x30, 0x82, 0xf1, 0x5e, 0xd8, 0x46, 0x1d, 0xdd},
                                                  {0x7c, 0x0e, 0x88, 0xc8, 0x88, 0x99, 0xa7, 0x79, 0x22, 0x84, 0x65, 0x07, 0x47, 0x97, 0xcd, 0x4c,
                                                   0x2e, 0x14, 0x98, 0xd2, 0x59, 0xb5, 0x43, 0x90, 0xb8, 0x5e, 0x3e, 0xef, 0x1c, 0x02, 0xdf, 0x60,
                                                   0xe7, 0x43, 0xf1, 0xb8, 0x40, 0x38, 0x2c, 0x4b, 0xcc, 0xaf, 0x3b, 0xaf, 0xb4, 0xca, 0x84, 0x29,
                                                   0xbe, 0xa0, 0x63},
                                                  {0xe2, 0xd3, 0x81, 0x29, 0x83, 0x18, 0xa2, 0x13, 0x5c, 0xa6, 0xd0, 0x1a, 0x24, 0xd0, 0xdf, 0xab},
                                                  {0x7c, 0xa6, 0x08, 0xd6, 0xda, 0xc7, 0x76, 0x82, 0xde, 0xf3, 0xe1, 0x29, 0x49, 0x9d, 0x15, 0x75},
                                                  {0xe4, 0xf6, 0x18, 0xa2, 0x3e, 0x93, 0xcd, 0xe8, 0xb9, 0x48, 0x0a, 0x63, 0xe0, 0xbc, 0xb0, 0x80,
                                                   0x6f, 0x66, 0xf4, 0x7e, 0x36, 0xf0, 0xcb, 0x86, 0xc9, 0x32, 0xf4, 0x32, 0x91, 0xca, 0x4d, 0x52},
                                                  {0xee, 0xd2, 0xfe, 0xe8, 0xf9, 0xbe, 0x1d, 0x5a, 0x55, 0xee, 0x4c, 0x28, 0x61, 0xb9, 0x31, 0x42,
                                                   0x58, 0x2a, 0x67, 0xdd, 0xef, 0x39, 0x7b, 0xff, 0xa6, 0xfa, 0x38, 0x1c, 0xa3, 0x4c, 0x93, 0xd5,
                                                   0xb4, 0xa1, 0xbd, 0x07, 0xb5, 0xee, 0xbf, 0x30, 0xc0, 0x0f, 0xb0, 0xa3, 0xb5, 0x87, 0x9d, 0x85 }
                                                  };

static Uint8 test_ad[TEST_VECTOR_COUNT][48] = {{0xe7, 0xe5, 0xe6, 0xf8, 0xda, 0xc9, 0x13, 0x03, 0x6c, 0xb2, 0xff, 0x29, 0xe8, 0x62, 0x5e, 0x0e },
                                                 {0xe7, 0xe5, 0xe6, 0xf8, 0xda, 0xc9, 0x13, 0x03, 0x6c, 0xb2, 0xff, 0x29, 0xe8, 0x62, 0x5e, 0x0e },
                                                 {0x41, 0xe3, 0x28, 0x80, 0x8d, 0x08, 0x1b, 0x67, 0x7d, 0x8f, 0x51, 0xbd, 0xae, 0xdf, 0x0a, 0xa7,
                                                  0xb4, 0x2e, 0x4d, 0xe8, 0x8c, 0x1a, 0x90, 0x04, 0x19, 0x6d, 0x7c, 0xa5, 0xe0, 0xe4, 0xf9, 0xaa,
                                                  0xb3, 0xa7, 0x8f, 0x26, 0xcf, 0x01, 0xd6, 0x0d, 0xee, 0xc6, 0x2d, 0xad, 0x8f, 0x9f, 0xd6, 0x2b },
                                                 {0x96, 0xfe, 0x6e, 0x72, 0x59, 0x7f, 0x59, 0x6a, 0xe9, 0x39, 0x07, 0xa8, 0x20, 0xba, 0x79, 0xa8},
                                                 {0x88, 0x31, 0x9d, 0x6e, 0x1d, 0x3f, 0xfa, 0x5f, 0x98, 0x71, 0x99, 0x16, 0x6c, 0x8a, 0x9b, 0x56,
                                                  0xc2, 0xae, 0xba, 0x5a},
                                                 {0xa7, 0xf8, 0x8b, 0x0e, 0x07, 0x67, 0x24, 0x01, 0xf8, 0x6f, 0x51, 0x54, 0x04, 0xfe, 0x5a, 0xf3,
                                                  0xe5, 0x3e, 0xdc, 0xca},
                                                 {0x3a, 0xbf, 0xac, 0x97, 0xf5, 0xe5, 0x69, 0xed, 0x96, 0x06, 0x38, 0x00, 0x2a, 0xe3, 0x27, 0x38},
                                                 {0x6f, 0x65, 0xe7, 0x13, 0xc4, 0x55, 0x98, 0x8a, 0x25, 0x6d, 0x59, 0xc7, 0x54, 0xb4, 0x4f, 0x4f},
                                                 {0x23, 0xfb, 0x6b, 0xe4, 0x66, 0x0f, 0x61, 0x18, 0xce, 0xd9, 0xa2, 0xae, 0xfd, 0x11, 0x73, 0xe7,
                                                  0x59, 0x19, 0x3e, 0x4d, 0x50, 0x3d, 0x98, 0xa2, 0x16, 0x6d, 0xd0, 0xf3, 0xeb, 0x69, 0x51, 0x1f }
                                                  };

// clang-format on

int
create_aes_session(Uint8*                  key,
                   Uint8*                  iv,
                   const Uint32            key_len,
                   const alc_cipher_mode_t mode)
{
    alc_error_t err;
    const int   err_size = 256;
    Uint8       err_buf[err_size];
    Uint8       tweakKey[16] = {
        0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7,
        0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xf, 0xf,
    };

    alc_cipher_aead_info_t cinfo = { // request params
                                     .ci_type   = ALC_CIPHER_TYPE_AES,
                                     .ci_mode   = ALC_AES_MODE_GCM,
                                     .ci_keyLen = key_len,
                                     // init params
                                     .ci_key = key,
                                     .ci_iv  = iv
    };

    /*
     * Application is expected to allocate for context
     */
    handle.ch_context = malloc(alcp_cipher_aead_context_size(&cinfo));
    if (!handle.ch_context)
        return -1;

    /* Request a context with cipher mode and keyLen */
    err = alcp_cipher_aead_request(cinfo.ci_mode, cinfo.ci_keyLen, &handle);
    if (alcp_is_error(err)) {
        free(handle.ch_context);
        printf("Error: unable to request \n");
        alcp_error_str(err, err_buf, err_size);
        return -1;
    }
    return 0;
}

/* GCM: Authenticated Encryption demo */
int
alcp_aes_gcm_encrypt_demo(
    const Uint8* plaintxt,
    const Uint32 len, /* Describes both 'plaintxt' and 'ciphertxt' */
    Uint8*       ciphertxt,
    Uint8*       iv,
    const Uint32 ivLen,
    Uint8*       ad,
    const Uint32 adLen,
    Uint8*       tag,
    const Uint32 tagLen,
    const Uint8* pKey,
    const Uint32 keyLen)
{
    alc_error_t err;
    const int   err_size = 256;
    Uint8       err_buf[err_size];

    // GCM init key
    err = alcp_cipher_aead_set_key(&handle, keyLen, pKey);
    if (alcp_is_error(err)) {
        printf("Error: unable gcm encrypt init \n");
        alcp_error_str(err, err_buf, err_size);
        return -1;
    }

    // GCM init iv
    err = alcp_cipher_aead_set_iv(&handle, ivLen, iv);
    if (alcp_is_error(err)) {
        printf("Error: unable gcm encrypt init \n");
        alcp_error_str(err, err_buf, err_size);
        return -1;
    }

    // Additional Data
    err = alcp_cipher_aead_set_aad(&handle, ad, adLen);
    if (alcp_is_error(err)) {
        printf("Error: unable gcm add data processing \n");
        alcp_error_str(err, err_buf, err_size);
        return -1;
    }

    // GCM encrypt
    err =
        alcp_cipher_aead_encrypt_update(&handle, plaintxt, ciphertxt, len, iv);
    if (alcp_is_error(err)) {
        printf("Error: unable encrypt \n");
        alcp_error_str(err, err_buf, err_size);
        return -1;
    }

    // get tag
    err = alcp_cipher_aead_get_tag(&handle, tag, tagLen);
    if (alcp_is_error(err)) {
        printf("Error: unable getting tag \n");
        alcp_error_str(err, err_buf, err_size);
        return -1;
    }
    return 0;
}

/* GCM: Authenticated Decryption demo */
int
alcp_aes_gcm_decrypt_demo(const Uint8* ciphertxt,
                          const Uint32 len,
                          Uint8*       plaintxt,
                          Uint8*       iv,
                          const Uint32 ivLen,
                          Uint8*       ad,
                          const Uint32 adLen,
                          Uint8*       tag,
                          const Uint32 tagLen)
{
    alc_error_t err;
    const int   err_size = 256;
    Uint8       err_buf[err_size];
    Uint8       tagDecrypt[16];

    // GCM init
    err = alcp_cipher_aead_set_iv(&handle, ivLen, iv);
    if (alcp_is_error(err)) {
        printf("Error: unable gcm encrypt init \n");
        alcp_error_str(err, err_buf, err_size);
        return -1;
    }

    // Additional Data
    err = alcp_cipher_aead_set_aad(&handle, ad, adLen);
    if (alcp_is_error(err)) {
        printf("Error: unable gcm add data processing \n");
        alcp_error_str(err, err_buf, err_size);
        return -1;
    }

    // GCM decrypt
    err =
        alcp_cipher_aead_decrypt_update(&handle, ciphertxt, plaintxt, len, iv);
    if (alcp_is_error(err)) {
        printf("Error: unable decrypt \n");
        alcp_error_str(err, err_buf, err_size);
        return -1;
    }

    // get tag
    err = alcp_cipher_aead_get_tag(&handle, tagDecrypt, tagLen);
    if (alcp_is_error(err)) {
        printf("Error: unable getting tag \n");
        alcp_error_str(err, err_buf, err_size);
        return -1;
    }

    bool isTagMatched = true;

    for (int i = 0; i < tagLen; i++) {
        if (tagDecrypt[i] != tag[i]) {
            isTagMatched = isTagMatched & false;
        }
    }

    if (isTagMatched == false) {
        // printf("\n tag mismatched, input encrypted data is not trusthworthy
        // ");
        memset(plaintxt, 0, len);
        return -1;
    }
    return 0;
}

/* Function takes input data from standard test vector for specific test number
 * & validates tag generated.*/
int
gcm_selftest(Uint8*            inputText,  // plaintext
             Uint32            inputLen,   // input length
             Uint8*            cipherText, // ciphertext output
             alc_cipher_mode_t m,
             int               i,
             Uint8             testNumber)
{
    int          retval = 0;
    unsigned int keybits;
    Uint8        key[32];
    int          ret = 0;
#if DEBUG_PRINT
    bool verboseprint = true;
#else
    bool verboseprint = false;
#endif
    memset(key, 0, 32);

    Uint8* outputText;
    outputText = malloc(inputLen);

    Uint8* iv;
    iv = malloc(128 * 4);
    memset(iv, 10, 128 * 4);

    Uint8* ref;
    ref = malloc(inputLen);
    memset(ref, 0, inputLen);

    Uint32 ivLen = 16;

    /* additional data, tag used in GCM */
    Uint32 adLen  = test_ad_len[testNumber];
    Uint32 tagLen = test_tag_len[testNumber];

    Uint8* ad = malloc(adLen);
    Uint8  tag[16];
    if (adLen) {
        memset(ad, 33, adLen);
    }
    memset(tag, 0, tagLen);

    printf("\n \t Test number %d", testNumber);

    int u   = i;
    keybits = 128 + u * 64;
    memset(key, ((i * 10) + m), 32);

    ivLen = test_iv_len[testNumber];
    memcpy(inputText, test_pt[testNumber], inputLen);
    memcpy(key, test_key[testNumber], 16);
    memcpy(iv, test_iv[testNumber], ivLen);
    memcpy(ad, test_ad[testNumber], adLen);

    memset(cipherText, 0, inputLen);

    memset(outputText, 0, inputLen);
    printText(key, 16, "key      ", verboseprint);
    printText(inputText, inputLen, "inputText", verboseprint);
    printText(iv, ivLen, "iv       ", verboseprint);
    printText(ad, adLen, "ad       ", verboseprint);

    create_aes_session(key, iv, keybits, m);

    // Encrypt
    retval = alcp_aes_gcm_encrypt_demo(inputText,
                                       inputLen,
                                       cipherText,
                                       iv,
                                       ivLen,
                                       ad,
                                       adLen,
                                       tag,
                                       tagLen,
                                       key,
                                       keybits);
    if (retval != 0)
        goto out;

    printf("\nGCM-Encrypt ");
    printText(cipherText, inputLen, "cipherTxt", verboseprint);
    printText(tag, tagLen, "tagEnc   ", verboseprint);
    if (memcmp(test_tag[testNumber], tag, (long unsigned int)tagLen) != 0) {
        printf("\n\t\t\t\t Encrypt Tag mismatch: Test FAILED \n");
    } else {
        printf("\t test PASSED ");
    }

    // Decrypt
    retval = alcp_aes_gcm_decrypt_demo(
        cipherText, inputLen, outputText, iv, ivLen, ad, adLen, tag, tagLen);
    if (retval != 0)
        goto out;

    printf("\nGCM-Decrypt ");
    printText(outputText, inputLen, "outputTxt", verboseprint);
    printText(tag, tagLen, "tagDec   ", verboseprint);
    if (memcmp(test_tag[testNumber], tag, (long unsigned int)tagLen) != 0) {
        printf("\n\t\t\t\t Encrypt Tag mismatch: Test FAILED \n");
        goto out;
    }
    if (memcmp(inputText, outputText, (long unsigned int)inputLen) != 0) {
        printf("\n\t\t\t\t input->enc->dec->input FAILED \n");
        goto out;
    } else {
        printf("\t test PASSED ");
    }

    /*
     * Complete the transaction
     */
    alcp_cipher_aead_finish(&handle);
    free(handle.ch_context);

    if (outputText) {
        free(outputText);
    }
    if (iv) {
        free(iv);
    }
    if (ref) {
        free(ref);
    }
    if (ad) {
        free(ad);
    }
    return 0;

out:
    return -1;
}

// Demo of GCM with std testor vectors
int
runGCMAutoTest()
{
    int    retval = 0;
    Uint8* inputText;
    Uint8* cipherText;

    /*
     * Auto test runs different GCM usages and validates its final tag with
     * standard test vector results.
     */

    printf("\n\n\n AOCL-CRYPTO: AES-GCM selftest ");

    int keySizeItr = 0;

    for (Uint8 testNumber = 0; testNumber < TEST_VECTOR_COUNT; testNumber++) {
        int inputLen = test_pt_len[testNumber];
        printf(" \n");

        // allocate inputText and cipherText memory
        inputText = malloc(inputLen);
        if (inputText == NULL) {
            return -1;
        }
        cipherText = malloc(inputLen);
        if (cipherText == NULL) {
            if (inputText) {
                free(inputText);
            }
            return -1;
        }

        // run full path demo for specific aes mode
        retval =
            gcm_selftest(inputText,
                         inputLen, /* len of both 'plaintxt' and 'ciphertxt' */
                         cipherText,
                         ALC_AES_MODE_GCM,
                         keySizeItr,
                         testNumber);
        if (retval != 0)
            return retval;

        // its time to free!
        if (inputText) {
            free(inputText);
        }
        if (cipherText) {
            free(cipherText);
        }
    }
    return 0;
}

int
main(void)
{
    // Run GCM auto test with standard test vector and match generated tag
    return runGCMAutoTest();
}