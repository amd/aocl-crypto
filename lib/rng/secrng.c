//====  Copyright (c) 2017 Advanced Micro Devices, Inc.  All rights reserved.
//
//               Developed by: Advanced Micro Devices, Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// with the Software without restriction, including without limitation the
// rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
// sell copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// Redistributions of source code must retain the above copyright notice, this
// list of conditions and the following disclaimers.
//
// Redistributions in binary form must reproduce the above copyright notice,
// this list of conditions and the following disclaimers in the documentation
// and/or other materials provided with the distribution.
//
// Neither the names of Advanced Micro Devices, Inc., nor the names of its
// contributors may be used to endorse or promote products derived from this
// Software without specific prior written permission.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// CONTRIBUTORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS WITH
// THE SOFTWARE.
//===----------------------------------------------------------------------===//

#include <stdio.h>
#include <x86intrin.h>

#include "secrng.h"

// Bit mask used to check ECX register value as returned by CPUId
// If RDRAND is supported, the 30th bit of ECX is set
#define RDRAND_MASK 0x40000000

// Bit mask used to check EBX register value as returned by CPUId
// If RDSEED is supported, the 18th bit of EBX is set
#define RDSEED_MASK 0x40000

#define SECRNG_INITIAL  99
#define MAX_RETRY_COUNT 10

#define __get_cpuid(level, a, b, c, d)                                         \
    __asm__("cpuid\n\t" : "=a"(a), "=b"(b), "=c"(c), "=d"(d) : "0"(level))

#define __get_cpuid_ext(level, count, a, b, c, d)                              \
    __asm__("cpuid\n\t"                                                        \
            : "=a"(a), "=b"(b), "=c"(c), "=d"(d)                               \
            : "0"(level), "2"(count))

int trdrand_status = SECRNG_INITIAL;
int trdseed_status = SECRNG_INITIAL;

int
is_RDRAND_supported()
{
    int ret = trdrand_status;

    if (ret == SECRNG_INITIAL) {
        int cpuinfo[4]  = { -1 };
        int function_id = 1; // Function number used for checking RDRAND

        // Call CPUId instruction : CPUID (functionnumber, EAX, EBX, ECX, EDX)
        __get_cpuid(
            function_id, cpuinfo[0], cpuinfo[1], cpuinfo[2], cpuinfo[3]);

        // EBX = cpuinfo[2]
        // Check for RDRAND support
        int is_rdrand_set = ((cpuinfo[2] & RDRAND_MASK) == RDRAND_MASK);

        if (is_rdrand_set)
            ret = SECRNG_SUPPORTED;
        else
            ret = SECRNG_NOT_SUPPORTED;

        trdrand_status = ret;
    }

    return ret;
}

int
is_RDSEED_supported()
{
    int ret = trdseed_status;

    if (ret == SECRNG_INITIAL) {
        int cpuinfo[4]  = { -1 };
        int function_id = 7; // Function number used for checking RDSEED

        // Call CPUId instruction : CPUID (functionnumber, sunfunctionnumber,
        // EAX, EBX, ECX, EDX)
        __get_cpuid_ext(
            function_id, 0, cpuinfo[0], cpuinfo[1], cpuinfo[2], cpuinfo[3]);

        // EBX = cpuinfo[1]
        // Check for RDSEED support
        int is_rdseed_set = ((cpuinfo[1] & RDSEED_MASK) == RDSEED_MASK);

        if (is_rdseed_set)
            ret = SECRNG_SUPPORTED;
        else
            ret = SECRNG_NOT_SUPPORTED;

        trdseed_status = ret;
    }

    return ret;
}

int
get_rdrand16u(uint16_t* rng_val, unsigned int retry_count)
{
    int ret = is_RDRAND_supported();

    // Check for valid input pointer
    if (!rng_val)
        return SECRNG_INVALID_INPUT;

    if (ret == SECRNG_SUPPORTED) {
        ret = SECRNG_FAILURE;

        // Invoke the rdrand intrinsic function
        if (_rdrand16_step(rng_val))
            ret = SECRNG_SUCCESS;
        else if (retry_count > 0) {
            // Check number of retries does not exceed the max limit
            retry_count = (retry_count > MAX_RETRY_COUNT) ? MAX_RETRY_COUNT
                                                          : retry_count;

            int i;
            for (i = 0; i < retry_count; i++) {
                if (_rdrand16_step(rng_val)) {
                    ret = SECRNG_SUCCESS;
                    break;
                }
            }
        }
    }

    return ret;
}

int
get_rdrand32u(uint32_t* rng_val, unsigned int retry_count)
{
    int ret = is_RDRAND_supported();

    // Check for valid input pointer
    if (!rng_val)
        return SECRNG_INVALID_INPUT;

    if (ret == SECRNG_SUPPORTED) {
        ret = SECRNG_FAILURE;

        // Invoke the rdrand intrinsic function
        if (_rdrand32_step(rng_val))
            ret = SECRNG_SUCCESS;
        else if (retry_count > 0) {
            // Check number of retries does not exceed the max limit
            retry_count = (retry_count > MAX_RETRY_COUNT) ? MAX_RETRY_COUNT
                                                          : retry_count;

            int i;
            for (i = 0; i < retry_count; i++) {
                if (_rdrand32_step(rng_val)) {
                    ret = SECRNG_SUCCESS;
                    break;
                }
            }
        }
    }

    return ret;
}

int
get_rdrand64u(uint64_t* rng_val, unsigned int retry_count)
{
    int ret = is_RDRAND_supported();

    // Check for valid input pointer
    if (!rng_val)
        return SECRNG_INVALID_INPUT;

    if (ret == SECRNG_SUPPORTED) {
        ret = SECRNG_FAILURE;

        unsigned long long* lrng_val = (unsigned long long*)rng_val;

        // Invoke the rdrand intrinsic function
        if (_rdrand64_step(lrng_val))
            ret = SECRNG_SUCCESS;
        else if (retry_count > 0) {
            // Check number of retries does not exceed the max limit
            retry_count = (retry_count > MAX_RETRY_COUNT) ? MAX_RETRY_COUNT
                                                          : retry_count;

            int i;
            for (i = 0; i < retry_count; i++) {
                if (_rdrand64_step(lrng_val)) {
                    ret = SECRNG_SUCCESS;
                    break;
                }
            }
        }
    }

    return ret;
}

int
get_rdrand32u_arr(uint32_t* rng_arr, unsigned int N, unsigned int retry_count)
{
    int ret = is_RDRAND_supported();

    // Check for valid input pointer
    if (!rng_arr)
        return SECRNG_INVALID_INPUT;

    if (ret == SECRNG_SUPPORTED) {
        ret = SECRNG_FAILURE;

        int i;
        for (i = 0; i < N; i++) {
            // Invoke the rdrand intrinsic function
            ret = get_rdrand32u(rng_arr, retry_count);

            if (ret != SECRNG_SUCCESS)
                break;

            rng_arr = rng_arr + 1;
        }
    }

    return ret;
}

int
get_rdrand64u_arr(uint64_t* rng_arr, unsigned int N, unsigned int retry_count)
{
    int ret = is_RDRAND_supported();

    // Check for valid input pointer
    if (!rng_arr)
        return SECRNG_INVALID_INPUT;

    if (ret == SECRNG_SUPPORTED) {
        ret = SECRNG_FAILURE;

        int i;
        for (i = 0; i < N; i++) {
            // Invoke the rdrand intrinsic function
            ret = get_rdrand64u(rng_arr, retry_count);

            if (ret != SECRNG_SUCCESS)
                break;

            rng_arr = rng_arr + 1;
        }
    }

    return ret;
}

int
get_rdrand_bytes_arr(unsigned char* rng_arr,
                     unsigned int   N,
                     unsigned int   retry_count)
{
    unsigned int numalignedbytes;
    unsigned int startbytes = 0;
    unsigned int endbytes   = 0;
    unsigned int alignedlength;

    uintptr_t* alignedstart;
    uintptr_t  temprnd;
    int        i;
    int        ret = is_RDRAND_supported();

    // Check for valid input pointer
    if (!rng_arr)
        return SECRNG_INVALID_INPUT;

    if (ret == SECRNG_SUPPORTED) {
        // Check whether the buffer is aligned as per the bitness (32/64 bit) of
        // the target machine
        int isaligned = (uintptr_t)rng_arr & (uintptr_t)(sizeof(uintptr_t) - 1);

        if (isaligned == 0) {
            alignedstart = (uintptr_t*)rng_arr;
        } else {
            // Memory not aligned

            // Get the next aligned memory address
            alignedstart = (uintptr_t*)((uintptr_t)rng_arr
                                        & ~((uintptr_t)(sizeof(uintptr_t) - 1))
                                              + (uintptr_t)sizeof(uintptr_t));
            // beginning unaligned bytes
            startbytes = (uintptr_t)rng_arr & (sizeof(uintptr_t) - 1);
        }

        // Check unaligned bytes at the end
        endbytes =
            ((uintptr_t)(rng_arr + N)) & (uintptr_t)(sizeof(uintptr_t) - 1);
        numalignedbytes = N - startbytes - endbytes;
        alignedlength   = numalignedbytes / sizeof(uintptr_t);

        // Fill the starting unaligned bytes
        if (startbytes > 0) {
#ifdef __x86_64__
            ret = get_rdrand64u((uint64_t*)&temprnd, retry_count);
#else
            ret = get_rdrand32u((uint32_t*)&temprnd, retry_count);
#endif
            if (ret != SECRNG_SUCCESS)
                return ret;

            for (i = 0; i < startbytes; i++) {
                rng_arr[i] = (unsigned char)(temprnd & 0xff);
                temprnd    = temprnd >> 8;
            }
        }

        // Fill the aligned bytes
#ifdef __x86_64__
        ret = get_rdrand64u_arr(
            (uint64_t*)alignedstart, alignedlength, retry_count);
#else
        ret = get_rdrand32u_arr(
            (uint32_t*)alignedstart, alignedlength, retry_count);
#endif
        if (ret != SECRNG_SUCCESS)
            return ret;

        // Fill the end residual unaligned bytes
        if (endbytes > 0) {
#ifdef __x86_64__
            ret = get_rdrand64u((uint64_t*)&temprnd, retry_count);
#else
            ret = get_rdrand32u((uint32_t*)&temprnd, retry_count);
#endif
            if (ret != SECRNG_SUCCESS)
                return ret;

            unsigned char* endblock =
                (unsigned char*)alignedstart + numalignedbytes;
            for (i = 0; i < endbytes; i++) {
                endblock[i] = (unsigned char)(temprnd & 0xff);
                temprnd     = temprnd >> 8;
            }
        }
    }

    return ret;
}

int
get_rdseed16u(uint16_t* rng_val, unsigned int retry_count)
{
    int ret = is_RDSEED_supported();

    // Check for valid input pointer
    if (!rng_val)
        return SECRNG_INVALID_INPUT;

    if (ret == SECRNG_SUPPORTED) {
        ret = SECRNG_FAILURE;

        // Invoke the rdseed intrinsic function
        if (_rdseed16_step(rng_val))
            ret = SECRNG_SUCCESS;
        else if (retry_count > 0) {
            // Check number of retries does not exceed the max limit
            retry_count = (retry_count > MAX_RETRY_COUNT) ? MAX_RETRY_COUNT
                                                          : retry_count;

            int i;
            for (i = 0; i < retry_count; i++) {
                if (_rdseed16_step(rng_val)) {
                    ret = SECRNG_SUCCESS;
                    break;
                }
            }
        }
    }

    return ret;
}

int
get_rdseed32u(uint32_t* rng_val, unsigned int retry_count)
{
    int ret = is_RDSEED_supported();

    // Check for valid input pointer
    if (!rng_val)
        return SECRNG_INVALID_INPUT;

    if (ret == SECRNG_SUPPORTED) {
        ret = SECRNG_FAILURE;

        // Invoke the rdseed intrinsic function
        if (_rdseed32_step(rng_val))
            ret = SECRNG_SUCCESS;
        else if (retry_count > 0) {
            // Check number of retries does not exceed the max limit
            retry_count = (retry_count > MAX_RETRY_COUNT) ? MAX_RETRY_COUNT
                                                          : retry_count;

            int i;
            for (i = 0; i < retry_count; i++) {
                if (_rdseed32_step(rng_val)) {
                    ret = SECRNG_SUCCESS;
                    break;
                }
            }
        }
    }

    return ret;
}

int
get_rdseed64u(uint64_t* rng_val, unsigned int retry_count)
{
    int ret = is_RDSEED_supported();

    // Check for valid input pointer
    if (!rng_val)
        return SECRNG_INVALID_INPUT;

    if (ret == SECRNG_SUPPORTED) {
        ret = SECRNG_FAILURE;

        unsigned long long* lrng_val = (unsigned long long*)rng_val;

        // Invoke the rdseed intrinsic function
        if (_rdseed64_step(lrng_val))
            ret = SECRNG_SUCCESS;
        else if (retry_count > 0) {
            // Check number of retries does not exceed the max limit
            retry_count = (retry_count > MAX_RETRY_COUNT) ? MAX_RETRY_COUNT
                                                          : retry_count;

            int i;
            for (i = 0; i < retry_count; i++) {
                if (_rdseed64_step(lrng_val)) {
                    ret = SECRNG_SUCCESS;
                    break;
                }
            }
        }
    }

    return ret;
}

int
get_rdseed32u_arr(uint32_t* rng_arr, unsigned int N, unsigned int retry_count)
{
    int ret = is_RDSEED_supported();

    // Check for valid input pointer
    if (!rng_arr)
        return SECRNG_INVALID_INPUT;

    if (ret == SECRNG_SUPPORTED) {
        ret = SECRNG_FAILURE;

        int i;
        for (i = 0; i < N; i++) {
            // Invoke the rdseed intrinsic function
            ret = get_rdseed32u(rng_arr, retry_count);

            if (ret != SECRNG_SUCCESS)
                break;

            rng_arr = rng_arr + 1;
        }
    }

    return ret;
}

int
get_rdseed64u_arr(uint64_t* rng_arr, unsigned int N, unsigned int retry_count)
{
    int ret = is_RDSEED_supported();

    // Check for valid input pointer
    if (!rng_arr)
        return SECRNG_INVALID_INPUT;

    if (ret == SECRNG_SUPPORTED) {
        ret = SECRNG_FAILURE;

        int i;
        for (i = 0; i < N; i++) {
            // Invoke the rdseed intrinsic function
            ret = get_rdseed64u(rng_arr, retry_count);

            if (ret != SECRNG_SUCCESS)
                break;

            rng_arr = rng_arr + 1;
        }
    }

    return ret;
}

int
get_rdseed_bytes_arr(unsigned char* rng_arr,
                     unsigned int   N,
                     unsigned int   retry_count)
{
    unsigned int numalignedbytes;
    unsigned int startbytes = 0;
    unsigned int endbytes   = 0;
    unsigned int alignedlength;

    uintptr_t* alignedstart;
    uintptr_t  temprnd;
    int        i;
    int        ret = is_RDSEED_supported();

    // Check for valid input pointer
    if (!rng_arr)
        return SECRNG_INVALID_INPUT;

    if (ret == SECRNG_SUPPORTED) {
        // Check whether the buffer is aligned as per the bitness (32/64 bit) of
        // the target machine
        int isaligned = (uintptr_t)rng_arr & (uintptr_t)(sizeof(uintptr_t) - 1);

        if (isaligned == 0) {
            alignedstart = (uintptr_t*)rng_arr;
        } else {
            // Memory not aligned

            // Get the next aligned memory address
            alignedstart = (uintptr_t*)((uintptr_t)rng_arr
                                        & ~((uintptr_t)(sizeof(uintptr_t) - 1))
                                              + (uintptr_t)sizeof(uintptr_t));
            // beginning unaligned bytes
            startbytes = (uintptr_t)rng_arr & (sizeof(uintptr_t) - 1);
        }

        // Check unaligned bytes at the end
        endbytes =
            ((uintptr_t)(rng_arr + N)) & (uintptr_t)(sizeof(uintptr_t) - 1);
        numalignedbytes = N - startbytes - endbytes;
        alignedlength   = numalignedbytes / sizeof(uintptr_t);

        // Fill the starting unaligned bytes
        if (startbytes > 0) {
#ifdef __x86_64__
            ret = get_rdseed64u((uint64_t*)&temprnd, retry_count);
#else
            ret = get_rdseed32u((uint32_t*)&temprnd, retry_count);
#endif
            if (ret != SECRNG_SUCCESS)
                return ret;

            for (i = 0; i < startbytes; i++) {
                rng_arr[i] = (unsigned char)(temprnd & 0xff);
                temprnd    = temprnd >> 8;
            }
        }

        // Fill the aligned bytes
#ifdef __x86_64__
        ret = get_rdseed64u_arr(
            (uint64_t*)alignedstart, alignedlength, retry_count);
#else
        ret = get_rdseed32u_arr(
            (uint32_t*)alignedstart, alignedlength, retry_count);
#endif
        if (ret != SECRNG_SUCCESS)
            return ret;

        // Fill the end residual unaligned bytes
        if (endbytes > 0) {
#ifdef __x86_64__
            ret = get_rdseed64u((uint64_t*)&temprnd, retry_count);
#else
            ret = get_rdseed32u((uint32_t*)&temprnd, retry_count);
#endif
            if (ret != SECRNG_SUCCESS)
                return ret;

            unsigned char* endblock =
                (unsigned char*)alignedstart + numalignedbytes;
            for (i = 0; i < endbytes; i++) {
                endblock[i] = (unsigned char)(temprnd & 0xff);
                temprnd     = temprnd >> 8;
            }
        }
    }

    return ret;
}
