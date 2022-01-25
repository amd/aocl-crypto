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

#ifndef secrng_h
#define secrng_h

#include <stdint.h>

#define SECRNG_SUCCESS       2
#define SECRNG_SUPPORTED     1
#define SECRNG_NOT_SUPPORTED -1
#define SECRNG_FAILURE       -2
#define SECRNG_INVALID_INPUT -3

#ifdef __cplusplus
extern "C"
{
#endif
    /*! \brief Checks support for RDRAND instruction
     * This function checks if the target architecture supports RDRAND
     * instruction
     *
     * \return Value indicating whether RDRAND is suuported or not. 1 - Success
     */
    int is_RDRAND_supported();

    /*! \brief Checks support for RDSEED instruction
     * This function checks if the target architecture supports RDSEED
     * instruction
     *
     * \return Value indicating whether RDSEED is suuported or not. 1 - Success
     */
    int is_RDSEED_supported();

    /*! \brief Returns a single 16-bit value using RDRAND
     *
     * This function invokes RDRAND instruction to fetch a single 16-bit value.
     * On success, the value returned by RDRAND is written to rng_val. On
     * failure, the function retries invoking RDRAND retry_count times. Any
     * failure after this, the function will return error.
     *
     * \param rng_val Pointer to memory to store the value returned by RDRAND
     * \param retry_count Number of retry attempts
     * \return success ot failure status of function call: SECRNG_SUCCESS,
     * SECRNG_FAILURE, SECRNG_NOTSUPPORTED
     */
    int get_rdrand16u(uint16_t* rng_val, unsigned int retry_count);

    /*! \brief Returns a single 16-bit value using RDSEED
     *
     * This function invokes RDSEED instruction to fetch a single 16-bit value.
     * On success, the value returned by RDSEED is written to rng_val. On
     * failure, the function retries invoking RDSEED retry_count times. Any
     * failure after this, the function will return error.
     *
     * \param rng_val Pointer to memory to store the value returned by RDSEED
     * \param retry_count Number of retry attempts
     * \return success ot failure status of function call: SECRNG_SUCCESS,
     * SECRNG_FAILURE, SECRNG_NOTSUPPORTED
     */
    int get_rdseed16u(uint16_t* rng_val, unsigned int retry_count);

    /*! \brief Returns a single 32-bit value using RDRAND
     *
     * This function invokes RDRAND instruction to fetch a single 32-bit value.
     * On success, the value returned by RDRAND is written to rng_val. On
     * failure, the function retries invoking RDRAND retry_count times. Any
     * failure after this, the function will return error.
     *
     * \param rng_val Pointer to memory to store the value returned by RDRAND
     * \param retry_count Number of retry attempts
     * \return success ot failure status of function call: SECRNG_SUCCESS,
     * SECRNG_FAILURE, SECRNG_NOTSUPPORTED
     */
    int get_rdrand32u(uint32_t* rng_val, unsigned int retry_count);

    /*! \brief Returns a single 32-bit value using RDSEED
     *
     * This function invokes RDSEED instruction to fetch a single 32-bit value.
     * On success, the value returned by RDSEED is written to rng_val. On
     * failure, the function retries invoking RDSEED retry_count times. Any
     * failure after this, the function will return error.
     *
     * \param rng_val Pointer to memory to store the value returned by RDSEED
     * \param retry_count Number of retry attempts
     * \return success ot failure status of function call: SECRNG_SUCCESS,
     * SECRNG_FAILURE, SECRNG_NOTSUPPORTED
     */
    int get_rdseed32u(uint32_t* rng_val, unsigned int retry_count);

    /*! \brief Returns a single 64-bit value using RDRAND
     *
     * This function invokes RDRAND instruction to fetch a single 64-bit value.
     * On success, the value returned by RDRAND is written to rng_val. On
     * failure, the function retries invoking RDRAND retry_count times. Any
     * failure after this, the function will return error.
     *
     * \param rng_val Pointer to memory to store the value returned by RDRAND
     * \param retry_count Number of retry attempts
     * \return success ot failure status of function call: SECRNG_SUCCESS,
     * SECRNG_FAILURE, SECRNG_NOTSUPPORTED
     */
    int get_rdrand64u(uint64_t* rng_val, unsigned int retry_count);

    /*! \brief Returns a single 64-bit value using RDSEED
     *
     * This function invokes RDSEED instruction to fetch a single 64-bit value.
     * On success, the value returned by RDSEED is written to rng_val. On
     * failure, the function retries invoking RDSEED retry_count times. Any
     * failure after this, the function will return error.
     *
     * \param rng_val Pointer to memory to store the value returned by RDSEED
     * \param retry_count Number of retry attempts
     * \return success ot failure status of function call: SECRNG_SUCCESS,
     * SECRNG_FAILURE, SECRNG_NOTSUPPORTED
     */
    int get_rdseed64u(uint64_t* rng_val, unsigned int retry_count);

    /*! \brief Returns an array of 32-bit values using RDRAND
     *
     * This function invokes RDRAND instruction N times to fetch an array of
     * 32-bit values. On success, the values are written to rng_arr. On each
     * failure, the function retries invoking RDRAND retry_count times. Any
     * failure after this, the function will return error.
     *
     * \param rng_arr Pointer to memory to store the values returned by RDRAND
     * \param N Number of random values to return
     * \param retry_count Number of retry attempts
     * \return success or failure status of function call: SECRNG_SUCCESS,
     * SECRNG_FAILURE, SECRNG_NOTSUPPORTED
     */
    int get_rdrand32u_arr(uint32_t*    rng_arr,
                          unsigned int N,
                          unsigned int retry_count);

    /*! \brief Returns an array of 32-bit values using RDSEED
     *
     * This function invokes RDSEED instruction N times to fetch an array of
     * 32-bit values. On success, the values are written to rng_arr. On each
     * failure, the function retries invoking RDSEED retry_count times. Any
     * failure after this, the function will return error.
     *
     * \param rng_arr Pointer to memory to store the values returned by RDSEED
     * \param N Number of random values to return
     * \param retry_count Number of retry attempts
     * \return success or failure status of function call: SECRNG_SUCCESS,
     * SECRNG_FAILURE, SECRNG_NOTSUPPORTED
     */
    int get_rdseed32u_arr(uint32_t*    rng_arr,
                          unsigned int N,
                          unsigned int retry_count);

    /*! \brief Returns an array of 64-bit values using RDRAND
     *
     * This function invokes RDRAND instruction N times to fetch an array of
     * 64-bit values. On success, the values are written to rng_arr. On each
     * failure, the function retries invoking RDRAND retry_count times. Any
     * failure after this, the function will return error.
     *
     * \param rng_arr Pointer to memory to store the values returned by RDRAND
     * \param N Number of random values to return
     * \param retry_count Number of retry attempts
     * \return success or failure status of function call: SECRNG_SUCCESS,
     * SECRNG_FAILURE, SECRNG_NOTSUPPORTED
     */
    int get_rdrand64u_arr(uint64_t*    rng_arr,
                          unsigned int N,
                          unsigned int retry_count);

    /*! \brief Returns an array of 64-bit values using RDSEED
     *
     * This function invokes RDSEED instruction N times to fetch an array of
     * 64-bit values. On success, the values are written to rng_arr. On each
     * failure, the function retries invoking RDSEED retry_count times. Any
     * failure after this, the function will return error.
     *
     * \param rng_arr Pointer to memory to store the values returned by RDSEED
     * \param N Number of random values to return
     * \param retry_count Number of retry attempts
     * \return success or failure status of function call: SECRNG_SUCCESS,
     * SECRNG_FAILURE, SECRNG_NOTSUPPORTED
     */
    int get_rdseed64u_arr(uint64_t*    rng_arr,
                          unsigned int N,
                          unsigned int retry_count);

    /*! \brief Returns an array of random bytes of the given size using RDRAND
     *
     * This function invokes RDRAND instruction multiple times to fetch an array
     * of random bytes of given size. On success, the values are written to
     * rng_arr. On failure, it returns error.
     *
     * \param rng_arr Pointer to memory to store the random  bytes
     * \param N Number of random bytes to return
     * \param retry_count Number of retry attempts
     * \return success or failure status of function call: SECRNG_SUCCESS,
     * SECRNG_FAILURE, SECRNG_NOTSUPPORTED
     */
    int get_rdrand_bytes_arr(unsigned char* rng_arr,
                             unsigned int   N,
                             unsigned int   retry_count);

    /*! \brief Returns an array of random bytes of the given size using RDSEED
     *
     * This function invokes RDSEED instruction multiple times to fetch an array
     * of random bytes of given size. On success, the values are written to
     * rng_arr. On failure, it returns error.
     *
     * \param rng_arr Pointer to memory to store the random  bytes
     * \param N Number of random bytes to return
     * \param retry_count Number of retry attempts
     * \return success or failure status of function call: SECRNG_SUCCESS,
     * SECRNG_FAILURE, SECRNG_NOTSUPPORTED
     */
    int get_rdseed_bytes_arr(unsigned char* rng_arr,
                             unsigned int   N,
                             unsigned int   retry_count);

#endif

#ifdef __cplusplus
}
#endif