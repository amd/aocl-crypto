/*
 * Copyright (C) 2019-2023, Advanced Micro Devices. All rights reserved.
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

#ifndef _ALCP_RNG_H_
#define _ALCP_RNG_H_ 2

#include "error.h"
#include <alcp/macros.h>
#include <stdint.h>

/**
 * @defgroup rng RNG API
 * @brief
 * Random number generation is a crucial component of cryptography, used to
 * create keys and prevent attackers from predicting or replicating patterns in
 * data. It is typically implemented using specialized algorithms or hardware.
 * @{
 */

EXTERN_C_BEGIN

/**
 * @brief Store info about type of RNG used
 *
 * @typedef enum alc_rng_type_t
 */
typedef enum
{
    ALC_RNG_TYPE_INVALID = 0,
    ALC_RNG_TYPE_SIMPLE,
    ALC_RNG_TYPE_CONTINUOUS,
    ALC_RNG_TYPE_DESCRETE,

    ALC_RNG_TYPE_MAX,
} alc_rng_type_t;

/**
 * @brief Store info about source of RNG used
 *
 * @typedef enum alc_rng_source_t
 */
typedef enum
{
    ALC_RNG_SOURCE_ALGO = 0, /* Default: select software CRNG/PRNG */
    ALC_RNG_SOURCE_OS,       /* Use the operating system based support */
    ALC_RNG_SOURCE_DEV,      /* Device based off-loading support */
    ALC_RNG_SOURCE_ARCH,     /* Architecture specific source */
    ALC_RNG_SOURCE_MAX,
} alc_rng_source_t;

/**
 * @brief Store info about distribution used for RNG
 *
 * @typedef enum alc_rng_distrib_t
 */
typedef enum
{
    ALC_RNG_DISTRIB_UNKNOWN = 0,

    ALC_RNG_DISTRIB_BETA,
    ALC_RNG_DISTRIB_CAUCHY,
    ALC_RNG_DISTRIB_CHISQUARE,
    ALC_RNG_DISTRIB_DIRICHLET,
    ALC_RNG_DISTRIB_EXPONENTIAL,
    ALC_RNG_DISTRIB_GAMMA,
    ALC_RNG_DISTRIB_GAUSSIAN,
    ALC_RNG_DISTRIB_GUMBEL,
    ALC_RNG_DISTRIB_LAPLACE,
    ALC_RNG_DISTRIB_LOGISTIC,
    ALC_RNG_DISTRIB_LOGNORMAL,
    ALC_RNG_DISTRIB_PARETO,
    ALC_RNG_DISTRIB_RAYLEIGH,
    ALC_RNG_DISTRIB_UNIFORM,
    ALC_RNG_DISTRIB_VONMISES,
    ALC_RNG_DISTRIB_WEIBULL,
    ALC_RNG_DISTRIB_WALD,
    ALC_RNG_DISTRIB_ZIPF,

    ALC_RNG_DISTRIB_BERNOULLI,
    ALC_RNG_DISTRIB_BINOMIAL,
    ALC_RNG_DISTRIB_GEOMETRIC,
    ALC_RNG_DISTRIB_HYPERGEOMETRIC,
    ALC_RNG_DISTRIB_MULTINOMIAL,
    ALC_RNG_DISTRIB_NEGBINOMIAL,
    ALC_RNG_DISTRIB_POISSON,
    ALC_RNG_DISTRIB_UNIFORM_BITS,

    ALC_RNG_DISTRIB_MAX,
} alc_rng_distrib_t;

/**
 * @brief Store info about algorithm used for RNG
 *
 * @typedef enum alc_rng_algo_flags_t
 */
typedef enum _alc_rng_algo_flags
{
    ALC_RNG_FLAG_DUMMY,
} alc_rng_algo_flags_t;

/**
 * @brief Store info about RNG
 *
 * @param ri_type Store info about type of RNG used
 * @param ri_source Store info about source of RNG used
 * @param ri_distrib Store info about distribution used for RNG
 * @param ri_flagsStore info about algorithm used for RNG
 *
 * @struct alc_rng_info_t
 */
typedef struct _alc_rng_info
{
    alc_rng_type_t       ri_type;
    alc_rng_source_t     ri_source;
    alc_rng_distrib_t    ri_distrib;
    alc_rng_algo_flags_t ri_flags;
} alc_rng_info_t, *alc_rng_info_p;

/**
 *
 * @brief Handler used for rng context handling
 *
 * @param rh_context pointer to the context of the rng
 *
 * @struct alc_rng_handle_t
 *
 */
typedef struct
{
    void* rh_context;
} alc_rng_handle_t, *alc_rng_handle_p, AlcRngHandle, *AlcRngHandleP;

/**
 * @brief   Query Library if the given configuration is supported
 * @parblock <br> &nbsp;
 * <b>This API needs to be called before any other API is called to
 * know if RNG that is being request is supported or not </b>
 * @endparblock
 * @param [in]  pRngInfo      Pointer to alc_rng_info_t structure
 *
 * @return   &nbsp; Error Code for the API called . if alc_error_t
 * is not zero then @ref alcp_rng_error or @ref alcp_error_str needs to be
 * called to know about error occurred
 */
ALCP_API_EXPORT alc_error_t
alcp_rng_supported(const alc_rng_info_p pRngInfo);

/**
 * @brief   Get the context/session size
 * @parblock <br> &nbsp;
 * <b>This API should be called before @ref alcp_rng_request to identify the
 * memory to be allocated for context </b>
 * @endparblock
 * @note       User is expected to allocate for the session
 *               this function returns size to be allocated
 *
 * @param [in]  pRngInfo    Pointer to RNG configuration
 *
 * @return  Uint64      Size of Rng Context
 */
ALCP_API_EXPORT Uint64
alcp_rng_context_size(const alc_rng_info_p pRngInfo);

/**
 * @brief       Request an handle for given RNG configuration
 * @parblock <br> &nbsp;
 * <b>This API can be called after @ref alcp_rng_supported is called and at the
 * end of session call @ref alcp_rng_finish</b>
 * @endparblock
 * @note       Requested algorithm may be first checked using
 *             @ref alcp_rng_context_size and pHandle as allocated by user.
 *
 * @param [in]      pRngInfo        Pointer to RNG configuration
 * @param [in]      pRngHandle      Pointer to user allocated session
 * @return   &nbsp; Error Code for the API called . if alc_error_t
 * is not zero then @ref alcp_rng_error or @ref alcp_error_str needs to be
 * called to know about error occurred
 */
ALCP_API_EXPORT alc_error_t
alcp_rng_request(const alc_rng_info_p pRngInfo, alc_rng_handle_p pRngHandle);

/**
 * @brief   Generate and fill buffer with random numbers
 * @parblock <br> &nbsp;
 * <b>This API can be called after @ref alcp_rng_request and @ref alcp_rng_init
 * if hardware RNG requires it and at the end of session call @ref
 * alcp_rng_finish</b>
 * @endparblock
 *
 * @param [in]  pRngHandle  Pointer to Handle
 * @param [out]  pBuf        Pointer buffer that needs to be filled with random
 *                      numbers
 * @param [in]  size        size of pBuf
 *
 * @return   &nbsp; Error Code for the API called . if alc_error_t
 * is not zero then @ref alcp_rng_error or @ref alcp_error_str needs to be
 * called to know about error occurred
 */
ALCP_API_EXPORT alc_error_t
alcp_rng_gen_random(alc_rng_handle_p pRngHandle,
                    Uint8*           pBuf, /* RNG output buffer */
                    Uint64           size  /* output buffer size */
);

/**
 * @brief       Initialize a random number generator
 * @parblock <br> &nbsp;
 * <b>This API can be called after @ref alcp_rng_request and at the end of
 * session call @ref alcp_rng_finish</b>
 * @endparblock
 * @note       Some hardware RNGs require initialization
 *
 * @param [in]  pRngHandle      Pointer to handle returned in alcp_rng_request()
 * @return   &nbsp; Error Code for the API called . if alc_error_t
 * is not zero then @ref alcp_rng_error or @ref alcp_error_str needs to be
 * called to know about error occurred
 *
 */
ALCP_API_EXPORT alc_error_t
alcp_rng_init(alc_rng_handle_p pRngHandle);

/**
 * @brief   Seed a PRNG or other if supported
 *
 * @parblock <br> &nbsp;
 * <b>This API can be called after @ref alcp_rng_request and @ref alcp_rng_init
 * if hardware RNG requires it  * <b>This API is called to reset data so should
 * be called after @ref alcp_rng_request and at the end of session call @ref
 * alcp_rng_finish</b>
 * @endparblock</b>
 * @endparblock
 *
 * @param [in]  pRngHandle     Pointer to user allocated handle
 * @param [in]  seed           Pointer to seed
 * @param [in]  size           Length of seed in bytes
 *
 * @return   &nbsp; Error Code for the API called . if alc_error_t
 * is not zero then @ref alcp_rng_error or @ref alcp_error_str needs to be
 * called to know about error occurred
 */
ALCP_API_EXPORT alc_error_t
alcp_rng_seed(alc_rng_handle_p pRngHandle, const Uint8* seed, Uint64 size);

/**
 * @brief   Complete a session
 * @parblock <br> &nbsp;
 * @parblock <br> &nbsp;
 * <b>This API is called to free resources so should be called to free the
 * session</b>
 * @endparblock
 * @note   Completes the session which was previously requested using
 *              alcp_rng_request()
 *
 * @param [in]  pRngHandle      Pointer to handle
 * @return   &nbsp; Error Code for the API called . if alc_error_t
 * is not zero then @ref alcp_rng_error or @ref alcp_error_str needs to be
 * called to know about error occurred
 */
ALCP_API_EXPORT alc_error_t
alcp_rng_finish(alc_rng_handle_p pRngHandle);

/**
 * @brief              Get the error string for errors occurring in RNG
 *                     operations
 * @parblock <br> &nbsp;
 * <b> This API is called to get the error string. It should be called after
 * @ref alcp_rng_request and before @ref alcp_rng_finish </b>
 * @param [in] pRngHandle Session handle for RNG operation
 * @param [out] pBuff  Destination Buffer to which Error String will be copied
 * @param [in] size    Length of the Buffer.
 *
 * @return alc_error_t Error code to validate the Handle
 */
ALCP_API_EXPORT alc_error_t
alcp_rng_error(alc_rng_handle_p pRngHandle, Uint8* pBuff, Uint64 size);

EXTERN_C_END

#endif
/**
 * @}
 */