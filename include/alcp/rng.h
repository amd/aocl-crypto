/*
 * Copyright (C) 2021-2026, Advanced Micro Devices. All rights reserved.
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
 * @enum alc_rng_type
 */
typedef enum alc_rng_type
{
    ALC_RNG_TYPE_INVALID = 0, /**< Invalid RNG type */
    ALC_RNG_TYPE_SIMPLE, /**< Simple RNG */
    ALC_RNG_TYPE_CONTINUOUS, /**< Continuous RNG */
    ALC_RNG_TYPE_DISCRETE, /**< Discrete RNG */

    ALC_RNG_TYPE_MAX, /**< Sentinel value for RNG type enumeration */
} alc_rng_type_t;

/**
 * @brief Store info about source of RNG used
 *
 * @enum alc_rng_source
 */
typedef enum alc_rng_source
{
    ALC_RNG_SOURCE_ALGO = 0, /**< Software CRNG/PRNG (default) */
    ALC_RNG_SOURCE_OS, /**< Operating system RNG */
    ALC_RNG_SOURCE_DEV, /**< Hardware device RNG */
    ALC_RNG_SOURCE_ARCH, /**< Architecture-specific RNG (e.g., RDRAND) */
    ALC_RNG_SOURCE_MAX, /**< Sentinel value for RNG source enumeration */
} alc_rng_source_t;

/**
 * @brief Store info about distribution used for RNG
 *
 * @enum alc_rng_distrib
 */
typedef enum alc_rng_distrib
{
    ALC_RNG_DISTRIB_UNKNOWN = 0, /**< Unknown distribution */

    ALC_RNG_DISTRIB_BETA, /**< Beta distribution */
    ALC_RNG_DISTRIB_CAUCHY, /**< Cauchy distribution */
    ALC_RNG_DISTRIB_CHISQUARE, /**< Chi-squared distribution */
    ALC_RNG_DISTRIB_DIRICHLET, /**< Dirichlet distribution */
    ALC_RNG_DISTRIB_EXPONENTIAL, /**< Exponential distribution */
    ALC_RNG_DISTRIB_GAMMA, /**< Gamma distribution */
    ALC_RNG_DISTRIB_GAUSSIAN, /**< Gaussian (normal) distribution */
    ALC_RNG_DISTRIB_GUMBEL, /**< Gumbel distribution */
    ALC_RNG_DISTRIB_LAPLACE, /**< Laplace distribution */
    ALC_RNG_DISTRIB_LOGISTIC, /**< Logistic distribution */
    ALC_RNG_DISTRIB_LOGNORMAL, /**< Log-normal distribution */
    ALC_RNG_DISTRIB_PARETO, /**< Pareto distribution */
    ALC_RNG_DISTRIB_RAYLEIGH, /**< Rayleigh distribution */
    ALC_RNG_DISTRIB_UNIFORM, /**< Uniform distribution */
    ALC_RNG_DISTRIB_VONMISES, /**< Von Mises distribution */
    ALC_RNG_DISTRIB_WEIBULL, /**< Weibull distribution */
    ALC_RNG_DISTRIB_WALD, /**< Wald (inverse Gaussian) distribution */
    ALC_RNG_DISTRIB_ZIPF, /**< Zipf distribution */

    ALC_RNG_DISTRIB_BERNOULLI, /**< Bernoulli distribution */
    ALC_RNG_DISTRIB_BINOMIAL, /**< Binomial distribution */
    ALC_RNG_DISTRIB_GEOMETRIC, /**< Geometric distribution */
    ALC_RNG_DISTRIB_HYPERGEOMETRIC, /**< Hypergeometric distribution */
    ALC_RNG_DISTRIB_MULTINOMIAL, /**< Multinomial distribution */
    ALC_RNG_DISTRIB_NEGBINOMIAL, /**< Negative binomial distribution */
    ALC_RNG_DISTRIB_POISSON, /**< Poisson distribution */
    ALC_RNG_DISTRIB_UNIFORM_BITS, /**< Uniform bits distribution */

    ALC_RNG_DISTRIB_MAX, /**< Sentinel value for distribution enumeration */
} alc_rng_distrib_t;

/**
 * @brief Store info about algorithm used for RNG
 *
 * @enum alc_rng_algo_flags
 */
typedef enum alc_rng_algo_flags
{
    ALC_RNG_FLAG_DUMMY, /**< Placeholder flag */
} alc_rng_algo_flags_t;

/**
 * @brief Store info about RNG
 *
 * @param ri_type Store info about type of RNG used
 * @param ri_source Store info about source of RNG used
 * @param ri_distrib Store info about distribution used for RNG
 * @param ri_flags Store info about algorithm used for RNG
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
 * @brief Handle for maintaining session.
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
 * @return   ALC_ERROR_NONE on success.
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
 * @return  Uint64      Size of RNG context in bytes. For APIs that return
 * alc_error_t, use @ref alcp_is_error to check for errors.
 */
ALCP_API_EXPORT Uint64
alcp_rng_context_size(const alc_rng_info_p pRngInfo);

/**
 * @brief       Request an handle for given RNG configuration
 * @parblock <br> &nbsp;
 * <b>This API can be called after @ref alcp_rng_supported and before @ref
 * alcp_rng_finish</b>
 * @endparblock
 * @note       Requested algorithm may be first checked using
 *             @ref alcp_rng_supported and pHandle as allocated by user.
 *
 * @param [in]      pRngInfo        Pointer to RNG configuration
 * @param [out]      pRngHandle      Library populated session handle for future
 * rng operations.
 * @return   ALC_ERROR_NONE on success.
 */
ALCP_API_EXPORT alc_error_t
alcp_rng_request(const alc_rng_info_p pRngInfo, alc_rng_handle_p pRngHandle);

/**
 * @brief   Generate and fill buffer with random numbers
 * @parblock <br> &nbsp;
 * <b>This API can be called after @ref alcp_rng_request and @ref alcp_rng_init
 * if hardware RNG requires it and before @ref alcp_rng_finish</b>
 * @endparblock
 *
 * @param [in]  pRngHandle  Pointer to handle
 * @param [out] pBuf        Output buffer to be filled with random numbers
 * @param [in]  size        Size of pBuf in bytes
 *
 * @return   ALC_ERROR_NONE on success.
 */
ALCP_API_EXPORT alc_error_t
alcp_rng_gen_random(alc_rng_handle_p pRngHandle,
                    Uint8*           pBuf, /* RNG output buffer */
                    Uint64           size  /* output buffer size */
);

/**
 * @brief       Initialize a random number generator
 * @parblock <br> &nbsp;
 * <b>This API can be called after @ref alcp_rng_request and before @ref
 * alcp_rng_finish</b>
 * @endparblock
 * @note       Some hardware RNGs require initialization
 *
 * @param [in]  pRngHandle      Pointer to handle returned by alcp_rng_request()
 * @return   ALC_ERROR_NONE on success.
 */
ALCP_API_EXPORT alc_error_t
alcp_rng_init(alc_rng_handle_p pRngHandle);

/**
 * @brief   Complete a session
 * @parblock <br> &nbsp;
 * <b>This API is called to free resources so should be called to free the
 * session</b>
 * @endparblock
 * @note   Completes the session which was previously requested using
 *              @ref alcp_rng_request
 *
 * @param [in]  pRngHandle      Pointer to handle
 * @return   ALC_ERROR_NONE on success.
 */
ALCP_API_EXPORT alc_error_t
alcp_rng_finish(alc_rng_handle_p pRngHandle);

EXTERN_C_END

#endif
/**
 * @}
 */
