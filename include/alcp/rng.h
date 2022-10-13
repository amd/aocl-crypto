/*
 * Copyright (C) 2019-2022, Advanced Micro Devices. All rights reserved.
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

EXTERN_C_BEGIN

typedef enum
{
    ALC_RNG_TYPE_INVALID = 0,
    ALC_RNG_TYPE_SIMPLE,
    ALC_RNG_TYPE_CONTINUOUS,
    ALC_RNG_TYPE_DESCRETE,

    ALC_RNG_TYPE_MAX,
} alc_rng_type_t;

typedef enum
{
    ALC_RNG_SOURCE_ALGO = 0, /* Default: select software CRNG/PRNG */
    ALC_RNG_SOURCE_OS,       /* Use the operating system based support */
    ALC_RNG_SOURCE_DEV,      /* Device based off-loading support */
    ALC_RNG_SOURCE_ARCH,     /* Architecture specific source */
    ALC_RNG_SOURCE_MAX,
} alc_rng_source_t;

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

typedef enum _alc_rng_algo_flags
{
    ALC_RNG_FLAG_DUMMY,
} alc_rng_algo_flags_t;

typedef struct _alc_rng_info
{
    alc_rng_type_t       ri_type;
    alc_rng_source_t     ri_source;
    alc_rng_distrib_t    ri_distrib;
    alc_rng_algo_flags_t ri_flags;
} alc_rng_info_t, *alc_rng_info_p;

typedef struct
{
    void* rh_context;
} alc_rng_handle_t, *alc_rng_handle_p, AlcRngHandle, *AlcRngHandleP;

/**
 * \brief   Query Library if the given configuration is supported
 * \notes
 *
 * \param   pRngInfo      Pointer to alc_rng_info_t structure
 *
 * \return  alc_error_t     Error code
 */
alc_error_t
alcp_rng_supported(const alc_rng_info_p pRngInfo);

/**
 * \brief   Get the context/session size
 *
 * \notes       User is expected to allocate for the session
 *               this function returns size to be allocated
 *
 * \param   pRngInfo    Pointer to RNG configuration
 *
 * \return  Uint64      Size of Rng Context
 */
Uint64
alcp_rng_context_size(const alc_rng_info_p pRngInfo);

/**
 * \brief       Request an handle for given RNG configuration
 * \notes       Requested algorithm may be first checked using
 *              alcp_rng_context_size() and pHandle as allocated by user.
 *
 * \param       pRngInfo        Pointer to RNG configuration
 * \param       pRngHandle      Pointer to user allocated session
 * \return      alc_error_t     Error code
 */
alc_error_t
alcp_rng_request(const alc_rng_info_p pRngInfo, alc_rng_handle_p pRngHandle);

/**
 * \brief   Generate and fill buffer with random numbers
 * \notes
 *
 * \param   pRngHandle  Pointer to Handle
 * \param   pBuf        Pointer buffer that needs to be filled with random
 *                      numbers
 * \param   size        size of pBuf
 *
 * \return  alc_error_t     Error code
 */
alc_error_t
alcp_rng_gen_random(alc_rng_handle_p pRngHandle,
                    Uint8*           pBuf, /* RNG output buffer */
                    Uint64           size  /* output buffer size */
);

/**
 * \brief       Initialize a random number generator
 *
 * \notes       Some hardware RNGs require initialization
 *
 * \param   rng_handle      Pointer to handle returned in alcp_rng_request()
 * \return  alc_error_t     Error code
 *
 */
alc_error_t
alcp_rng_init(alc_rng_handle_p pRngHandle);

/**
 * \brief   Seed a PRNG or other if supported
 *
 * \notes
 *
 * \param   rng_handle     Pointer to user allocated handle
 * \param   seed           Pointer to seed
 * \param   size           Length of seed in bytes
 *
 * \return  alc_error_t     Error code, usually ALC_ERROR_NONE
 */
alc_error_t
alcp_rng_seed(alc_rng_handle_p pRngHandle, const Uint8* seed, Uint64 size);

/**
 * \brief   Complete a session
 *
 * \notes   Completes the session which was previously requested using
 *              alcp_rng_request()
 *
 * \param   rng_handle      Pointer to handle
 * \return  alc_error_t     Error code
 */
alc_error_t
alcp_rng_finish(alc_rng_handle_p pRngHandle);

EXTERN_C_END

#endif
