/*
 * Copyright (C) 2019-2021, Advanced Micro Devices. All rights reserved.
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

#ifndef __RNG_H
#define __RNG_H
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

typedef enum
{
    ALC_DUMMY_FLAG,
} alc_rng_algo_flags_t;

typedef struct
{
    alc_rng_type_t       r_type;
    alc_rng_source_t     r_source;
    alc_rng_distrib_t    r_distrib;
    alc_rng_algo_flags_t r_flags;
} alc_rng_info_t;

typedef struct
{
    void* ctx;
} alc_rng_handle_t;

uint64_t
alcp_rng_context_size(const alc_rng_info_t rng_info);

alc_error_t
alcp_rng_supported(const alc_rng_info_t* tt);

alc_error_t
alcp_rng_request(const alc_rng_info_t* tt, alc_rng_handle_t* cntxt);

alc_error_t
alcp_rng_gen_random(alc_rng_handle_t* tt,
                    uint8_t*          buf, /* RNG output buffer */
                    uint64_t          size /* output buffer size */
);

alc_error_t
alcp_rng_finish(alc_rng_handle_t* tt);

EXTERN_C_END
#endif