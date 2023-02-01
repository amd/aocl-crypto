/*
 * Copyright (C) 2022-2023, Advanced Micro Devices. All rights reserved.
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
#ifndef _ALCP_EC_H_
#define _ALCP_EC_H_ 2

#include <stdint.h>

#include "alcp/error.h"
#include "alcp/macros.h"

EXTERN_C_BEGIN

// FIXME: modifty the macro a equation based.
#define ALC_MAX_EC_PRECISION_IN_64BITS 9

typedef enum
{
    ALCP_EC_CURVE25519 = 0,
    ALCP_EC_SECP256R1,
    ALCP_EC_MAX,
} alc_ec_curve_id;

typedef enum
{
    ALCP_EC_CURVE_TYPE_SHORT_WEIERSTRASS = 0,
    ALCP_EC_CURVE_TYPE_MONTGOMERY,
    ALCP_EC_CURVE_TYPE_MAX
} alc_ec_curve_type;

typedef enum
{
    ALCP_EC_POINT_FORMAT_UNCOMPRESSED = 0,
    ALCP_EC_POINT_FORMAT_COMPRESSED,
} alc_ec_point_format_id;

typedef struct alc_ec_info
{
    alc_ec_curve_id        ecCurveId;
    alc_ec_curve_type      ecCurveType;
    alc_ec_point_format_id ecPointFormat;

} alc_ec_info_t, *alc_ec_info_p;

/**
 * \brief
 *
 * \notes
 */
typedef void              alc_ec_context_t;
typedef alc_ec_context_t* alc_ec_context_p;

/**
 * \brief
 * \notes
 */
typedef struct _alc_ec_handle
{
    alc_ec_context_p context;
} alc_ec_handle_t, *alc_ec_handle_p, AlcEcHandle, *AlcEcHandleP;

/**
 * \brief       Returns the context size of the interaction
 *
 * \notes       alcp_ec_supported() should be called first to
 *              know if the given curveType is valid.
 *
 * \param       p_ec_info   Description of the requested ec session
 *
 * \return      size > 0    if valid session is found, size otherwise
 */
ALCP_API_EXPORT Uint64
alcp_ec_context_size(const alc_ec_info_p p_ec_info);

/**
 * \brief       Allows to check if a given algorithm is supported
 *
 * \notes       alcp_ec_supported() should be called
 *              know if the given curveType and configuration is valid.
 *
 * \param       pEcInfo Description of the requested ec session
 *
 * \return      size > 0 if valid session is found, size otherwise
 */
ALCP_API_EXPORT alc_error_t
alcp_ec_supported(const alc_ec_info_p pEcInfo);

/**
 * \brief       Request a handle for ec  for a configuration
 *              as pointed by p_ec_info_p
 * \notes       alcp_ec_supported() should be called first to
 *              know if the given curveType is valid.
 *
 * \param       pEcInfo   Description of the requested ec session
 *
 * \param       pEcHandle The handle returned by the Library
 *
 * \return      size > 0        if valid session is found, size otherwise
 */
ALCP_API_EXPORT alc_error_t
alcp_ec_request(const alc_ec_info_p pEcInfo, alc_ec_handle_p pEcHandle);

EXTERN_C_END

#endif /* _ALCP_EC_H_ */
