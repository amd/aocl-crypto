/*
 * Copyright (C) 2023, Advanced Micro Devices. All rights reserved.
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

/**
 * @defgroup ec EC API
 * @brief
 * Elliptic Curve Cryptography (ECC) is a type of public key cryptography that
 * uses the mathematics of elliptic curves to secure information and protect
 * sensitive data.
 * @{
 */

/**
 * @brief Store info about curve id used for EC
 *
 * @typedef enum alc_ec_curve_id
 */
typedef enum
{
    ALCP_EC_CURVE25519 = 0,
    ALCP_EC_SECP256R1,
    ALCP_EC_MAX,
} alc_ec_curve_id;

/**
 * @brief Store info about curve type used for EC
 *
 * @typedef enum alc_ec_curve_type
 */
typedef enum
{
    ALCP_EC_CURVE_TYPE_SHORT_WEIERSTRASS = 0,
    ALCP_EC_CURVE_TYPE_MONTGOMERY,
    ALCP_EC_CURVE_TYPE_MAX
} alc_ec_curve_type;

/**
 * @brief Store info about point format id used for EC
 *
 * @typedef enum alc_ec_point_format_id
 */
typedef enum
{
    ALCP_EC_POINT_FORMAT_UNCOMPRESSED = 0,
    ALCP_EC_POINT_FORMAT_COMPRESSED,
} alc_ec_point_format_id;

/**
 * @brief Store info about EC
 *
 * @param ecCurveId     Store info about curve id used for EC
 * @param ecCurveType   Store info about curve type used for EC
 * @param ecPointFormat Store info about point format id used for EC
 *
 * @struct alc_ec_info_t
 */
typedef struct alc_ec_info
{
    alc_ec_curve_id        ecCurveId;
    alc_ec_curve_type      ecCurveType;
    alc_ec_point_format_id ecPointFormat;

} alc_ec_info_t, *alc_ec_info_p;

/**
 * @brief Store Context for the future operation of EC
 *
 */
typedef void              alc_ec_context_t;
typedef alc_ec_context_t* alc_ec_context_p;

/**
 * @brief Handle for maintaining session.
 *
 * @param context pointer to the context of the EC
 *
 * @struct alc_ec_handle_t
 */
typedef struct _alc_ec_handle
{
    alc_ec_context_p context;
} alc_ec_handle_t, *alc_ec_handle_p, AlcEcHandle, *AlcEcHandleP;

/**
 * @brief       Returns the context size of the interaction
 *
 * @parblock <br> &nbsp;
 * <b>This API can be called after @ref alcp_ec_request only otherwise
 * Context will be empty </b>
 * @endparblock
 *
 * @note        @ref alcp_ec_supported() should be called first to
 *              know if the given curveType is valid.
 *
 * @param [in]      p_ec_info   Description of the requested ec session
 *
 * @return      Size of Context
 */
ALCP_API_EXPORT Uint64
alcp_ec_context_size(const alc_ec_info_p p_ec_info);

/**
 * @brief       Allows to check if a given algorithm is supported
 *
 * @parblock <br> &nbsp;
 * <b>This API needs to be called before any other API is called to
 * know if EC that is being request is supported or not </b>
 * @endparblock
 *
 * @note        alcp_ec_supported() should be called
 *              know if the given curveType and configuration is valid.
 *
 * @param [in]      pEcInfo Description of the requested ec session
 *
 * @return   &nbsp; Error Code for the API called. If alc_error_t
 * is not ALC_ERROR_NONE then @ref alcp_error_str needs to be called to know
 * about error occurred
 */
ALCP_API_EXPORT alc_error_t
alcp_ec_supported(const alc_ec_info_p pEcInfo);

/**
 * @brief       Request a handle for ec  for a configuration
 *              as pointed by p_ec_info_p
 *
 * @parblock <br> &nbsp;
 * <b>This API can be called after @ref alcp_ec_supported is called and at the
 * end of session call @ref alcp_ec_finish</b>
 * @endparblock
 *
 * @note        alcp_ec_supported() should be called first to
 *              know if the given curveType is valid.
 *
 * @param [in]      pEcInfo   Description of the requested ec session
 *
 * @param [out]      pEcHandle Library populated session handle for future
 * EC operations.
 *
 * @return   &nbsp; Error Code for the API called. If alc_error_t
 * is not ALC_ERROR_NONE then @ref alcp_error_str needs to be called to know
 * about error occurred
 */
ALCP_API_EXPORT alc_error_t
alcp_ec_request(const alc_ec_info_p pEcInfo, alc_ec_handle_p pEcHandle);

/**
 * @brief              Get the error string for errors occurring in EC
 *                     operations
 * @parblock <br> &nbsp;
 * <b> This API is called to get the error string. It should be called after
 * @ref alcp_ec_request and before @ref alcp_ec_finish </b>
 * @endparblock
 * @param [in] pEcHandle Session handle for EC operation
 * @param [out] pBuff  Destination Buffer to which Error String will be copied
 * @param [in] size    Length of the Buffer.
 *
 * @return alc_error_t Error code to validate the Handle
 */
ALCP_API_EXPORT alc_error_t
alcp_ec_error(alc_ec_handle_p pEcHandle, Uint8* pBuff, Uint64 size);

EXTERN_C_END

#endif /* _ALCP_EC_H_ */
       /**
        * @}
        */
