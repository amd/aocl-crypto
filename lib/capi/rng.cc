#include <stdio.h>
#include <iostream>
#include "alcp/macros.h"
#include "rng.hh"
#include "error.hh"

EXTERN_C_BEGIN
    alc_error_t alcp_rng_supported(const alc_rng_info_t *tt){
        alc_error_t error = ALC_ERROR_NOT_SUPPORTED;

        switch (tt->r_type){
            case ALC_RNG_TYPE_DESCRETE:
                switch (tt->r_distrib){
                    case ALC_RNG_DISTRIB_UNIFORM:
                        switch (tt->r_source){
                            case ALC_RNG_SOURCE_OS:
                                error = ALC_ERROR_NONE;
                                break;
                            case ALC_RNG_SOURCE_ARCH:
                                error = ALC_ERROR_NONE;
                                break;
                        }
                }
        }

        // switch(tt->r_type){
        //     case ALC_RNG_TYPE_DESCRETE:
        //         break;
        //     default:
        //         error = ALC_ERROR_NOT_SUPPORTED;
        //         // Can return error here for speed
        // }

        // switch(tt->r_distrib){
        //     case ALC_RNG_DISTRIB_UNIFORM:
        //         break;
        //     default:
        //         error = ALC_ERROR_NOT_SUPPORTED;
        //         // Can return error here for speed
        // }

        // switch(tt->r_source){
        //     case ALC_RNG_SOURCE_ARCH:
        //         break;
        //     default:
        //         error = ALC_ERROR_NOT_SUPPORTED;
        //         // Can return error here for speed
        // }

        // switch(tt->r_source){
        //     case ALC_RNG_SOURCE_OS:
        //         break;
        //     default:
        //         error = ALC_ERROR_NOT_SUPPORTED;
        //         // Can return error here for speed
        // }

        return error;

    }

    alc_error_t alcp_rng_request(const alc_rng_info_t *tt, alc_context_t * cntxt){
        alc_error_t error = ALC_ERROR_NOT_SUPPORTED;

        switch (tt->r_type){
            case ALC_RNG_TYPE_DESCRETE:
                switch (tt->r_distrib){
                    case ALC_RNG_DISTRIB_UNIFORM:
                        error = ALC_ERROR_NONE;
                        switch (tt->r_source){
                            case ALC_RNG_SOURCE_OS:
                                cntxt->rng_info.r_distrib = tt->r_distrib;
                                cntxt->rng_info.r_type    = tt->r_type;
                                cntxt->rng_info.r_source  = tt->r_source;
                                cntxt->rng_info.r_flags   = tt->r_flags;
                                cntxt->engine = &(alcp::rng::rng_engine_linux_urandom);
                                break;
                            case ALC_RNG_SOURCE_ARCH:
                                cntxt->rng_info.r_distrib = tt->r_distrib;
                                cntxt->rng_info.r_type    = tt->r_type;
                                cntxt->rng_info.r_source  = tt->r_source;
                                cntxt->rng_info.r_flags   = tt->r_flags;
                                cntxt->engine = &(alcp::rng::rng_engine_amd_rdrand_bytes);
                                break;
                            default:
                                error = ALC_ERROR_NOT_SUPPORTED;
                        }
                }
        }

        // switch(tt->r_type){
        //     case ALC_RNG_TYPE_CONTINUOUS:
        //         //call cont
        //         error = ALC_ERROR_NOT_SUPPORTED;
        //         break;
        //     case ALC_RNG_TYPE_DESCRETE:
        //         //call desc
        //         error = ALC_ERROR_NOT_SUPPORTED;
        //         break;
        //     case ALC_RNG_TYPE_INVALID:
        //         //call invalid
        //         error = ALC_ERROR_NOT_SUPPORTED;
        //         break;
        //     case ALC_RNG_TYPE_MAX:
        //         //call max
        //         error = ALC_ERROR_NOT_SUPPORTED;
        //         break;
        //     case ALC_RNG_TYPE_SIMPLE:
        //         // call simple
        //         error = ALC_ERROR_NOT_SUPPORTED;
        //         break;
        // }
        return error;
    }

    alc_error_t alcp_rng_gen_random(alc_context_t *tt,
                                    uint8_t       *buf,  /* RNG output buffer */
                                    uint64_t       size  /* output buffer size */
                                    ){
        int randn=0;
        int tries = 10;
        if(buf == NULL){
            return ALC_ERROR_INVALID_ARG;
        }
        while(randn!=size){
            randn += tt->engine(buf+randn,size-randn);
            tries -= 1;
            if(tries == 0){
                return ALC_ERROR_NO_ENTROPY;
            }
        }
        return ALC_ERROR_NONE;
    }
EXTERN_C_END
