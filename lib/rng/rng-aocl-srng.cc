/*
 * Copyright (C) 2019-2021, Advanced Micro Devices. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 3. Neither the name of the copyright holder nor the names of its contributors
 *    may be used to endorse or promote products derived from this software without
 *    specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA,
 * OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 */
#include <secrng.h>
#include <stdio.h>
#include "rng.hh"
#include "alcp/macros.h"

// Enable debug for debugging the code
#define DEBUG

namespace alcp::rng {
    int rng_engine_amd_rdrand_bytes(uint8_t * buffer,int buffersize){
        #ifdef DEBUG
        printf("Engine amd_rdrand_bytes\n");
        #endif
        int opt = is_RDRAND_supported();
        if(opt==0){
            opt = -1;
        }
        else{
            opt = get_rdrand_bytes_arr(
                                        buffer,
                                        buffersize,
                                        100 // Retires is hard coded as 100, may be add this to context.
                                       );
            if(opt<=0){
                opt=-1;
            }
            else{
                opt=buffersize;
            }
        }
        return opt;
    }

    // probably a bad idea..
    // int rng_engine_amd_rdrand(uint8_t * buffer, int buffersize){
    //     int opt = is_RDRAND_supported();
    //     if(opt==0){
    //         opt = -1;
    //     }
    //     else{
    //         int chunk_8 = buffersize/8;
    //         int chunk_4 = (buffersize-(chunk_8*8))/4;
    //         int left = buffersize - chunk_8*8 - chunk_4*4;
    //         opt = get_rdseed64u_arr((uint64_t *)buffer,chunk_8,100);
    //         opt = opt & get_rdseed32u_arr((uint32_t *)(buffer+(chunk_8*8)),chunk_4,100);
    //         uint64_t rndm= 0;
    //         switch(left) {
    //             case 3:
    //                 opt = opt & get_rdseed32u(((uint32_t *)&rndm)+1,100);
    //                 *((uint16_t *)(buffer+buffersize-left-1+0)) = *(((uint32_t *)&rndm)+1) & 0xffff;
    //                 *(((uint32_t *)&rndm)+1) = *(((uint32_t *)&rndm)+1)>>16;
    //                 *(buffer+buffersize-left-1+2) = *(((uint32_t *)&rndm)+1) & 0xff;
    //                 break;
    //             case 2:
    //                 opt = opt & get_rdseed16u(((uint16_t *)&rndm)+2,100);
    //                 *((uint16_t *)(buffer+buffersize-left-1)) = rndm;
    //                 break;
    //             case 1:
    //                 opt = opt & get_rdseed16u(((uint16_t *)&rndm)+2,100);
    //                 *(buffer+buffersize-left-1) = rndm & 0xff;
    //                 break;
    //         }

    //     }
    //     return opt;
    // }
}