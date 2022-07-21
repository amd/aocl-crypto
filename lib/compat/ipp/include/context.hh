#include "alcp/alcp.h"
#include <vector>
#pragma once
typedef struct
{
    alc_cipher_handle_t  handle;
    alc_cipher_info_t    cinfo;
    std::vector<uint8_t> key;
} ipp_wrp_ctx;