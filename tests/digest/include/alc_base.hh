#include <alcp/alcp.h>
#include <iostream>
#include <malloc.h>
#include <vector>
#include "alcp/digest.h"

#pragma once

namespace alcp::bench {
class AlcpDigestBase {
    alc_digest_handle_t m_handle;
    _alc_sha2_mode      m_mode;
    _alc_digest_type    m_type;
    uint32_t            sha_len;
    uint8_t *           message;
    uint8_t *           digest;

    public:
        AlcpDigestBase(alc_digest_handle_t * m_handle,
                       _alc_sha2_mode        mode,
                       _alc_digest_type      type,
                       _alc_digest_len       sha_len);

        alc_error_t
        digestInit(alc_digest_handle_t * m_handle,
                   _alc_sha2_mode        mode,
                   _alc_digest_type      type,
                   _alc_digest_len       sha_len);
 
        alc_error_t
        digest_function(alc_digest_handle_t * m_handle,
                        uint8_t *             src,
                        uint64_t              src_size,
                        uint8_t *             output,
                        uint64_t              out_size);

};

} // namespace alcp::bench
