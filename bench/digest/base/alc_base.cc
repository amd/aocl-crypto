#include "alc_base.hh"
#include "base.hh"

namespace alcp::bench {

static uint8_t size_[4096] = {0};

AlcpDigestBase::AlcpDigestBase(_alc_sha2_mode   mode,
                               _alc_digest_type type, 
                               _alc_digest_len  sha_len)
    : m_mode { mode },
      m_type { type },
      m_sha_len { sha_len }
{
    alc_error_t err;
    alc_digest_info_t dinfo = {
        .dt_type = m_type,
        .dt_len = m_sha_len,
        .dt_mode = {.dm_sha2 = m_mode,},
    };

    m_handle = new alc_digest_handle_t;
    m_handle->context = &size_[0];

    err = alcp_digest_request(&dinfo, m_handle);
    if (alcp_is_error(err)) {
        printf("Error!\n");
    }
}

alc_error_t
AlcpDigestBase::digest_function(uint8_t * src,
                                uint64_t  src_size,
                                uint8_t * output,
                                uint64_t  out_size)
{
    alc_error_t err;
    err = alcp_digest_update(m_handle, src, src_size);
    if (alcp_is_error(err)) {
        printf("Digest update failed\n");
        return err;
    }

    alcp_digest_finalize(m_handle, NULL, 0);
    if (alcp_is_error(err)) {
        printf("Digest finalize failed\n");
        return err;
    }

    err = alcp_digest_copy(m_handle, output, out_size);
    if (alcp_is_error(err)) {
        printf("Digest copy failed\n");
        return err;
    }
    alcp_digest_finish(m_handle);
    return err;
}

} // namespace alcp::bench
