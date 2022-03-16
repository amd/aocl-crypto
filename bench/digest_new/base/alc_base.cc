#include "alc_base.hh"
#include "base.hh"

namespace alcp::bench {

AlcpDigestBase::AlcpDigestBase(alc_digest_handle_t * m_handle,
                               _alc_sha2_mode      mode,
                               _alc_digest_type    type,
                               _alc_digest_len     sha_len) {
    digestInit(m_handle, mode, type, sha_len);
}

alc_error_t
AlcpDigestBase::digestInit(alc_digest_handle_t * m_handle,
                      _alc_sha2_mode      mode,
                      _alc_digest_type    type,
                       _alc_digest_len    sha_len) {
    alc_error_t err;
    alc_digest_info_t dinfo = {
        .dt_type = type,
        .dt_len = sha_len,
        .dt_mode = {.dm_sha2 = mode,},
    };

    uint64_t size     = alcp_digest_context_size(&dinfo);
    m_handle->context = malloc(size);

    err = alcp_digest_request(&dinfo, m_handle);

    if (alcp_is_error(err)) {
        return err;
    }
    return err;
}


alc_error_t
AlcpDigestBase::digest_function(alc_digest_handle_t* s_dg_handle,
              uint8_t*          src,
              uint64_t             src_size,
              uint8_t*             output,
              uint64_t             out_size)
{
    alc_error_t err;

    err = alcp_digest_update(s_dg_handle, src, src_size);
    if (alcp_is_error(err)) {
        printf("Unable to compute hash\n");
        goto out;
    }

    alcp_digest_finalize(s_dg_handle, NULL, 0);

    err = alcp_digest_copy(s_dg_handle, output, out_size);
    if (alcp_is_error(err)) {
        printf("Unable to copy digest\n");
        goto out;
    }

    //alcp_digest_finish(s_dg_handle);

out:
    return err;
}


} // namespace alcp::testing