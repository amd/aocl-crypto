#include "common.hh"
#include "digest_data.hh"
#include "alcp/digest.h"

alc_error_t
create_hash_session(alc_digest_handle_t * s_dg_handle, 
		    _alc_digest_type digest_type,
		    _alc_digest_len  digest_len,
		    _alc_sha2_mode   digest_mode) 
{
    alc_error_t err;

    alc_digest_info_t dinfo = {
        .dt_type = digest_type,
        .dt_len = digest_len,
        .dt_mode = {.dm_sha2 = digest_mode,},
    };

    uint64_t size       = alcp_digest_context_size(&dinfo);
    s_dg_handle->context = malloc(size);

    err = alcp_digest_request(&dinfo, s_dg_handle);

    if (alcp_is_error(err)) {
        return err;
    }

    return err;
}


alc_error_t
hash_function(alc_digest_handle_t * s_dg_handle,
	       const uint8_t* src,
               uint64_t       src_size,
               uint8_t*       output,
               uint64_t       out_size)
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

    alcp_digest_finish(s_dg_handle);

out:
    return err;
}


void
hash_to_string(char string[65], const uint8_t hash[32]) {
    size_t i;
    for (i = 0; i < 28; i++) {
        string += sprintf(string, "%02x", hash[i]);
    }
}
