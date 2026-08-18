/*
 * Copyright (C) 2026, Advanced Micro Devices. All rights reserved.
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

/*
 * AOCL-Cryptography file-encryptor utility.
 *
 * Uses only the public C API (alcp/alcp.h). The block size is fixed at 16
 * bytes because every mode offered here is AES.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <alcp/alcp.h>

#define AES_BLOCK_SIZE 16
#define PADDING_ESCAPE 0x0f

static Uint8
parse_hex_to_num(const char c)
{
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    if (c >= '0' && c <= '9')
        return c - '0';

    return 0;
}

/*
 * Decodes a hex string into newly allocated bytes. Returns NULL when the
 * string is empty; *out_len carries the decoded length.
 */
static Uint8*
parse_hex_str_to_bin(const char* in, Uint64* out_len)
{
    Uint64 len = (in == NULL) ? 0 : strlen(in);
    Uint64 i;
    Uint8* out;

    *out_len = 0;
    if (len < 2) {
        return NULL;
    }

    out = malloc(len / 2);
    if (out == NULL) {
        return NULL;
    }

    for (i = 0; i + 1 < len; i += 2) {
        out[i / 2] =
            (parse_hex_to_num(in[i]) << 4) | parse_hex_to_num(in[i + 1]);
    }
    *out_len = len / 2;
    return out;
}

/*
 * Pads to the AES block size by appending an escape byte followed by zeros,
 * so the original length is recoverable. Deprecate once every mode pads
 * internally.
 */
static Uint8*
pad_zeros(const Uint8* in, Uint64 in_len, Uint64* out_len)
{
    Uint64 rem = AES_BLOCK_SIZE - (in_len % AES_BLOCK_SIZE);
    Uint8* out = malloc(in_len + rem);

    if (out == NULL) {
        *out_len = 0;
        return NULL;
    }

    memcpy(out, in, in_len);
    out[in_len] = PADDING_ESCAPE;
    memset(out + in_len + 1, 0x00, rem - 1);

    *out_len = in_len + rem;
    return out;
}

/* Truncates at the last escape byte written by pad_zeros. */
static Uint64
unpad_zeros(const Uint8* in, Uint64 in_len)
{
    Uint64 i;

    for (i = in_len; i > 0; i--) {
        if (in[i - 1] == PADDING_ESCAPE) {
            return i - 1;
        }
    }
    return in_len;
}

/* Maps a mode string such as "aes-cbc-128" onto the C API enums. */
static int
parse_mode(const char* mode, alc_cipher_mode_t* out_mode, Uint64* out_key_bits)
{
    if (strstr(mode, "cbc") != NULL) {
        *out_mode = ALC_AES_MODE_CBC;
    } else if (strstr(mode, "cfb") != NULL) {
        *out_mode = ALC_AES_MODE_CFB;
    } else if (strstr(mode, "ctr") != NULL) {
        *out_mode = ALC_AES_MODE_CTR;
    } else if (strstr(mode, "ofb") != NULL) {
        *out_mode = ALC_AES_MODE_OFB;
    } else if (strstr(mode, "xts") != NULL) {
        *out_mode = ALC_AES_MODE_XTS;
    } else {
        return -1;
    }

    if (strstr(mode, "192") != NULL) {
        *out_key_bits = 192;
    } else if (strstr(mode, "256") != NULL) {
        *out_key_bits = 256;
    } else {
        *out_key_bits = 128;
    }

    return 0;
}

/*
 * Runs one cipher session over the whole buffer. is_encrypt selects the
 * direction; out must already hold in_len bytes.
 */
static int
run_cipher(const char*  mode,
           const Uint8* key,
           Uint64       key_len,
           const Uint8* iv,
           Uint64       iv_len,
           const Uint8* in,
           Uint8*       out,
           Uint64       in_len,
           int          is_encrypt)
{
    alc_cipher_handle_t handle;
    alc_cipher_mode_t   cipher_mode;
    Uint64              key_bits_from_mode = 0;
    Uint64              outlen             = 0;
    alc_error_t         err;
    int                 rc = -1;

    if (parse_mode(mode, &cipher_mode, &key_bits_from_mode) != 0) {
        fprintf(stderr, "Error: Unsupported mode: %s\n", mode);
        return -1;
    }

    handle.ch_context = malloc(alcp_cipher_context_size());
    if (handle.ch_context == NULL) {
        fprintf(stderr, "Error: Out of memory\n");
        return -1;
    }

    if (key_bits_from_mode != key_len * 8) {
        fprintf(stderr,
                "Error: %s needs a %lu-bit key, but %lu bits were supplied\n",
                mode,
                (unsigned long)key_bits_from_mode,
                (unsigned long)(key_len * 8));
        goto out_free;
    }

    err = alcp_cipher_request(cipher_mode, key_len * 8, &handle);
    if (alcp_is_error(err)) {
        fprintf(stderr,
                "Error: Failed to create cipher for mode: %s"
                " (CPU features not supported?)\n",
                mode);
        goto out_free;
    }

    err = alcp_cipher_init(&handle, key, key_len * 8, iv, iv_len);
    if (alcp_is_error(err)) {
        fprintf(stderr, "Error: Unable to initialize cipher\n");
        goto out_finish;
    }

    if (is_encrypt) {
        err = alcp_cipher_encrypt(&handle, in, out, in_len, &outlen);
    } else {
        err = alcp_cipher_decrypt(&handle, in, out, in_len, &outlen);
    }
    if (alcp_is_error(err)) {
        fprintf(stderr,
                "Error: Unable to %s\n",
                is_encrypt ? "encrypt" : "decrypt");
        goto out_finish;
    }

    rc = 0;

out_finish:
    alcp_cipher_finish(&handle);
out_free:
    free(handle.ch_context);
    return rc;
}

/*
 * MSVC deprecates fopen in favour of fopen_s, and the example is built with
 * warnings as errors, so route both callers through one wrapper rather than
 * silencing the diagnostic.
 */
static FILE*
open_file(const char* path, const char* mode)
{
#if defined(_MSC_VER)
    FILE* f = NULL;
    if (fopen_s(&f, path, mode) != 0) {
        return NULL;
    }
    return f;
#else
    return fopen(path, mode);
#endif
}

/* Reads a whole file into newly allocated memory. */
static Uint8*
read_file(const char* path, Uint64* out_len)
{
    FILE*  f;
    long   size;
    Uint8* buf;

    *out_len = 0;
    if (path == NULL || path[0] == '\0') {
        return NULL;
    }

    f = open_file(path, "rb");
    if (f == NULL) {
        return NULL;
    }

    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return NULL;
    }
    size = ftell(f);
    if (size < 0) {
        fclose(f);
        return NULL;
    }
    rewind(f);

    buf = malloc((size_t)size > 0 ? (size_t)size : 1);
    if (buf == NULL) {
        fclose(f);
        return NULL;
    }

    if (fread(buf, 1, (size_t)size, f) != (size_t)size) {
        free(buf);
        fclose(f);
        return NULL;
    }

    fclose(f);
    *out_len = (Uint64)size;
    return buf;
}

static int
write_file(const char* path, const Uint8* data, Uint64 len)
{
    FILE* f;

    if (path == NULL || path[0] == '\0') {
        return -1;
    }

    f = open_file(path, "wb");
    if (f == NULL) {
        return -1;
    }

    if (len > 0 && fwrite(data, 1, len, f) != len) {
        fclose(f);
        return -1;
    }

    fclose(f);
    return 0;
}

/*
 * Returns the value that follows param, "" when the flag is present without
 * a value, or NULL when it is absent.
 */
static const char*
get_param(int argc, char const* argv[], const char* param)
{
    int i;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], param) != 0) {
            continue;
        }
        if (i + 1 < argc && argv[i + 1][0] != '-') {
            return argv[i + 1];
        }
        return "";
    }
    return NULL;
}

static int
arg_exists(int argc, char const* argv[], const char* param)
{
    return get_param(argc, argv, param) != NULL;
}

static void
print_help(void)
{
    printf("+-------------------------------------------+\n"
           "|  AOCL-Cryptography file-encryptor utility |\n"
           "+-------------------------------------------+\n"
           "| Command    |   Args                       |\n"
           "|-------------------------------------------|\n"
           "| --help/-h  |   None                       |\n"
           "| --iv       |   32 char hex encoded IV     |\n"
           "| --key      |   32-64 char hex encoded Key |\n"
           "| --alg      |   --alg aes-ctr-128          |\n"
           "| -i         |   Path to input file         |\n"
           "| -o         |   Path to output file        |\n"
           "| -e         |   Select Encrypt operation   |\n"
           "| -d         |   Select Decrypt operation   |\n"
           "+-------------------------------------------+\n");
}

int
main(int argc, char const* argv[])
{
    const char* algorithm = "aes-cfb-128";
    const char* alg_arg;
    Uint8 *     key = NULL, *iv = NULL;
    Uint64      key_len = 0, iv_len = 0;
    Uint8 *     in = NULL, *padded = NULL, *out = NULL;
    Uint64      in_len = 0, work_len = 0, out_len = 0;
    int         is_encrypt, is_decrypt;
    int         rc = -1;

    if (arg_exists(argc, argv, "--help") || arg_exists(argc, argv, "-h")) {
        print_help();
        return 0;
    }

    alg_arg = get_param(argc, argv, "--alg");
    if (alg_arg == NULL) {
        printf("Using default alg %s\n", algorithm);
    } else if (alg_arg[0] == '\0') {
        /* --alg was given without a value: silently falling back to the
         * default would run a different algorithm than the one asked for. */
        printf("Invalid argument!\n");
        print_help();
        goto cleanup;
    } else {
        algorithm = alg_arg;
    }

    key = parse_hex_str_to_bin(get_param(argc, argv, "--key"), &key_len);
    iv  = parse_hex_str_to_bin(get_param(argc, argv, "--iv"), &iv_len);

    if (key_len < 16 || iv_len < 16) {
        printf("Invalid argument!\n");
        print_help();
        goto cleanup;
    }

    is_encrypt = arg_exists(argc, argv, "-e");
    is_decrypt = arg_exists(argc, argv, "-d");

    if (is_encrypt == is_decrypt) {
        printf("One of encrypt, decrypt must be specified, not both!\n");
        print_help();
        goto cleanup;
    }

    in = read_file(get_param(argc, argv, "-i"), &in_len);
    if (in == NULL) {
        printf("Input file of the file do not exist!\n");
        goto cleanup;
    }

    if (is_encrypt) {
        padded = pad_zeros(in, in_len, &work_len);
        if (padded == NULL) {
            fprintf(stderr, "Error: Out of memory\n");
            goto cleanup;
        }
    } else {
        work_len = in_len;
    }

    out = malloc(work_len > 0 ? work_len : 1);
    if (out == NULL) {
        fprintf(stderr, "Error: Out of memory\n");
        goto cleanup;
    }

    if (run_cipher(algorithm,
                   key,
                   key_len,
                   iv,
                   iv_len,
                   is_encrypt ? padded : in,
                   out,
                   work_len,
                   is_encrypt)
        != 0) {
        goto cleanup;
    }

    out_len = is_encrypt ? work_len : unpad_zeros(out, work_len);

    if (write_file(get_param(argc, argv, "-o"), out, out_len) != 0) {
        printf("Cannot open output file for writing!\n");
        goto cleanup;
    }

    printf("Success!\n");
    rc = 0;

cleanup:
    free(key);
    free(iv);
    free(in);
    free(padded);
    free(out);
    return rc;
}
