Cipher API
**********
Cipher is a cryptographic technique used to secure information by transforming message into a cryptic form that can only be read by those with the key to decipher it.

----

Data Structures
---------------
.. doxygenstruct:: alc_cipher_info_t
.. doxygenstruct:: alc_cipher_handle_t
.. doxygenstruct:: alc_cipher_mode_gcm_info_t
.. doxygenstruct:: alc_cipher_mode_siv_info_t
.. doxygenstruct:: alc_key_info_t

----

Functions
---------
.. doxygenfunction:: alcp_cipher_context_size
.. doxygenfunction:: alcp_cipher_request
.. doxygenfunction:: alcp_cipher_encrypt
.. doxygenfunction:: alcp_cipher_decrypt
.. doxygenfunction:: alcp_cipher_blocks_encrypt
.. doxygenfunction:: alcp_cipher_blocks_decrypt
.. doxygenfunction:: alcp_cipher_init
.. doxygenfunction:: alcp_cipher_finish
.. doxygenfunction:: alcp_cipher_error
.. doxygenfunction:: alcp_cipher_aead_context_size
.. doxygenfunction:: alcp_cipher_aead_request
.. doxygenfunction:: alcp_cipher_aead_encrypt
.. doxygenfunction:: alcp_cipher_aead_encrypt_update
.. doxygenfunction:: alcp_cipher_aead_decrypt_update
.. doxygenfunction:: alcp_cipher_aead_decrypt
.. doxygenfunction:: alcp_cipher_aead_init
.. doxygenfunction:: alcp_cipher_aead_set_aad
.. doxygenfunction:: alcp_cipher_aead_get_tag
.. doxygenfunction:: alcp_cipher_aead_set_tag_length
.. doxygenfunction:: alcp_cipher_aead_finish
.. doxygenfunction:: alcp_cipher_aead_error

----

Variables
---------
.. doxygenvariable:: alc_cipher_type_t
.. doxygenvariable:: alc_cipher_mode_t
.. doxygenvariable:: alc_aes_ctrl_t
.. doxygenvariable:: alc_key_type_t
.. doxygenvariable:: alc_key_alg_t
.. doxygenvariable:: alc_key_len_t
.. doxygenvariable:: alc_key_fmt_t
.. doxygenvariable:: alc_cipher_context_t