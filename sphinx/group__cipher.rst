Cipher
**********
Cipher is a cryptographic technique used to secure information by transforming message into a cryptic form that can only be read by those with the key to decipher it.

----

Data Structures
---------------
.. doxygenstruct:: alc_cipher_handle_t

----

Functions
---------
.. doxygenfunction:: alcp_cipher_context_size
.. doxygenfunction:: alcp_cipher_request
.. doxygenfunction:: alcp_cipher_init
.. doxygenfunction:: alcp_cipher_encrypt
.. doxygenfunction:: alcp_cipher_decrypt
.. doxygenfunction:: alcp_cipher_finish
.. doxygenfunction:: alcp_cipher_segment_init
.. doxygenfunction:: alcp_cipher_segment_request
.. doxygenfunction:: alcp_cipher_segment_encrypt_xts
.. doxygenfunction:: alcp_cipher_segment_decrypt_xts
.. doxygenfunction:: alcp_cipher_segment_finish
.. doxygenfunction:: alcp_cipher_aead_context_size
.. doxygenfunction:: alcp_cipher_aead_request
.. doxygenfunction:: alcp_cipher_aead_init
.. doxygenfunction:: alcp_cipher_aead_encrypt
.. doxygenfunction:: alcp_cipher_aead_decrypt
.. doxygenfunction:: alcp_cipher_aead_set_aad
.. doxygenfunction:: alcp_cipher_aead_get_tag
.. doxygenfunction:: alcp_cipher_aead_set_tag_length
.. doxygenfunction:: alcp_cipher_aead_set_ccm_plaintext_length
.. doxygenfunction:: alcp_cipher_aead_finish

----

Variables
---------
.. doxygenvariable:: alc_cipher_mode_t
.. doxygenvariable:: alc_key_len_t
.. doxygenvariable:: alc_cipher_context_t