Cipher
**********
Cipher is a cryptographic technique used to secure information by transforming message into a cryptic form that can only be read by those with the key to decipher it.

----

Data Structures
---------------
.. doxygenstruct:: alc_cipher_handle_t
   :project: crypto

----

Functions
---------
.. doxygenfunction:: alcp_cipher_context_size
   :project: crypto
.. doxygenfunction:: alcp_cipher_request
   :project: crypto
.. doxygenfunction:: alcp_cipher_init
   :project: crypto
.. doxygenfunction:: alcp_cipher_encrypt
   :project: crypto
.. doxygenfunction:: alcp_cipher_decrypt
   :project: crypto
.. doxygenfunction:: alcp_cipher_finish
   :project: crypto
.. doxygenfunction:: alcp_cipher_segment_init
   :project: crypto
.. doxygenfunction:: alcp_cipher_segment_request
   :project: crypto
.. doxygenfunction:: alcp_cipher_segment_encrypt_xts
   :project: crypto
.. doxygenfunction:: alcp_cipher_segment_decrypt_xts
   :project: crypto
.. doxygenfunction:: alcp_cipher_segment_finish
   :project: crypto
.. doxygenfunction:: alcp_cipher_aead_context_size
   :project: crypto
.. doxygenfunction:: alcp_cipher_aead_request
   :project: crypto
.. doxygenfunction:: alcp_cipher_aead_init
   :project: crypto
.. doxygenfunction:: alcp_cipher_aead_encrypt
   :project: crypto
.. doxygenfunction:: alcp_cipher_aead_decrypt
   :project: crypto
.. doxygenfunction:: alcp_cipher_aead_set_aad
   :project: crypto
.. doxygenfunction:: alcp_cipher_aead_get_tag
   :project: crypto
.. doxygenfunction:: alcp_cipher_aead_set_tag_length
   :project: crypto
.. doxygenfunction:: alcp_cipher_aead_set_ccm_plaintext_length
   :project: crypto
.. doxygenfunction:: alcp_cipher_aead_finish
   :project: crypto

----

Variables
---------
.. doxygenvariable:: alc_cipher_mode_t
   :project: crypto
.. doxygenvariable:: alc_key_len_t
   :project: crypto
.. doxygenvariable:: alc_cipher_context_t
   :project: crypto
