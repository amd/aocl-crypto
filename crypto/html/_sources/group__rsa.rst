RSA API
**********
RSA algorithm is a public-key cryptosystem. In a public-key cryptosystem, the encryption key is public and decryption key is private. RSA algorithm involves key generation, encryption / decryption and signature.

----

Data Structures
---------------
.. doxygenstruct:: alc_rsa_handle_t

----

Functions
---------
.. doxygenfunction:: alcp_rsa_context_size 
.. doxygenfunction:: alcp_rsa_request 
.. doxygenfunction:: alcp_rsa_publickey_encrypt
.. doxygenfunction:: alcp_rsa_publickey_encrypt_oaep 
.. doxygenfunction:: alcp_rsa_add_digest_oaep
.. doxygenfunction:: alcp_rsa_add_mgf_oaep
.. doxygenfunction:: alcp_rsa_privatekey_decrypt
.. doxygenfunction:: alcp_rsa_privatekey_decrypt_oaep 
.. doxygenfunction:: alcp_rsa_get_publickey 
.. doxygenfunction:: alcp_rsa_set_publickey 
.. doxygenfunction:: alcp_rsa_set_privatekey 
.. doxygenfunction:: alcp_rsa_get_key_size 
.. doxygenfunction:: alcp_rsa_finish 
.. doxygenfunction:: alcp_rsa_error

----

Variables
---------
.. doxygenvariable:: alc_rsa_padding
.. doxygenvariable:: alc_rsa_key_size
.. doxygenvariable:: alc_rsa_context_t
