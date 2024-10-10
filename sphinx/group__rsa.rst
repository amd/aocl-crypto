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
.. doxygenfunction:: alcp_rsa_get_digest_info_index 
.. doxygenfunction:: alcp_rsa_get_digest_info_size
.. doxygenfunction:: alcp_rsa_context_size 
.. doxygenfunction:: alcp_rsa_request 
.. doxygenfunction:: alcp_rsa_add_digest
.. doxygenfunction:: alcp_rsa_add_mgf
.. doxygenfunction:: alcp_rsa_publickey_encrypt
.. doxygenfunction:: alcp_rsa_publickey_encrypt_oaep 
.. doxygenfunction:: alcp_rsa_privatekey_decrypt
.. doxygenfunction:: alcp_rsa_privatekey_decrypt_oaep 
.. doxygenfunction:: alcp_rsa_privatekey_sign_pss 
.. doxygenfunction:: alcp_rsa_publickey_verify_pss
.. doxygenfunction:: alcp_rsa_privatekey_sign_pkcs1v15
.. doxygenfunction:: alcp_rsa_publickey_verify_pkcs1v15
.. doxygenfunction:: alcp_rsa_privatekey_sign_hash_pkcs1v15
.. doxygenfunction:: alcp_rsa_publickey_verify_hash_pkcs1v15
.. doxygenfunction:: alcp_rsa_publickey_encrypt_pkcs1v15
.. doxygenfunction:: alcp_rsa_privatekey_decrypt_pkcs1v15
.. doxygenfunction:: alcp_rsa_privatekey_sign_hash_pss
.. doxygenfunction:: alcp_rsa_publickey_verify_hash_pss
.. doxygenfunction:: alcp_rsa_set_publickey 
.. doxygenfunction:: alcp_rsa_set_bignum_public_key
.. doxygenfunction:: alcp_rsa_set_bignum_private_key
.. doxygenfunction:: alcp_rsa_set_privatekey 
.. doxygenfunction:: alcp_rsa_get_key_size 
.. doxygenfunction:: alcp_rsa_context_copy
.. doxygenfunction:: alcp_rsa_finish 

----

Variables
---------
.. doxygenvariable:: alc_rsa_padding
.. doxygenvariable:: alc_rsa_key_size
.. doxygenvariable:: alc_rsa_context_t
