RSA
**********
RSA algorithm is a public-key cryptosystem. In a public-key cryptosystem, the encryption key is public and decryption key is private. RSA algorithm involves key generation, encryption / decryption and signature.

----

Data Structures
---------------
.. doxygenstruct:: alc_rsa_handle_t
   :project: crypto

----

Functions
---------
.. doxygenfunction:: alcp_rsa_get_digest_info_index 
   :project: crypto
.. doxygenfunction:: alcp_rsa_get_digest_info_size
   :project: crypto
.. doxygenfunction:: alcp_rsa_context_size 
   :project: crypto
.. doxygenfunction:: alcp_rsa_request 
   :project: crypto
.. doxygenfunction:: alcp_rsa_add_digest
   :project: crypto
.. doxygenfunction:: alcp_rsa_add_mgf
   :project: crypto
.. doxygenfunction:: alcp_rsa_publickey_encrypt
   :project: crypto
.. doxygenfunction:: alcp_rsa_publickey_encrypt_oaep 
   :project: crypto
.. doxygenfunction:: alcp_rsa_privatekey_decrypt
   :project: crypto
.. doxygenfunction:: alcp_rsa_privatekey_decrypt_oaep 
   :project: crypto
.. doxygenfunction:: alcp_rsa_privatekey_sign_pss 
   :project: crypto
.. doxygenfunction:: alcp_rsa_publickey_verify_pss
   :project: crypto
.. doxygenfunction:: alcp_rsa_privatekey_sign_pkcs1v15
   :project: crypto
.. doxygenfunction:: alcp_rsa_publickey_verify_pkcs1v15
   :project: crypto
.. doxygenfunction:: alcp_rsa_privatekey_sign_hash_pkcs1v15
   :project: crypto
.. doxygenfunction:: alcp_rsa_publickey_verify_hash_pkcs1v15
   :project: crypto
.. doxygenfunction:: alcp_rsa_publickey_encrypt_pkcs1v15
   :project: crypto
.. doxygenfunction:: alcp_rsa_privatekey_decrypt_pkcs1v15
   :project: crypto
.. doxygenfunction:: alcp_rsa_privatekey_sign_hash_pss
   :project: crypto
.. doxygenfunction:: alcp_rsa_publickey_verify_hash_pss
   :project: crypto
.. doxygenfunction:: alcp_rsa_set_publickey 
   :project: crypto
.. doxygenfunction:: alcp_rsa_set_bignum_public_key
   :project: crypto
.. doxygenfunction:: alcp_rsa_set_bignum_private_key
   :project: crypto
.. doxygenfunction:: alcp_rsa_set_privatekey 
   :project: crypto
.. doxygenfunction:: alcp_rsa_get_key_size 
   :project: crypto
.. doxygenfunction:: alcp_rsa_context_copy
   :project: crypto
.. doxygenfunction:: alcp_rsa_finish 
   :project: crypto

----

Variables
---------
.. doxygenvariable:: alc_rsa_padding
   :project: crypto
.. doxygenvariable:: alc_rsa_key_size
   :project: crypto
.. doxygenvariable:: alc_rsa_context_t
   :project: crypto
