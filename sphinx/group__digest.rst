Digest API
**********
A digest is a one way cryptographic function by which a message of any length can be mapped into a fixed-length output. It can be used for verifying integrity or passwords.

----

Data Structures
---------------
.. doxygenunion:: alc_digest_mode_t
.. doxygenstruct:: alc_digest_data_t
.. doxygenstruct:: alc_digest_info_t
.. doxygenstruct:: alc_digest_handle_t

----

Functions
---------
.. doxygenfunction:: alcp_digest_context_size
.. doxygenfunction:: alcp_digest_supported
.. doxygenfunction:: alcp_digest_request
.. doxygenfunction:: alcp_digest_update
.. doxygenfunction:: alcp_digest_copy
.. doxygenfunction:: alcp_digest_finalize
.. doxygenfunction:: alcp_digest_finish
.. doxygenfunction:: alcp_digest_reset
.. doxygenfunction:: alcp_digest_error
.. doxygenfunction:: alcp_digest_set_shake_length
   
----

Variables
---------
.. doxygenvariable:: alc_digest_type_t
.. doxygenvariable:: alc_sha2_mode_t
.. doxygenvariable:: alc_sha3_mode_t
.. doxygenvariable:: alc_digest_len_t
.. doxygenvariable:: alc_digest_context_t