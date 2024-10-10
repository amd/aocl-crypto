Digest API
**********
A digest is a one way cryptographic function by which a message of any length can be mapped into a fixed-length output. It can be used for verifying integrity or passwords.

----

Data Structures
---------------
.. doxygenstruct:: alc_digest_handle_t

----

Functions
---------
.. doxygenfunction:: alcp_digest_context_size
.. doxygenfunction:: alcp_digest_request
.. doxygenfunction:: alcp_digest_init
.. doxygenfunction:: alcp_digest_update
.. doxygenfunction:: alcp_digest_finalize
.. doxygenfunction:: alcp_digest_finish
.. doxygenfunction:: alcp_digest_context_copy
.. doxygenfunction:: alcp_digest_shake_squeeze
   
----

Variables
---------
.. doxygenvariable:: alc_digest_len_t
.. doxygenvariable:: alc_digest_mode_t
.. doxygenvariable:: alc_digest_context_t
.. doxygenvariable:: alc_digest_block_size_t