Digest
**********
A digest is a one way cryptographic function by which a message of any length can be mapped into a fixed-length output. It can be used for verifying integrity or passwords.

----

Data Structures
---------------
.. doxygenstruct:: alc_digest_handle_t
   :project: crypto

----

Functions
---------
.. doxygenfunction:: alcp_digest_context_size
   :project: crypto
.. doxygenfunction:: alcp_digest_request
   :project: crypto
.. doxygenfunction:: alcp_digest_init
   :project: crypto
.. doxygenfunction:: alcp_digest_update
   :project: crypto
.. doxygenfunction:: alcp_digest_finalize
   :project: crypto
.. doxygenfunction:: alcp_digest_finish
   :project: crypto
.. doxygenfunction:: alcp_digest_context_copy
   :project: crypto
.. doxygenfunction:: alcp_digest_shake_squeeze
   :project: crypto
   
----

Variables
---------
.. doxygenvariable:: alc_digest_len_t
   :project: crypto
.. doxygenvariable:: alc_digest_mode_t
   :project: crypto
.. doxygenvariable:: alc_digest_context_t
   :project: crypto
.. doxygenvariable:: alc_digest_block_size_t
   :project: crypto
