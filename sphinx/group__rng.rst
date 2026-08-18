RNG
**********
Random number generation is a crucial component of cryptography, used to create keys and prevent attackers from predicting or replicating patterns in data. It is typically implemented using specialized algorithms or hardware.

----

Data Structures
---------------
.. doxygenstruct:: alc_rng_info_t
   :project: crypto
.. doxygenstruct:: alc_rng_handle_t
   :project: crypto

----

Functions
---------
.. doxygenfunction:: alcp_rng_supported
   :project: crypto
.. doxygenfunction:: alcp_rng_context_size
   :project: crypto
.. doxygenfunction:: alcp_rng_request
   :project: crypto
.. doxygenfunction:: alcp_rng_gen_random
   :project: crypto
.. doxygenfunction:: alcp_rng_init
   :project: crypto
.. doxygenfunction:: alcp_rng_finish
   :project: crypto

----

Enumerations
------------
.. doxygenenum:: alc_rng_type
   :project: crypto
.. doxygenenum:: alc_rng_source
   :project: crypto
.. doxygenenum:: alc_rng_distrib
   :project: crypto
.. doxygenenum:: alc_rng_algo_flags
   :project: crypto
