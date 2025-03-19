RNG
**********
Random number generation is a crucial component of cryptography, used to create keys and prevent attackers from predicting or replicating patterns in data. It is typically implemented using specialized algorithms or hardware.

----

Data Structures
---------------
.. doxygenstruct:: alc_rng_info_t
.. doxygenstruct:: alc_rng_handle_t

----

Functions
---------
.. doxygenfunction:: alcp_rng_supported 
.. doxygenfunction:: alcp_rng_context_size
.. doxygenfunction:: alcp_rng_request 
.. doxygenfunction:: alcp_rng_gen_random
.. doxygenfunction:: alcp_rng_init
.. doxygenfunction:: alcp_rng_seed
.. doxygenfunction:: alcp_rng_finish
    
----

Variables
---------
.. doxygenvariable:: alc_rng_type_t
.. doxygenvariable:: alc_rng_source_t
.. doxygenvariable:: alc_rng_distrib_t
.. doxygenvariable:: alc_rng_algo_flags_t
