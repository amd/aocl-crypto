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
.. doxygenfunction:: alcp_rng_seed
   :project: crypto
.. doxygenfunction:: alcp_rng_finish
   :project: crypto
    
----

Variables
---------
.. doxygenvariable:: alc_rng_type_t
   :project: crypto
.. doxygenvariable:: alc_rng_source_t
   :project: crypto
.. doxygenvariable:: alc_rng_distrib_t
   :project: crypto
.. doxygenvariable:: alc_rng_algo_flags_t
   :project: crypto
