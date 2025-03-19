MAC
**********
A Message Authentication Code (MAC) is a cryptographic technique used to verify the authenticity and integrity of a message, ensuring that it has not been tampered during transmission.

----

Data Structures
---------------
.. doxygenstruct:: alc_hmac_info_t
.. doxygenstruct:: alc_cmac_info_t
.. doxygenstruct:: alc_mac_handle_t
.. doxygenunion:: alc_mac_info_t

----

Functions
---------
.. doxygenfunction:: alcp_mac_context_size
.. doxygenfunction:: alcp_mac_request
.. doxygenfunction:: alcp_mac_init
.. doxygenfunction:: alcp_mac_update
.. doxygenfunction:: alcp_mac_finalize
.. doxygenfunction:: alcp_mac_finish
.. doxygenfunction:: alcp_mac_reset 
.. doxygenfunction:: alcp_mac_context_copy
    
----

Variables
---------
.. doxygenvariable:: alc_mac_type_t
    