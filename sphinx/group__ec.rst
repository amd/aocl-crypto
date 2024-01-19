EC API
**********
Elliptic Curve Cryptography (ECC) is a type of public key cryptography that uses the mathematics of elliptic curves to secure information and protect sensitive data.

----

Data Structures
---------------
.. doxygenstruct:: alc_ec_info_t
.. doxygenstruct:: alc_ec_handle_t

----

Functions
---------
.. doxygenfunction:: alcp_ec_context_size
.. doxygenfunction:: alcp_ec_supported 
.. doxygenfunction:: alcp_ec_request 
.. doxygenfunction:: alcp_ec_error 
.. doxygenfunction:: alcp_ec_set_privatekey 
.. doxygenfunction:: alcp_ec_get_publickey
.. doxygenfunction:: alcp_ec_get_secretkey
.. doxygenfunction:: alcp_ec_finish
   
----

Variables
---------
.. doxygenvariable:: alc_ec_curve_id
.. doxygenvariable:: alc_ec_curve_type
.. doxygenvariable:: alc_ec_point_format_id
.. doxygenvariable:: alc_ec_context_t
