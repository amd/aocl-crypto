EC
**********
Elliptic Curve Cryptography (ECC) is a type of public key cryptography that uses the mathematics of elliptic curves to secure information and protect sensitive data.

----

Data Structures
---------------
.. doxygenstruct:: alc_ec_info_t
   :project: crypto
.. doxygenstruct:: alc_ec_handle_t
   :project: crypto

----

Functions
---------
.. doxygenfunction:: alcp_ec_context_size
   :project: crypto
.. doxygenfunction:: alcp_ec_supported 
   :project: crypto
.. doxygenfunction:: alcp_ec_request 
   :project: crypto
.. doxygenfunction:: alcp_ec_set_privatekey 
   :project: crypto
.. doxygenfunction:: alcp_ec_get_publickey
   :project: crypto
.. doxygenfunction:: alcp_ec_get_secretkey
   :project: crypto
.. doxygenfunction:: alcp_ec_finish
   :project: crypto
   
----

Variables
---------
.. doxygenvariable:: alc_ec_curve_id
   :project: crypto
.. doxygenvariable:: alc_ec_curve_type
   :project: crypto
.. doxygenvariable:: alc_ec_point_format_id
   :project: crypto
.. doxygenvariable:: alc_ec_context_t
   :project: crypto
