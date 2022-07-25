FILE(GLOB COMPAT_SRCS "*.cc")

SET(COMPAT_SRCS ${COMPAT_SRCS} PARENT_SCOPE)

# TODO: Move below detection code to something global
# So that there will not be a need to parse it multiple times
SET(ENABLE_OPENSSL_COMPAT FALSE)
SET(ENABLE_IPP_COMPAT FALSE)

IF (AOCL_COMPAT_LIBS)
	# Make comma seperated values (CSV), semicolen seperated values (SSV)
	STRING (REPLACE "," ";" AOCL_COMPAT_LIBS ${AOCL_COMPAT_LIBS})
	# Iterate through each value as it is a proper list
	FOREACH ( value ${AOCL_COMPAT_LIBS} )
		# Compare the value to openssl
		string(COMPARE EQUAL "${value}" "openssl" result)
		IF (result)
			# If comparision true then enable openssl-compat
			SET(ENABLE_OPENSSL_COMPAT TRUE)
			MESSAGE("-- Enabled OpenSSL Compatibility SHIM Layer")
		ENDIF()
		# Compare the value to ipp
		string(COMPARE EQUAL "${value}" "ipp" result)
		IF (result)
			# If comparision true then enable ipp-compat
			SET(ENABLE_IPP_COMPAT TRUE)
			MESSAGE("-- Enabled IPP Compatibility SHIM Layer")
		ENDIF(result)
	ENDFOREACH(value ${AOCL_COMPAT_LIBS})
ENDIF(AOCL_COMPAT_LIBS)

IF (ENABLE_OPENSSL_COMPAT)
    # Adding openssl-compat as a seperate liberary
    ADD_SUBDIRECTORY(openssl)
ENDIF (ENABLE_OPENSSL_COMPAT)

IF (ENABLE_IPP_COMPAT)
	# Adding ipp-compat as a seperate liberary
	ADD_SUBDIRECTORY(ipp)
ENDIF (ENABLE_IPP_COMPAT)

