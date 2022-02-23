# Added aocl-compat as a seperate liberary
ADD_LIBRARY(openssl-compat 
	alcp_provider.c 
	alcp_cipher_prov.c
	alcp_cipher_aes.c
	)

# Link to ALCP shared object file
TARGET_LINK_LIBRARIES(openssl-compat PUBLIC alcp)

# Include ALCP header files
TARGET_INCLUDE_DIRECTORIES(openssl-compat PRIVATE ${PROJECT_SOURCE_DIR}/include)

TARGET_INCLUDE_DIRECTORIES(openssl-compat PRIVATE /home/pmallapp/tmp/openssl/install/release/include)


