# Added aocl-compat as a seperate liberary
ADD_LIBRARY(ipp-compat 
	ipp_aes.cc
    ipp_aes_init.cc
    ipp_sizes.cc
    ipp_wrp.cc
	)

# Link to ALCP shared object file
TARGET_LINK_LIBRARIES(ipp-compat PUBLIC alcp)
# Include internal header files
TARGET_INCLUDE_DIRECTORIES(ipp-compat PRIVATE include)

# Include ALCP header files
TARGET_INCLUDE_DIRECTORIES(ipp-compat PRIVATE ${PROJECT_SOURCE_DIR}/include)


