# Added aocl-compat as a seperate liberary
FILE(GLOB IPP_SRCS "*.cc" )
ADD_LIBRARY(ipp-compat 
	${IPP_SRCS}
	)

# Link to ALCP shared object file
TARGET_LINK_LIBRARIES(ipp-compat PUBLIC alcp)
# Include internal header files
TARGET_INCLUDE_DIRECTORIES(ipp-compat PRIVATE include)

# Include ALCP header files
TARGET_INCLUDE_DIRECTORIES(ipp-compat PRIVATE ${PROJECT_SOURCE_DIR}/include)


