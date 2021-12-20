
ADD_SUBDIRECTORY(cipher)

ADD_SUBDIRECTORY(digest)

INCLUDE_DIRECTORIES(
	"${CMAKE_SOURCE_DIR}/include" 
	"${CMAKE_SOURCE_DIR}/lib/include")

#target_link_libraries(cipher ${ALCP})

