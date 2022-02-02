#INCLUDE_DIRECTORIES(
#	${CMAKE_SOURCE_DIR}/include
#	${CMAKE_SOURCE_DIR}/lib/include
#	)

ADD_EXECUTABLE(aes-cfb aes-cfb.c)
TARGET_LINK_LIBRARIES(aes-cfb PUBLIC alcp)


ADD_EXECUTABLE(aes-demo aes-demo.c aes-key_expansion.c)
TARGET_LINK_LIBRARIES(aes-demo PUBLIC alcp)
