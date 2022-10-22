#INCLUDE_DIRECTORIES(
#	${CMAKE_SOURCE_DIR}/include
#	${CMAKE_SOURCE_DIR}/lib/include
#	)

ADD_EXECUTABLE(aes-cfb aes-cfb.c)

ADD_EXECUTABLE(aes-demo aes-demo.c)

ADD_EXECUTABLE(aes-xts aes-xts.c)

ADD_EXECUTABLE(aes-ccm aes-ccm.c)
