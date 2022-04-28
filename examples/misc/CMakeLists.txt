
ADD_EXECUTABLE ( test_logger logger.cc)

TARGET_INCLUDE_DIRECTORIES ( test_logger PRIVATE   
	${CMAKE_SOURCE_DIR}/lib/include )

