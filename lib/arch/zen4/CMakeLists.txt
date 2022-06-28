
FILE(GLOB ZEN4_SRCS "*.cc")

IF (MSVC)
	SET(ARCH_COMPILE_FLAG /arch:znver4)
ELSE()

	SET(ARCH_COMPILE_FLAG -fPIC -znver3 -mavx -mavx2 -maes -mvaes -mpclmul -mavx512f -mavx512dq -mavx512ifma -mavx512cd
	                      -mavx512bw -mavx512vl -mavx512vbmi -mavx512vbmi2 -mavx512vnni -mavx512bitalg -mavx512vpopcntdq
						  -mvpclmulqdq -DUSE_AVX512)

ENDIF()

#CMAKE_POLICY(SET CMP0079 NEW)

ADD_COMPILE_OPTIONS(${ARCH_COMPILE_FLAG})

INCLUDE_DIRECTORIES(${CMAKE_SOURCE_DIR}/lib/include)

ADD_LIBRARY(arch_zen4
	STATIC
	${ZEN4_SRCS})


TARGET_LINK_LIBRARIES(alcp PRIVATE arch_zen4)

