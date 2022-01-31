
#FILE(GLOB COMMON_SRCS "*.cc" )

#
# The Policy will throw error about TARGET_SOURCES makes the
# relative paths as absolute
#
IF(POLICY CMP0076)
    CMAKE_POLICY(SET CMP0076 NEW)
ENDIF()

IF(POLICY CMP0079)
    CMAKE_POLICY(SET CMP0079 NEW)
ENDIF()


SET(ALCP_VRS_SRC
	version.cc)

SET(ALCP_COMMON_SRCS
	algorithm.cc
	dynlib.cc
	error.cc
	module.cc
	modulemanager.cc
	)

#[==[
# add_compile_options_config(<CONFIG> <option> ...)
#FUNCTION(ADD_COMPILE_OPTIONS_CONFIG CONFIG)
#    FOREACH(opt ${ARGN})
#        ADD_COMPILE_OPTIONS("$<$<CONFIG:${CONFIG}>:${opt}>")
#    ENDFOREACH()
#ENDFUNCTION()
#]==]

include(utils)

IF (MSVC)
	ADD_COMPILE_OPTIONS(/W3 /WX)
ELSE ()
	ADD_COMPILE_OPTIONS("-Wall")
	ADD_COMPILE_OPTIONS_CONFIG(RELEASE "-O2" "-pedantic" "-Werror")
	ADD_COMPILE_OPTIONS_CONFIG(DEBUG "-ggdb")
ENDIF()

INCLUDE_DIRECTORIES(
	${CMAKE_SOURCE_DIR}/include
	)

ADD_LIBRARY(alcp SHARED 
	${ALCP_VRS_SRC}
	)

ADD_SUBDIRECTORY(arch)
ADD_SUBDIRECTORY(capi)
ADD_SUBDIRECTORY(compat)
ADD_SUBDIRECTORY(cipher)
ADD_SUBDIRECTORY(digest)
ADD_SUBDIRECTORY(ref)


TARGET_SOURCES(alcp
	PRIVATE
	#${ARCH_SRCS} 
	#${CIPHER_SRCS}
	#${CAPI_SRCS} 
	#${REF_SRCS} 
	${ALCP_COMMON_SRCS})

TARGET_INCLUDE_DIRECTORIES(alcp PRIVATE
	${CMAKE_CURRENT_SOURCE_DIR}/include)

TARGET_LINK_LIBRARIES(alcp PUBLIC dl)

# Need to build comapt libs after building the libalcp.so
#${COMPAT_SRCS} 
