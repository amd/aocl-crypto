find_package(Doxygen)
if (DOXYGEN_FOUND)
    # Configuration file
    SET(DOXYGEN_CONFIG_FILE "${CMAKE_SOURCE_DIR}/doxygen/config.doxy")

    message(STATUS "Building Doxygen")

    add_custom_target( docs_api ALL
        COMMAND ${DOXYGEN_EXECUTABLE} ${DOXYGEN_CONFIG_FILE}
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
        COMMENT "Generate API documentation with Doxygen"
        VERBATIM )
else (DOXYGEN_FOUND)
  message(FATAL "Doxygen seems not to be installed, try 'apt install doxygen' if debain based.")
endif (DOXYGEN_FOUND)