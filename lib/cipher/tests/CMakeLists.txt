Include(${CMAKE_SOURCE_DIR}/cmake/AlcpTests.cmake)

# Enforcing File Name
file(GLOB TEST_FILES "*_unit_test.cc")
# You can rename files to another name and wont be included

# Bump up C++ standard
SET(CMAKE_CXX_STANDARD 20)

alcp_module("Cipher")

message(STATUS "Cipher Unit Tests Imported ${TEST_FILES}")

foreach(testFile IN LISTS TEST_FILES)
    get_filename_component(currentTestName ${testFile} NAME_WLE)
    get_filename_component(currentTestFile ${testFile} NAME)
    message("Test-> " ${currentTestName} " file " ${currentTestFile} )
    alcp_cc_test(${currentTestName}
             DIRECTORY tests/
             SOURCES   "${currentTestFile}"
             DEPENDS   ${_module_lib}
    )
endforeach()