# Declare the beginning of a new namespace.
#
# As a rule of thumb, every CMakeLists.txt should be a different module, named
# after the directory that contains it, and this function should appear at the
# top of each CMakeLists script.
# Multiple directories can be part of the same module as long as target names
# do not collide.
#

include(CMakeParseArguments)
include(GoogleTest)

macro(alcp_module NAME)
  set(ALCP_MODULE ${NAME})
endmacro()

# Declare a test using googletest.
#
# Parameters:
#   NAME           name of the test.
#   SOURCES        list of test source files, headers included.
#   HEADERS        list of headers to depend on
#   DEPENDS        list of dependencies
#   CONTENTS       list of non-code dependencies, such as test vectors.
#
# Attributes:
#   BROKEN            Known to fail
#   SKIP              Dont add to targets
#   HANGING           Test might hang(such as looking for Entropy)
#   WINDOWS_DISABLED  Dont run on Windows (Why ? you'll know)
#
# Tests added with this macro are automatically registered.
# Each test produces a build target named alcp_test_<MODULE>_<NAME>.
#
#
#   alcp_cc_test(
#     DIRECTORY test/
#       TEST BufferTest WINDOWS_DISABLED
#         SOURCES BufferTest.cc
#         HEADERS BufferTest.hh
#         CONTENTS data/
#   )

function(alcp_cc_test testName)
  if (NOT ALCP_ENABLE_TESTS)
    return()
  endif()

  if (NOT DEFINED ALCP_MODULE)
    message(FATAL_ERROR "alcp module name not defined")
  endif()

  # We replace :: with __ in targets, because :: may not appear in target names.
  # However, the module name should still span multiple name spaces.
  STRING(REPLACE "::" "__" _ESCAPED_ALCP_MODULE ${ALCP_MODULE})
  
  set(testPrefix test)
  set(options BROKEN SKIP WINDOWS_DISABLED)
  set(oneValueArgs CONTENTS DIRECTORY)
  set(multiValueArgs SOURCES HEADERS DEPENDS)
  cmake_parse_arguments(PARSE_ARGV 0 
    ${testPrefix}
    "${options}"
    "${oneValueArgs}"
    "${multiValueArgs}"
    )

  set(_target_name "${_ESCAPED_ALCP_MODULE}_${testName}")
  
  message(STATUS "UNIT TEST TARGET ${_target_name}")

  if ( ${${testPrefix}_SKIP} OR ${${testPrefix}_BROKEN} )
    message("Test : " ${testName} "[SKIPPED]")
    return()
  endif()
  
  if ( ${${testPrefix}_WINDOWS_DISABLED} AND WIN32)
    message("Test : " ${testName} "[WIN32-DISABLED]")
    return()
  endif()

  if ( ${${testPrefix}_SLOW} )
    if (STREQUAL "${alcp_ENABLE_SLOW_TESTS}" "OFF" )
      message("Test : " ${testName} "[SKIPPED] SLOW")
      return()
    endif()
  endif()

  #message("DEPENDS " ${${testPrefix}_DEPENDS})

  file(GLOB TEST_COMMON_SRC ${CMAKE_SOURCE_DIR}/tests/common/base/*.cc)

  if(${ALCP_MODULE} STREQUAL "Cipher")
    SET(TEST_COMMON_SRC ${TEST_COMMON_SRC}
                        ${CMAKE_SOURCE_DIR}/tests/cipher/base/alc_base.cc
                        ${CMAKE_SOURCE_DIR}/tests/cipher/base/base.cc
       )
  endif()


  include_directories(${CMAKE_CURRENT_SOURCE_DIR})
  add_executable(${_target_name}
      ${${testPrefix}_SOURCES}
      ${TEST_COMMON_SRC}
  )

  target_link_libraries(${_target_name}
    gtest_main
    alcp
    ${${testPrefix}_DEPENDS}
  )

  # FIXME: Remove this and replace with equavalent files outside the integration testing area.
  target_include_directories(${_target_name} PRIVATE ${CMAKE_SOURCE_DIR}/tests/include)
  target_include_directories(${_target_name} PRIVATE ${CMAKE_SOURCE_DIR}/tests/common/include)
  target_include_directories(${_target_name} PRIVATE ${CMAKE_SOURCE_DIR}/lib/include)

  #set_property(TARGET ${_target_name}
  #  PROPERTY FOLDER "${alcp_IDE_FOLDER}/Tests")

# FIXME: Disabled for now, forcing standard.
#   set_property(TARGET ${_target_name} PROPERTY CXX_STANDARD ${ALCP_CXX_STANDARD})
#   set_property(TARGET ${_target_name} PROPERTY CXX_STANDARD_REQUIRED true)

  message("Adding Test: " ${_target_name})
  
  if (HAVE_CMAKE_GTEST)
    # If we have CMake's built-in gtest support use it to add each test
    # function as a separate test.
    gtest_add_tests(TARGET ${_target_name}
                    WORKING_DIRECTORY "${CMAKE_BINARY_DIR}"
                    AUTO)
                  set_tests_properties(${test_cases} PROPERTIES TIMEOUT 120)
  else()
    # Otherwise add each test executable as a single test.
    # Note: This was preferred over using gtest_discover_tests because of [1].
    # [1] https://gitlab.kitware.com/cmake/cmake/-/issues/23039
    add_test(NAME ${_target_name} 
            COMMAND ${_target_name} 
            WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
          #set_tests_properties(
          #ctest_run_test_code 
          #PROPERTIES DEPENDS ${_target_name})
  endif()
 
  # TODO: Set the CONTENTS directory and copy its contents to ${CMAKE_BINARY_DIR}
  endfunction(alcp_cc_test)
