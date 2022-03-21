find_package(GTest REQUIRED)

# Include all the ALCP Headers
INCLUDE_DIRECTORIES(
	"${CMAKE_SOURCE_DIR}/include" 
	"${CMAKE_SOURCE_DIR}/lib/include"
        "${CMAKE_CURRENT_SOURCE_DIR}/include")

if(GTest_FOUND)
    ADD_EXECUTABLE(test_digest base/alc_base.cc
                               base/base.cc
                               test_main.cc)
    # Link dataset to the root dir
    file(CREATE_LINK ${CMAKE_CURRENT_SOURCE_DIR}/test_data/dataset_SHA_224.csv ${CMAKE_BINARY_DIR}/dataset_SHA_224.csv SYMBOLIC)
    # Link dataset to the actual place of test binary
    file(CREATE_LINK ${CMAKE_CURRENT_SOURCE_DIR}/test_data/dataset_SHA_224.csv ${CMAKE_CURRENT_BINARY_DIR}/dataset_SHA_224.csv SYMBOLIC)

    # Link dataset to the root dir
    file(CREATE_LINK ${CMAKE_CURRENT_SOURCE_DIR}/test_data/dataset_SHA_256.csv ${CMAKE_BINARY_DIR}/dataset_SHA_256.csv SYMBOLIC)
    # Link dataset to the actual place of test binary
    file(CREATE_LINK ${CMAKE_CURRENT_SOURCE_DIR}/test_data/dataset_SHA_256.csv ${CMAKE_CURRENT_BINARY_DIR}/dataset_SHA_256.csv SYMBOLIC)

    # Link dataset to the root dir
    file(CREATE_LINK ${CMAKE_CURRENT_SOURCE_DIR}/test_data/dataset_SHA_384.csv ${CMAKE_BINARY_DIR}/dataset_SHA_384.csv SYMBOLIC)
    # Link dataset to the actual place of test binary
    file(CREATE_LINK ${CMAKE_CURRENT_SOURCE_DIR}/test_data/dataset_SHA_384.csv ${CMAKE_CURRENT_BINARY_DIR}/dataset_SHA_384.csv SYMBOLIC)

    # Link dataset to the root dir
    file(CREATE_LINK ${CMAKE_CURRENT_SOURCE_DIR}/test_data/dataset_SHA_512.csv ${CMAKE_BINARY_DIR}/dataset_SHA_512.csv SYMBOLIC)
    # Link dataset to the actual place of test binary
    file(CREATE_LINK ${CMAKE_CURRENT_SOURCE_DIR}/test_data/dataset_SHA_512.csv ${CMAKE_CURRENT_BINARY_DIR}/dataset_SHA_512.csv SYMBOLIC)

    target_link_libraries(test_digest alcp)
    target_link_libraries(test_digest "${GTEST_LIBRARY}")
    target_link_libraries(test_digest pthread)
else(GTest_FOUND)
    message(FATAL_ERROR "Gtest not found, cannot build tests!")
endif(GTest_FOUND)
