find_package(GTest REQUIRED)

# Include all the ALCP Headers
INCLUDE_DIRECTORIES(
	"${CMAKE_SOURCE_DIR}/include" 
	"${CMAKE_SOURCE_DIR}/lib/include")

if(GTest_FOUND)
    # CBC
    ADD_EXECUTABLE(aes_cbc_kat alc_base.cc base.cc test_cbc_kat.cc)
    # Depending on the person, they are gonna run from root dir or binary directory
    # Link dataset to the root dir
    file(CREATE_LINK ${CMAKE_CURRENT_SOURCE_DIR}/dataset_cbc.csv ${CMAKE_BINARY_DIR}/dataset_cbc.csv SYMBOLIC)
    # Link dataset to the actual place of test binary
    file(CREATE_LINK ${CMAKE_CURRENT_SOURCE_DIR}/dataset_cbc.csv ${CMAKE_CURRENT_BINARY_DIR}/dataset_cbc.csv SYMBOLIC)
    target_link_libraries(aes_cbc_kat alcp)
    target_link_libraries(aes_cbc_kat "${GTEST_LIBRARY}/libgtest.a")
    target_link_libraries(aes_cbc_kat pthread)

    # OFB
    ADD_EXECUTABLE(aes_ofb_kat alc_base.cc base.cc test_ofb_kat.cc)
    # Depending on the person, they are gonna run from root dir or binary directory
    # Link dataset to the root dir
    file(CREATE_LINK ${CMAKE_CURRENT_SOURCE_DIR}/dataset_ofb.csv ${CMAKE_BINARY_DIR}/dataset_ofb.csv SYMBOLIC)
    # Link dataset to the actual place of test binary
    file(CREATE_LINK ${CMAKE_CURRENT_SOURCE_DIR}/dataset_ofb.csv ${CMAKE_CURRENT_BINARY_DIR}/dataset_ofb.csv SYMBOLIC)
    target_link_libraries(aes_ofb_kat alcp)
    target_link_libraries(aes_ofb_kat "${GTEST_LIBRARY}/libgtest.a")
    target_link_libraries(aes_ofb_kat pthread)

    # CFB
    ADD_EXECUTABLE(aes_cfb_kat alc_base.cc base.cc test_cfb_kat.cc)
    # Depending on the person, they are gonna run from root dir or binary directory
    # Link dataset to the root dir
    file(CREATE_LINK ${CMAKE_CURRENT_SOURCE_DIR}/dataset_cfb.csv ${CMAKE_BINARY_DIR}/dataset_cfb.csv SYMBOLIC)
    # Link dataset to the actual place of test binary
    file(CREATE_LINK ${CMAKE_CURRENT_SOURCE_DIR}/dataset_cfb.csv ${CMAKE_CURRENT_BINARY_DIR}/dataset_cfb.csv SYMBOLIC)
    target_link_libraries(aes_cfb_kat alcp)
    target_link_libraries(aes_cfb_kat "${GTEST_LIBRARY}/libgtest.a")
    target_link_libraries(aes_cfb_kat pthread)
    
else(GTest_FOUND)
    message(FATAL_ERROR "Gtest not found, cannot build tests!")
endif(GTest_FOUND)
