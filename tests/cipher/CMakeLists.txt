find_package(GTest REQUIRED)
find_package(ippcp)

# Include all the ALCP Headers
INCLUDE_DIRECTORIES(
	"${CMAKE_SOURCE_DIR}/include" 
	"${CMAKE_SOURCE_DIR}/lib/include"
    "${CMAKE_CURRENT_SOURCE_DIR}/include")

if(GTest_FOUND)
    if(ippcp_FOUND)
        message(STATUS "Found IPPCP: ${ippcp_DIR}")
        add_compile_options("-DUSE_IPP")
    endif(ippcp_FOUND)
    # CBC
    if(ippcp_FOUND)
        ADD_EXECUTABLE(aes_cbc_kat base/ipp_base.cc base/alc_base.cc base/base.cc test_cbc_kat.cc)
    else(ippcp_FOUND)
        ADD_EXECUTABLE(aes_cbc_kat base/alc_base.cc base/base.cc test_cbc_kat.cc)
    endif(ippcp_FOUND)
    # Depending on the person, they are gonna run from root dir or binary directory
    # Link dataset to the root dir
    file(CREATE_LINK ${CMAKE_CURRENT_SOURCE_DIR}/dataset/dataset_cbc.csv ${CMAKE_BINARY_DIR}/dataset_cbc.csv SYMBOLIC)
    # Link dataset to the actual place of test binary
    file(CREATE_LINK ${CMAKE_CURRENT_SOURCE_DIR}/dataset/dataset_cbc.csv ${CMAKE_CURRENT_BINARY_DIR}/dataset_cbc.csv SYMBOLIC)
    target_link_libraries(aes_cbc_kat alcp)
    target_link_libraries(aes_cbc_kat "${GTEST_LIBRARY}/libgtest.a")
    target_link_libraries(aes_cbc_kat pthread)
    if(ippcp_FOUND)
       target_link_libraries(aes_cbc_kat ippcpmx)
    endif(ippcp_FOUND)

    # OFB
    if(ippcp_FOUND)
        ADD_EXECUTABLE(aes_ofb_kat base/ipp_base.cc base/alc_base.cc base/base.cc test_ofb_kat.cc)
    else(ippcp_FOUND)
        ADD_EXECUTABLE(aes_ofb_kat base/alc_base.cc base/base.cc test_ofb_kat.cc)
    endif(ippcp_FOUND)
    # Depending on the person, they are gonna run from root dir or binary directory
    # Link dataset to the root dir
    file(CREATE_LINK ${CMAKE_CURRENT_SOURCE_DIR}/dataset/dataset_ofb.csv ${CMAKE_BINARY_DIR}/dataset_ofb.csv SYMBOLIC)
    # Link dataset to the actual place of test binary
    file(CREATE_LINK ${CMAKE_CURRENT_SOURCE_DIR}/dataset/dataset_ofb.csv ${CMAKE_CURRENT_BINARY_DIR}/dataset_ofb.csv SYMBOLIC)
    target_link_libraries(aes_ofb_kat alcp)
    target_link_libraries(aes_ofb_kat "${GTEST_LIBRARY}/libgtest.a")
    target_link_libraries(aes_ofb_kat pthread)
    if(ippcp_FOUND)
       target_link_libraries(aes_ofb_kat ippcpmx)
    endif(ippcp_FOUND)

    # CFB
    if(ippcp_FOUND)
        ADD_EXECUTABLE(aes_cfb_kat base/ipp_base.cc base/alc_base.cc base/base.cc test_cfb_kat.cc)
    else(ippcp_FOUND)
        ADD_EXECUTABLE(aes_cfb_kat base/alc_base.cc base/base.cc test_cfb_kat.cc)
    endif(ippcp_FOUND)
    # Depending on the person, they are gonna run from root dir or binary directory
    # Link dataset to the root dir
    file(CREATE_LINK ${CMAKE_CURRENT_SOURCE_DIR}/dataset/dataset_cfb.csv ${CMAKE_BINARY_DIR}/dataset_cfb.csv SYMBOLIC)
    # Link dataset to the actual place of test binary
    file(CREATE_LINK ${CMAKE_CURRENT_SOURCE_DIR}/dataset/dataset_cfb.csv ${CMAKE_CURRENT_BINARY_DIR}/dataset_cfb.csv SYMBOLIC)
    target_link_libraries(aes_cfb_kat alcp)
    target_link_libraries(aes_cfb_kat "${GTEST_LIBRARY}/libgtest.a")
    target_link_libraries(aes_cfb_kat pthread)
    if(ippcp_FOUND)
       target_link_libraries(aes_cfb_kat ippcpmx)
    endif(ippcp_FOUND)

     # CTR
    if(ippcp_FOUND)
        ADD_EXECUTABLE(aes_ctr_kat base/ipp_base.cc base/alc_base.cc base/base.cc test_ctr_kat.cc)
    else(ippcp_FOUND)
        ADD_EXECUTABLE(aes_ctr_kat base/alc_base.cc base/base.cc test_ctr_kat.cc)
    endif(ippcp_FOUND)
    # Depending on the person, they are gonna run from root dir or binary directory
    # Link dataset to the root dir
    file(CREATE_LINK ${CMAKE_CURRENT_SOURCE_DIR}/dataset/dataset_ctr.csv ${CMAKE_BINARY_DIR}/dataset_ctr.csv SYMBOLIC)
    # Link dataset to the actual place of test binary
    file(CREATE_LINK ${CMAKE_CURRENT_SOURCE_DIR}/dataset/dataset_ctr.csv ${CMAKE_CURRENT_BINARY_DIR}/dataset_ctr.csv SYMBOLIC)
    target_link_libraries(aes_ctr_kat alcp)
    target_link_libraries(aes_ctr_kat "${GTEST_LIBRARY}/libgtest.a")
    target_link_libraries(aes_ctr_kat pthread)
    if(ippcp_FOUND)
       target_link_libraries(aes_ctr_kat ippcpmx)
    endif(ippcp_FOUND)
    
    
else(GTest_FOUND)
    message(FATAL_ERROR "Gtest not found, cannot build tests!")
endif(GTest_FOUND)
