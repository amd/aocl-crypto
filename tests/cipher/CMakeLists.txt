include(FetchContent)
FetchContent_Declare(gtest
        GIT_REPOSITORY https://github.com/google/googletest.git
        GIT_TAG 4523B6410BFCD3289597FA2B5B6E18DE)
FetchContent_MakeAvailable(gtest)

if(ENABLE_TESTS_IPP_API)
    find_package(ippcp)
endif(ENABLE_TESTS_IPP_API)

# Basic sources and libs needed for ALCP
set(ALC_BASE_FILES ${ALC_BASE_FILES} base/alc_base.cc base/base.cc)
set(LIBS ${LIBS} gtest alcp)

if(ippcp_FOUND)
    message(STATUS "Found IPPCP: ${ippcp_DIR}")
    add_compile_options("-DUSE_IPP")
    # If there is IPP, add IPP source and add IPP liberary
    set(EXTRA_SOURCES ${EXTRA_SOURCES} base/ipp_base.cc)
    set(LIBS ${LIBS} ippcp)
endif(ippcp_FOUND)

if(OPENSSL_INSTALL_DIR)
    add_compile_options("-DUSE_OSSL")
    # If there is OpenSSL, add OpenSSL source and add OpenSSL liberary
    set(EXTRA_SOURCES ${EXTRA_SOURCES} base/openssl_base.cc)
    set(LIBS ${LIBS} ${OPENSSL_INSTALL_DIR}/lib64/libcrypto.so)
endif(OPENSSL_INSTALL_DIR)

set(LIBS ${LIBS} pthread)

# Function to dynamically generate compilation of each test cases
function(KAT_AES MOD)
    ADD_EXECUTABLE(aes_${MOD}_kat test_${MOD}_kat.cc ${ALC_BASE_FILES} ${EXTRA_SOURCES})
    # Depending on the person, they are gonna run from root dir or binary directory
    # Link dataset to the root dir
    file(CREATE_LINK ${CMAKE_CURRENT_SOURCE_DIR}/dataset/dataset_${MOD}.csv ${CMAKE_BINARY_DIR}/dataset_${MOD}.csv SYMBOLIC)
    # Link dataset to the actual place of test binary
    file(CREATE_LINK ${CMAKE_CURRENT_SOURCE_DIR}/dataset/dataset_${MOD}.csv ${CMAKE_CURRENT_BINARY_DIR}/dataset_${MOD}.csv SYMBOLIC)
    target_link_libraries(aes_${MOD}_kat ${LIBS})
endfunction()

# Include all the ALCP Headers
INCLUDE_DIRECTORIES(
	"${CMAKE_SOURCE_DIR}/include" 
	"${CMAKE_SOURCE_DIR}/lib/include"
    "${CMAKE_CURRENT_SOURCE_DIR}/include")

KAT_AES(cbc)
KAT_AES(cfb)
KAT_AES(ctr)
KAT_AES(ofb)
