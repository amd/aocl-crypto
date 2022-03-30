include(FetchContent)
include(GoogleTest)
FetchContent_Declare(gtest
    GIT_REPOSITORY https://github.com/google/googletest.git
    GIT_TAG 4523B6410BFCD3289597FA2B5B6E18DE)
FetchContent_MakeAvailable(gtest)

# Basic sources and libs needed for ALCP
set(ALC_BASE_FILES ${ALC_BASE_FILES} ../common/base/rng_base.cc base/alc_base.cc base/base.cc)
set(LIBS ${LIBS} gtest alcp)

if(ENABLE_TESTS_IPP_API)
    add_compile_options("-DUSE_IPP")
    # If there is IPP, add IPP source and add IPP liberary
    set(EXTRA_SOURCES ${EXTRA_SOURCES} base/ipp_base.cc)
    set(LIBS ${LIBS} ${IPP_INSTALL_DIR}/lib/intel64/libippcp.a)
endif(ENABLE_TESTS_IPP_API)

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
    target_include_directories(aes_${MOD}_kat PRIVATE
        "${CMAKE_SOURCE_DIR}/include" 
        "${CMAKE_SOURCE_DIR}/lib/include"
        "${CMAKE_CURRENT_SOURCE_DIR}/include"
        "${CMAKE_CURRENT_SOURCE_DIR}/../common/include")
    target_link_libraries(aes_${MOD}_kat ${LIBS})
    gtest_add_tests(TARGET      aes_${MOD}_kat
                    TEST_SUFFIX .${MOD})
endfunction()

function(CROSS_AES MOD)
    ADD_EXECUTABLE(aes_${MOD}_cross test_${MOD}_cross.cc ${ALC_BASE_FILES} ${EXTRA_SOURCES})
    target_include_directories(aes_${MOD}_cross PRIVATE
        "${CMAKE_SOURCE_DIR}/include" 
        "${CMAKE_SOURCE_DIR}/lib/include"
        "${CMAKE_CURRENT_SOURCE_DIR}/include"
        "${CMAKE_CURRENT_SOURCE_DIR}/../common/include")
    target_link_libraries(aes_${MOD}_cross ${LIBS})
    if(OPENSSL_INSTALL_DIR)
        gtest_add_tests(TARGET      aes_${MOD}_cross
                        TEST_SUFFIX .${MOD})
    endif(OPENSSL_INSTALL_DIR)
endfunction()


KAT_AES(cbc)
KAT_AES(cfb)
KAT_AES(ctr)
KAT_AES(ofb)
CROSS_AES(cbc)
CROSS_AES(cfb)
CROSS_AES(ctr)
CROSS_AES(ofb)