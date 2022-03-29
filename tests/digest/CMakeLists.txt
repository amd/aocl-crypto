include(FetchContent)
include(GoogleTest)
FetchContent_Declare(gtest
    GIT_REPOSITORY https://github.com/google/googletest.git
    GIT_TAG 4523B6410BFCD3289597FA2B5B6E18DE)
FetchContent_MakeAvailable(gtest)

# Basic sources and libs needed for ALCP
set(ALC_BASE_FILES ${ALC_BASE_FILES} base/alc_base.cc base/base.cc)
set(LIBS ${LIBS} gtest alcp)

if(ENABLE_TESTS_IPP_API)
    add_compile_options("-DUSE_IPP")
    # If there is IPP, add IPP source and add IPP liberary
    set(EXTRA_SOURCES ${EXTRA_SOURCES} base/ipp_base.cc)
    set(LIBS ${LIBS} ${IPP_INSTALL_DIR}/lib/intel64/libippcp.a)
endif(ENABLE_TESTS_IPP_API)

if(OPENSSL_INSTALL_DIR)
    add_compile_options("-DUSE_OSSL")
    #  If there is OpenSSL, add OpenSSL source and add OpenSSL liberary
    set(EXTRA_SOURCES ${EXTRA_SOURCES} base/openssl_base.cc)
    set(LIBS ${LIBS} ${OPENSSL_INSTALL_DIR}/lib64/libcrypto.so)
 endif(OPENSSL_INSTALL_DIR)
 set(LIBS ${LIBS} pthread)

ADD_EXECUTABLE(test_digest test_main.cc ${ALC_BASE_FILES} ${EXTRA_SOURCES})

target_include_directories(test_digest PRIVATE
	"${CMAKE_SOURCE_DIR}/include" 
	"${CMAKE_SOURCE_DIR}/lib/include"
    "${CMAKE_CURRENT_SOURCE_DIR}/include"
    "${CMAKE_CURRENT_SOURCE_DIR}/../common/include")
target_link_libraries(test_digest ${LIBS})

function(TEST_DATA_LINK SHA_ALG)
    # Link dataset to the root dir
    file(CREATE_LINK ${CMAKE_CURRENT_SOURCE_DIR}/test_data/dataset_${SHA_ALG}.csv ${CMAKE_BINARY_DIR}/dataset_${SHA_ALG}.csv SYMBOLIC)
    # Link dataset to the actual place of test binary
    file(CREATE_LINK ${CMAKE_CURRENT_SOURCE_DIR}/test_data/dataset_${SHA_ALG}.csv ${CMAKE_CURRENT_BINARY_DIR}/dataset_${SHA_ALG}.csv SYMBOLIC)
endfunction(TEST_DATA_LINK SHA_ALG)

TEST_DATA_LINK(SHA_224)
TEST_DATA_LINK(SHA_256)
TEST_DATA_LINK(SHA_384)
TEST_DATA_LINK(SHA_512)

gtest_add_tests(TARGET      test_digest
                TEST_SUFFIX .${MOD})