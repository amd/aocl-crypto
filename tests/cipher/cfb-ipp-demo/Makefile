
TARGET=aes-demo
BUILD_DIR ?= ./build

ifeq (${IPP_HOME},)
$(error IPP_HOME is not set)	
endif
#IPP_SRC:=/home/pmallapp/tmp/ipp-crypto

IPP_INC=-I${IPP_HOME}/include #-I${IPP_SRC}/sources/ippcp
IPP_LIB=${IPP_HOME}/lib/libippcp.a
IPP_SO_LIB=${IPP_HOME}/lib/libippcp.so

CFLAGS := -Wall -march=znver3

ifneq ($(DEBUG),)
	CFLAGS+= -ggdb
else
	CFLAGS+=-O2
endif

SRCS = aes-cfb-ipp.c
       

CFLAGS+=${IPP_INC}
LIBS=${IPP_SO_LIB}

ifneq (${USE_VAES256},)
	CFLAGS+= -DUSE_VAES256
endif

OBJS := $(SRCS:%=$(BUILD_DIR)/%.o)
DEPS := $(OBJS:.o=.d)

all : build_all

build_all: ${BUILD_DIR} ${TARGET} 

${BUILD_DIR}:
	$(MKDIR_P) $@

$(BUILD_DIR)/%.s.o : %.S
	${CC} -c ${CFLAGS} -o $@ $<

$(BUILD_DIR)/%.c.o : %.c
	${CC} -c ${CFLAGS} -o $@ $<

${TARGET}: ${OBJS}
	${CC} ${CFLAGS} ${LDFLAGS} -o $@ $^  ${LIBS}

.PHONY: clean
clean:
	rm -f ${TARGET}
	rm -fr ${BUILD_DIR}

run: 
	# program      dummy   mode     numbuf  datalen count  target  debug
	./${TARGET}	0	 3	 2	 512	 1  	0.0002 	1

-include $(DEPS)

MKDIR_P ?= mkdir -p

