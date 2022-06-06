# Output directory
OBJ := bin
# Default compiler
CC := gcc
INCLUDE := include
CFLAGS := -Llib -I$(INCLUDE) -lalcp -lamdsecrng -lcpu
# Add more targets as they come.
TARGETS := cipher/aes-cfb cipher/aes-demo digest/sha2_224_example digest/sha2_256_example digest/sha2_384_example digest/sha2_512_example rng/rng-demo

.PHONY: all

all: banner create build

banner:
	@echo "Building examples for AOCL-Crypto"

create:
	@mkdir -p  $(OBJ)/cipher
	@mkdir -p  $(OBJ)/digest
	@mkdir -p  $(OBJ)/rng

build: $(TARGETS)
	@echo "Build Success"

$(TARGETS):
	@$(CC) examples/$@.c -o $(OBJ)/$@ $(CFLAGS)
	@echo "Building "$@

clean:
	@echo "Removing Build Dir"
	@if [ -d $(OBJ) ]; then \
		rm -rf $(OBJ); \
	fi
