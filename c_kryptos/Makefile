NAME		= libkryptos.a

AR			= ar
INC_FLAGS	= -I inc -I lib/inc
CFLAGS		= -Wall -Werror -Wextra 
DEBUG_FLAGS	= -g -fsanitize=address

SRC_DIR		= src
OBJ_DIR		= obj

SRC			= read kry_file random
UTILS		= rotate pad_hash pkcs7 u32_block_utils u64_block_utils \
			  u32_be_to_hex u32_le_to_hex u64_be_to_hex u64_le_to_hex \
			  u8_to_u32_be u8_to_u32_le u8_to_u64_be u8_to_u64_le
HASH		= md5 sha1 sha256 sha512 sha_utils #whirlpool

OBJ			= $(patsubst %, $(OBJ_DIR)/%.o, \
		$(SRC) \
		$(patsubst %, utils/%, $(UTILS)) \
		$(patsubst %, hash/%, $(HASH)))

all: $(NAME)

$(NAME): $(OBJ)
	@$(AR) -rcs $@ $(OBJ)
	@ranlib $(NAME)

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c 
	@echo Compiling $<.
	@mkdir -p $(dir $@)
	@$(CC) $(CFLAGS) $(INC_FLAGS) -c $< -o $@

clean:
	rm -rf $(OBJ_DIR)

fclean: clean
	rm -f $(NAME)

re: fclean all
