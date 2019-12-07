NAME		= libcrypto.a

AR			= ar
CC			= gcc
INC_FLAGS	= -I inc -I lib/inc
CFLAGS		= -Wall -Werror -Wextra 
DEBUG_FLAGS	= -g -fsanitize=address

SRC_DIR		= src
OBJ_DIR		= obj

SRC			= read_data crypto_file random
UTILS		= rotate md_pad_u8_to_u32 md_pad_u8_to_u64 \
			  u32_be_to_u8 u32_le_to_u8 u64_be_to_u8 u64_le_to_u8 \
			  u8_to_u32_be u8_to_u32_le u8_to_u64_be u8_to_u64_le \
			  pkcs7
HASH		= u32_md_block_utils u64_md_block_utils

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
