#ifndef KRYPTOS_BLOCK_H
# define KRYPTOS_BLOCK_H

# include <stdint.h>
# include "kryptos_file.h"

# define DONE -1

typedef struct	s_u32_block
{
	uint32_t	*data;
	int			size;
	uint32_t	*bit_len;
	int			bit_len_size;
	int			padding;
}				u32_block;

typedef struct	s_u64_block
{
	uint64_t	*data;
	int			size;
	uint64_t	*bit_len;
	int			bit_len_size;
	int			padding;
}				u64_block;

int	init_u32_block(u32_block *block, int size, int bit_len_size, char endian);
int	set_u32_block(u32_block *out, kry_file *in, uint8_t type);
int	free_u32_block(u32_block *block);

int	init_u64_block(u64_block *block, int size, int  bit_len_size, char endian);
int	set_u64_block(u64_block *out, kry_file *in, uint8_t type);
int	free_u64_block(u64_block *block);

#endif
