#ifndef CRYPTO_MD_BLOCK_H
# define CRYPTO_MD_BLOCK_H

# include <stdint.h>

# define DONE -1

typedef struct	s_u32_md_block
{
	uint32_t	*data;
	uint8_t		size;
	uint32_t	*bit_len;
	uint8_t		bit_len_size;
	int16_t		padding;
}				t_u32_md_block;

typedef struct	s_u64_md_block
{
	uint64_t	*data;
	uint8_t		size;
	uint64_t	*bit_len;
	uint8_t		bit_len_size;
	int16_t		padding;
}				t_u64_md_block;

int	init_u32_md_block(t_u32_md_block *block, uint8_t hash_size,
		uint8_t bit_len_size, uint8_t type);
int	set_u32_md_block(t_u32_md_block *out, t_ssl_file *in,
		uint8_t type);
int	free_u32_md_block(t_u32_md_block *block);

int	init_u64_md_block(t_u64_md_block *block, uint8_t hash_size,
		uint8_t bit_len_size, uint8_t type);
int	set_u64_md_block(t_u64_md_block *out, t_ssl_file *in,
		uint8_t type);
int	free_u64_md_block(t_u64_md_block *block);

#endif
