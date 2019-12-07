#ifndef KRYPTOS_BLAKE_H
# define KRYPTOS_BLAKE_H

typedef struct	s_blake256_chunk
{
	u32_block	block;
	uint32_t	buf_len;
	uint32_t	buf_pos;
	uint32_t	state[16];
	uint32_t	temp[8];
	uint32_t	hash[8];
	uint32_t	salt[4];
}				blake256_chunk;

typedef blake256_chunk	blake224_chunk;

#endif
