#ifndef KRYPTOS_MD5_H
# define KRYPTOS_MD5_H

# include <stdint.h>
# include "kryptos_block.h"

# define A 0
# define B 1
# define C 2
# define D 3

typedef struct	s_md5_chunk
{
	u32_block	block;
	uint32_t	buf_len;
	uint32_t	buf_pos;
	uint32_t	hash[4];
	uint32_t	temp[4];
}				md5_chunk;

#endif
