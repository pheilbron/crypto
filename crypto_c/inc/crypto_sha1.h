#ifndef CRYPTO_SHA1_H
# define CRYPTO_SHA1_H

# include <stdint.h>
# include "crypto_md_block.h"

# define A 0
# define B 1
# define C 2
# define D 3
# define E 4

typedef struct	s_sha1_chunk
{
	t_u32_md_block	block;
	uint32_t		buf_len;
	uint32_t		buf_pos;
	uint32_t		s[80];
	uint32_t		hash[5];
	uint32_t		temp[5];
}				t_sha1_chunk;

#endif
