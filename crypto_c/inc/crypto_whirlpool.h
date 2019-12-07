#ifndef CRYPTO_WHIRLPOOL_H
# define CRYPTO_WHIRLPOOL_H

# include <stdint.h>
# include "crypto_md_block.h"

typedef struct	s_whirlpool_chunk
{
	t_u64_md_block	block;
	uint64_t		state[8];
	uint64_t		temp[8];
	uint64_t		key[8];
}				t_whirlpool_chunk;

#endif
