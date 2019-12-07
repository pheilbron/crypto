#ifndef KRYPTOS_WHIRLPOOL_H
# define KRYPTOS_WHIRLPOOL_H

# include <stdint.h>
# include "kryptos_block.h"

typedef struct	s_whirlpool_chunk
{
	u64_block	block;
	uint64_t	state[8];
	uint64_t	temp[8];
	uint64_t	key[8];
}				whirlpool_chunk;

#endif
