#ifndef KRYPTOS_SHA512_H
# define KRYPTOS_SHA512_H

# include <stdint.h>
# include "kryptos_block.h"

# define A 0
# define B 1
# define C 2
# define D 3
# define E 4
# define F 5
# define G 6
# define H 7

typedef struct	s_sha512_chunk
{
	u64_block	block;
	uint32_t	buf_len;
	uint32_t	buf_pos;
	uint64_t	s[80];
	uint64_t	hash[8];
	uint64_t	temp[8];
}				sha512_chunk;

extern uint64_t	g_sha512_tab[];

#endif
