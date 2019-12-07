#ifndef CRYPTO_SHA512_H
# define CRYPTO_SHA512_H

# include <stdint.h>
# include "crypto_md_block.h"

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
	t_u64_md_block	block;
	uint32_t		buf_len;
	uint32_t		buf_pos;
	uint64_t		s[80];
	uint64_t		hash[8];
	uint64_t		temp[8];
}				t_sha512_chunk;

extern uint64_t	g_sha512_tab[];

void	init_sha512_message_schedule(t_sha512_chunk *chunk);
void	compress_sha512_chunk(t_sha512_chunk *chunk);
void	update_sha512_message_schedule(t_sha512_chunk *chunk, uint8_t type);

#endif
