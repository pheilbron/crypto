#ifndef KRYPTOS_SHA256_H
# define KRYPTOS_SHA256_H

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

typedef struct	s_sha256_chunk
{
	u32_block	block;
	uint32_t	buf_len;
	uint32_t	buf_pos;
	uint32_t	s[64];
	uint32_t	hash[8];
	uint32_t	temp[8];
}				sha256_chunk;

extern uint32_t	g_sha256_tab[];

void	init_sha256_message_schedule(sha256_chunk *chunk);
void	compress_sha256_chunk(sha256_chunk *chunk);
void	update_sha256_message_schedule(sha256_chunk *chunk, uint8_t type);

#endif
