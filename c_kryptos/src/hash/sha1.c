#include <stdint.h>
#include "kryptos.h"
#include "kryptos_sha1.h"
#include "kryptos_block.h"
#include "kryptos_utils.h"

uint32_t	g_sha1_tab[] = {0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xca62c1d6};

static void		init_message_schedule(sha1_chunk *chunk)
{
	uint8_t	i;

	i = 0;
	while (i < 16)
	{
		chunk->s[i] = chunk->block.data[chunk->buf_pos + i];
		i++;
	}
	while (i < 80)
	{
		chunk->s[i] = rot_l(chunk->s[i - 3] ^ chunk->s[i - 8] ^
				chunk->s[i - 14] ^ chunk->s[i - 16], 1, 32);
		i++;
	}
}

static void		set_block(sha1_chunk *chunk)
{
	uint32_t	temp;
	
	chunk->temp[A] = chunk->hash[A];
	chunk->temp[B] = chunk->hash[B];
	chunk->temp[C] = chunk->hash[C];
	chunk->temp[D] = chunk->hash[D];
	chunk->temp[E] = chunk->hash[E];
	for (int i = 0; i < 80; i++)
	{
		if (i < 20)
			temp = (chunk->temp[B] & chunk->temp[C]) |
				(~(chunk->temp[B]) & chunk->temp[D]);
		else if ((i > 19 && i < 40) || (i > 59 && i < 80))
			temp = (chunk->temp[B] ^ chunk->temp[C] ^ chunk->temp[D]);
		else
			temp = (chunk->temp[B] & chunk->temp[C]) |
				(chunk->temp[B] & chunk->temp[D]) |
				(chunk->temp[C] & chunk->temp[D]);
		temp += rot_l(chunk->temp[A], 5, 32) + chunk->temp[E] +
			g_sha1_tab[i / 20] + chunk->s[i];
		chunk->temp[E] = chunk->temp[D];
		chunk->temp[D] = chunk->temp[C];
		chunk->temp[C] = rot_l(chunk->temp[B], 30, 32);
		chunk->temp[B] = chunk->temp[A];
		chunk->temp[A] = temp;
	}
	chunk->hash[A] += chunk->temp[A];
	chunk->hash[B] += chunk->temp[B];
	chunk->hash[C] += chunk->temp[C];
	chunk->hash[D] += chunk->temp[D];
	chunk->hash[E] += chunk->temp[E];
}

int		sha1(void *data, char **hash, uint8_t type)
{
	sha1_chunk	chunk;
	int			status;

	if (!init_u32_block(&chunk.block, 16, 64, type))
		return (0);
	chunk.buf_pos = 0;
	chunk.hash[A] = 0x67452301;
	chunk.hash[B] = 0xefcdab89;
	chunk.hash[C] = 0x98badcfe;
	chunk.hash[D] = 0x10325476;
	chunk.hash[E] = 0xc3d2e1f0;
	if (type == KRY_BUFFER)
	{
		chunk.buf_len = pad_hash_u8_to_u32(data, &chunk.block.data, BIG_END);
		while (chunk.buf_pos < chunk.buf_len)
		{
			init_message_schedule(&chunk);
			set_block(&chunk);
			chunk.buf_pos += 16;
		}
	}
	else
	{
		while ((status = set_u32_block(&chunk.block, data, BIG_END)) > 0)
		{
			init_message_schedule(&chunk);
			set_block(&chunk);
		}
		if (status != DONE)
			return (free_u32_block(&chunk.block) & 0);
	}
	if ((*hash = malloc(sizeof(**hash) * (5 * 8 + 1))))
		u32_be_to_hex(chunk.hash, hash, 5);
	return (free_u32_block(&chunk.block));
}
