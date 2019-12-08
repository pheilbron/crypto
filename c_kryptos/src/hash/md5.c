#include <stdint.h>
#include "kryptos.h"
#include "kryptos_md5.h"
#include "kryptos_block.h"
#include "kryptos_utils.h"

uint32_t	g_constant_tab[] = {0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
	0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501, 0x698098d8, 0x8b44f7af,
	0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
	0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453,
	0xd8a1e681, 0xe7d3fbc8, 0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
	0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681,
	0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
	0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5,
	0x1fa27cf8, 0xc4ac5665, 0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
	0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1, 0x6fa87e4f, 0xfe2ce6e0,
	0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391};

uint32_t	g_shift_tab[] = {
	7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
	5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
	4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
	6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21};

static uint32_t	f(md5_chunk *ch, int i)
{
	uint32_t	f_value;
	uint32_t	g;

	if (i >= 0 && i < 16)
	{
		f_value = (ch->temp[B] & ch->temp[C]) | (~(ch->temp[B]) & ch->temp[D]);
		g = i;
	}
	else if (i > 15 && i < 32)
	{
		f_value = (ch->temp[B] & ch->temp[D]) | (ch->temp[C] & ~(ch->temp[D]));
		g = ((i * 5) + 1) % 16;
	}
	else if (i > 31 && i < 48)
	{
		f_value = (ch->temp[B] ^ ch->temp[C] ^ ch->temp[D]);
		g = ((i * 3) + 5) % 16;
	}
	else
	{
		f_value = ch->temp[C] ^ (ch->temp[B] | ~(ch->temp[D]));
		g = (i * 7) % 16;
	}
	return (f_value + ch->temp[A] + g_constant_tab[i] +
			ch->block.data[g + ch->buf_pos]);
}

static void	set_block(md5_chunk *chunk)
{
	uint32_t	f_value;

	chunk->temp[A] = chunk->hash[A];
	chunk->temp[B] = chunk->hash[B];
	chunk->temp[C] = chunk->hash[C];
	chunk->temp[D] = chunk->hash[D];
	for (int i = 0; i < 64; i++)
	{
		f_value = rot_l(f(chunk, i), g_shift_tab[i], 32);
		chunk->temp[A] = chunk->temp[D];
		chunk->temp[D] = chunk->temp[C];
		chunk->temp[C] = chunk->temp[B];
		chunk->temp[B] += f_value;
	}
	chunk->hash[A] += chunk->temp[A];
	chunk->hash[B] += chunk->temp[B];
	chunk->hash[C] += chunk->temp[C];
	chunk->hash[D] += chunk->temp[D];
}

int		md5(void *data, char **hash, uint8_t type)
{
	md5_chunk	chunk;
	int			status;

	if (!init_u32_block(&chunk.block, 16, 64, type))
		return (0);
	chunk.buf_pos = 0;
	chunk.hash[A] = 0x67452301;
	chunk.hash[B] = 0xefcdab89;
	chunk.hash[C] = 0x98badcfe;
	chunk.hash[D] = 0x10325476;
	if (type == KRY_BUFFER)
	{
		chunk.buf_len = pad1_u8_to_u32(data, &chunk.block.data, LITTLE_END);
		while (chunk.buf_pos < chunk.buf_len)
		{
			set_block(&chunk);
			chunk.buf_pos += 16;
		}
	}
	else
	{
		while ((status = set_u32_block(&chunk.block, data, LITTLE_END)) > 0)
			set_block(&chunk);
		if (status != DONE)
			return (free_u32_block(&chunk.block) & 0);
	}
	if ((*hash = malloc(sizeof(**hash) * (4 * 8 + 1))))
		u32_le_to_hex(chunk.hash, hash, 4);
	return (free_u32_block(&chunk.block));
}
