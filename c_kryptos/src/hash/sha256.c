#include <stdint.h>
#include "kryptos.h"
#include "kryptos_sha256.h"
#include "kryptos_sha_utils.h"
#include "kryptos_block.h"
#include "kryptos_utils.h"

uint32_t g_sha256_tab[] = {0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
	0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01,
	0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa,
	0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
	0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138,
	0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624,
	0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
	0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f,
	0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

static uint32_t	message_schedule_sum(uint32_t message_schedule[64],
		uint8_t offset, uint8_t type)
{
	if (type == S0)
		return (rot_r(message_schedule[offset - 2], 17, 32) ^
				rot_r(message_schedule[offset - 2], 19, 32) ^
				(message_schedule[offset - 2] >> 10));
	else if (type == S1)
		return (rot_r(message_schedule[offset - 15], 7, 32) ^
				rot_r(message_schedule[offset - 15], 18, 32) ^
				(message_schedule[offset - 15] >> 3));
	else
		return (0);
}

static uint32_t	compression_sum(sha256_chunk *c, uint8_t type)
{
	if (type == S0)
		return (rot_r(c->temp[A], 2, 32) ^ rot_r(c->temp[A], 13, 32) ^
				rot_r(c->temp[A], 22, 32));
	else if (type == S1)
		return (rot_r(c->temp[E], 6, 32) ^ rot_r(c->temp[E], 11, 32) ^
				rot_r(c->temp[E], 25, 32));
	else
		return (0);
}

void	init_message_schedule(sha256_chunk *chunk)
{
	uint8_t	i;

	i = 0;
	while (i < 16)
	{
		chunk->s[i] = chunk->block.data[chunk->buf_pos + i];
		i++;
	}
	while (i < 64)
	{
		chunk->s[i] = message_schedule_sum(chunk->s, i, S1) +
			chunk->s[i - 7] + message_schedule_sum(chunk->s, i, S0) +
			chunk->s[i - 16];
		i++;
	}
}

static void	update_block(sha256_chunk *chunk)
{
	uint32_t	temp1;
	uint32_t	temp2;

	chunk->temp[A] = chunk->hash[A];
	chunk->temp[B] = chunk->hash[B];
	chunk->temp[C] = chunk->hash[C];
	chunk->temp[D] = chunk->hash[D];
	chunk->temp[E] = chunk->hash[E];
	chunk->temp[F] = chunk->hash[F];
	chunk->temp[G] = chunk->hash[G];
	chunk->temp[H] = chunk->hash[H];
	for (int i = 0; i < 64; i++)
	{
		temp1 = compression_sum(chunk, S1) +
			u32_ch(chunk->temp[E], chunk->temp[F], chunk->temp[G]) +
			chunk->temp[H] + chunk->s[i] + g_sha256_tab[i];
		temp2 = compression_sum(chunk, S0) +
			u32_maj(chunk->temp[A], chunk->temp[B], chunk->temp[C]);
		chunk->temp[H] = chunk->temp[G];
		chunk->temp[G] = chunk->temp[F];
		chunk->temp[F] = chunk->temp[E];
		chunk->temp[E] = chunk->temp[D] + temp1;
		chunk->temp[D] = chunk->temp[C];
		chunk->temp[C] = chunk->temp[B];
		chunk->temp[B] = chunk->temp[A];
		chunk->temp[A] = temp1 + temp2;
	}
	chunk->hash[A] += chunk->temp[A];
	chunk->hash[B] += chunk->temp[B];
	chunk->hash[C] += chunk->temp[C];
	chunk->hash[D] += chunk->temp[D];
	chunk->hash[E] += chunk->temp[E];
	chunk->hash[F] += chunk->temp[F];
	chunk->hash[G] += chunk->temp[G];
	chunk->hash[H] += chunk->temp[H];
}

int	sha224(void *data, char **hash, uint8_t type)
{
	sha256_chunk	chunk;
	int				status;

	if (!init_u32_block(&chunk.block, 16, 64, type))
		return (0);
	chunk.buf_pos = 0;
	if (type == KRY_BUFFER)
	{
		chunk.buf_len = pad_hash_u8_to_u32(data, &chunk.block.data, BIG_END);
		while (chunk.buf_pos < chunk.buf_len)
		{
			init_message_schedule(&chunk);
			update_block(&chunk);
			chunk.buf_pos += 16;
		}
	}
	else
	{
		while ((status = set_u32_block(&chunk.block, data, BIG_END)) > 0)
		{
			init_message_schedule(&chunk);
			update_block(&chunk);
		}
		if (status != DONE)
			return (free_u32_block(&chunk.block) & 0);
	}
	if ((*hash = malloc(sizeof(**hash) * (7 * 8 + 1))))
		u32_be_to_hex(chunk.hash, hash, 7);
	return (free_u32_block(&chunk.block));
}

int	sha256(void *data, char **hash, uint8_t type)
{
	sha256_chunk	chunk;
	int				status;

	if (!init_u32_block(&chunk.block, 16, 64, type))
		return (0);
	chunk.buf_pos = 0;
	chunk.hash[A] = 0x6a09e667;
	chunk.hash[B] = 0xbb67ae85;
	chunk.hash[C] = 0x3c6ef372;
	chunk.hash[D] = 0xa54ff53a;
	chunk.hash[E] = 0x510e527f;
	chunk.hash[F] = 0x9b05688c;
	chunk.hash[G] = 0x1f83d9ab;
	chunk.hash[H] = 0x5be0cd19;
	if (type == KRY_BUFFER)
	{
		chunk.buf_len = pad_hash_u8_to_u32(data, &chunk.block.data, BIG_END);
		while (chunk.buf_pos < chunk.buf_len)
		{
			init_message_schedule(&chunk);
			update_block(&chunk);
			chunk.buf_pos += 16;
		}
	}
	else
	{
		while ((status = set_u32_block(&chunk.block, data, BIG_END)) > 0)
		{
			init_message_schedule(&chunk);
			update_block(&chunk);
		}
		if (status != DONE)
			return (free_u32_block(&chunk.block) & 0);
	}
	if ((*hash = malloc(sizeof(**hash) * (8 * 8 + 1))))
		u32_be_to_hex(chunk.hash, hash, 8);
	return (free_u32_block(&chunk.block));
}
