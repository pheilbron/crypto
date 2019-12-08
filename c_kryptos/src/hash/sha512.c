#include <stdint.h>
#include "kryptos.h"
#include "kryptos_sha512.h"
#include "kryptos_sha_utils.h"
#include "kryptos_block.h"
#include "kryptos_utils.h"

uint64_t g_sha512_tab[] = {0x428a2f98d728ae22, 0x7137449123ef65cd,
	0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc, 0x3956c25bf348b538,
	0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
	0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c,
	0x550c7dc3d5ffb4e2, 0x72be5d74f27b896f, 0x80deb1fe3b1696b1,
	0x9bdc06a725c71235, 0xc19bf174cf692694, 0xe49b69c19ef14ad2,
	0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
	0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4,
	0x76f988da831153b5, 0x983e5152ee66dfab, 0xa831c66d2db43210,
	0xb00327c898fb213f, 0xbf597fc7beef0ee4, 0xc6e00bf33da88fc2,
	0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
	0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed,
	0x53380d139d95b3df, 0x650a73548baf63de, 0x766a0abb3c77b2a8,
	0x81c2c92e47edaee6, 0x92722c851482353b, 0xa2bfe8a14cf10364,
	0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
	0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a,
	0x106aa07032bbd1b8, 0x19a4c116b8d2d0c8, 0x1e376c085141ab53,
	0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8, 0x391c0cb3c5c95a63,
	0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
	0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72,
	0x8cc702081a6439ec, 0x90befffa23631e28, 0xa4506cebde82bde9,
	0xbef9a3f7b2c67915, 0xc67178f2e372532b, 0xca273eceea26619c,
	0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
	0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae,
	0x1b710b35131c471b, 0x28db77f523047d84, 0x32caab7b40c72493,
	0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c, 0x4cc5d4becb3e42b6,
	0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817};

static uint64_t	message_schedule_sum(uint64_t message_schedule[80],
		uint8_t offset, uint8_t type)
{
	if (type == S0)
		return (rot_r(message_schedule[offset - 2], 19, 64) ^
				rot_r(message_schedule[offset - 2], 61, 64) ^
				(message_schedule[offset - 2] >> 6));
	else if (type == S1)
		return (rot_r(message_schedule[offset - 15], 1, 64) ^
				rot_r(message_schedule[offset - 15], 8, 64) ^
				(message_schedule[offset - 15] >> 7));
	else
		return (0);
}

static uint64_t	compression_sum(sha512_chunk *c, uint8_t type)
{
	if (type == S0)
		return (rot_r(c->temp[A], 28, 64) ^ rot_r(c->temp[A], 34, 64) ^
				rot_r(c->temp[A], 39, 64));
	else if (type == S1)
		return (rot_r(c->temp[E], 14, 64) ^ rot_r(c->temp[E], 18, 64) ^
				rot_r(c->temp[E], 41, 64));
	else
		return (0);
}

static void	init_message_schedule(sha512_chunk *chunk)
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
		chunk->s[i] = message_schedule_sum(chunk->s, i, S1) +
			chunk->s[i - 7] + message_schedule_sum(chunk->s, i, S0) +
			chunk->s[i - 16];
		i++;
	}
}

static void		update_block(sha512_chunk *chunk)
{
	uint64_t	temp1;
	uint64_t	temp2;

	chunk->temp[A] = chunk->hash[A];
	chunk->temp[B] = chunk->hash[B];
	chunk->temp[C] = chunk->hash[C];
	chunk->temp[D] = chunk->hash[D];
	chunk->temp[E] = chunk->hash[E];
	chunk->temp[F] = chunk->hash[F];
	chunk->temp[G] = chunk->hash[G];
	chunk->temp[H] = chunk->hash[H];
	for (int i = 0; i < 80; i++)
	{
		temp1 = compression_sum(chunk, S1) +
			u64_ch(chunk->temp[E], chunk->temp[F], chunk->temp[G]) +
			chunk->temp[H] + chunk->s[i] + g_sha512_tab[i];
		temp2 = compression_sum(chunk, S0) +
			u64_maj(chunk->temp[A], chunk->temp[B], chunk->temp[C]);
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

int	sha384(void *data, char **hash, uint8_t type)
{
	sha512_chunk	chunk;
	int				status;

	if (!init_u64_block(&chunk.block, 16, 128, type))
		return (0);
	chunk.buf_pos = 0;
	chunk.hash[A] = 0xcbbb9d5dc1059ed8;
	chunk.hash[B] = 0x629a292a367cd507;
	chunk.hash[C] = 0x9159015a3070dd17;
	chunk.hash[D] = 0x152fecd8f70e5939;
	chunk.hash[E] = 0x67332667ffc00b31;
	chunk.hash[F] = 0x8eb44a8768581511;
	chunk.hash[G] = 0xdb0c2e0d64f98fa7;
	chunk.hash[H] = 0x47b5481dbefa4fa4;
	if (type == KRY_BUFFER)
	{
		chunk.buf_len = pad1_u8_to_u64(data, &chunk.block.data, BIG_END);
		while (chunk.buf_pos < chunk.buf_len)
		{
			init_message_schedule(&chunk);
			update_block(&chunk);
			chunk.buf_pos += 16;
		}
	}
	else
	{
		while ((status = set_u64_block(&chunk.block, data, BIG_END)) > 0)
		{
			init_message_schedule(&chunk);
			update_block(&chunk);
		}
		if (status != DONE)
			return (free_u64_block(&chunk.block) & 0);
	}
	if ((*hash = malloc(sizeof(**hash) * (6 * 16 + 1))))
		u64_be_to_hex(chunk.hash, hash, 6);
	return (free_u64_block(&chunk.block));
}

int	sha512(void *data, char **hash, uint8_t type)
{
	sha512_chunk	chunk;
	int				status;

	if (!init_u64_block(&chunk.block, 16, 128, type))
		return (0);
	chunk.buf_pos = 0;
	chunk.hash[A] = 0x6a09e667f3bcc908;
	chunk.hash[B] = 0xbb67ae8584caa73b;
	chunk.hash[C] = 0x3c6ef372fe94f82b;
	chunk.hash[D] = 0xa54ff53a5f1d36f1;
	chunk.hash[E] = 0x510e527fade682d1;
	chunk.hash[F] = 0x9b05688c2b3e6c1f;
	chunk.hash[G] = 0x1f83d9abfb41bd6b;
	chunk.hash[H] = 0x5be0cd19137e2179;
	if (type == KRY_BUFFER)
	{
		chunk.buf_len = pad1_u8_to_u64(data, &chunk.block.data, BIG_END);
		while (chunk.buf_pos < chunk.buf_len)
		{
			init_message_schedule(&chunk);
			update_block(&chunk);
			chunk.buf_pos += 16;
		}
	}
	else
	{
		while ((status = set_u64_block(&chunk.block, data, BIG_END)) > 0)
		{
			init_message_schedule(&chunk);
			update_block(&chunk);
		}
		if (status != DONE)
			return (free_u64_block(&chunk.block) & 0);
	}
	if ((*hash = malloc(sizeof(**hash) * (8 * 16 + 1))))
		u64_be_to_hex(chunk.hash, hash, 8);
	return (free_u64_block(&chunk.block));
}

int	sha512_224(void *data, char **hash, uint8_t type)
{
	sha512_chunk	chunk;
	int				status;

	if (!init_u64_block(&chunk.block, 16, 128, type))
		return (0);
	chunk.buf_pos = 0;
	chunk.hash[A] = 0x8C3D37C819544DA2;
	chunk.hash[B] = 0x73E1996689DCD4D6;
	chunk.hash[C] = 0x1DFAB7AE32FF9C82;
	chunk.hash[D] = 0x679DD514582F9FCF;
	chunk.hash[E] = 0x0F6D2B697BD44DA8;
	chunk.hash[F] = 0x77E36F7304C48942;
	chunk.hash[G] = 0x3F9D85A86A1D36C8;
	chunk.hash[H] = 0x1112E6AD91D692A1;
	if (type == KRY_BUFFER)
	{
		chunk.buf_len = pad1_u8_to_u64(data, &chunk.block.data, BIG_END);
		while (chunk.buf_pos < chunk.buf_len)
		{
			init_message_schedule(&chunk);
			update_block(&chunk);
			chunk.buf_pos += 16;
		}
	}
	else
	{
		while ((status = set_u64_block(&chunk.block, data, BIG_END)) > 0)
		{
			init_message_schedule(&chunk);
			update_block(&chunk);
		}
		if (status != DONE)
			return (free_u64_block(&chunk.block) & 0);
	}
	if ((*hash = malloc(sizeof(**hash) * (7 * 8 + 1))))
		u32_be_to_hex((uint32_t *)chunk.hash, hash, 7);
	return (free_u64_block(&chunk.block));
}

int	sha512_256(void *data, char **hash, uint8_t type)
{
	sha512_chunk	chunk;
	int				status;

	if (!init_u64_block(&chunk.block, 16, 128, type))
		return (0);
	chunk.buf_pos = 0;
	chunk.hash[A] = 0x22312194FC2BF72C;
	chunk.hash[B] = 0x9F555FA3C84C64C2;
	chunk.hash[C] = 0x2393B86B6F53B151;
	chunk.hash[D] = 0x963877195940EABD;
	chunk.hash[E] = 0x96283EE2A88EFFE3;
	chunk.hash[F] = 0xBE5E1E2553863992;
	chunk.hash[G] = 0x2B0199FC2C85B8AA;
	chunk.hash[H] = 0x0EB72DDC81C52CA2;
	if (type == KRY_BUFFER)
	{
		chunk.buf_len = pad1_u8_to_u64(data, &chunk.block.data, BIG_END);
		while (chunk.buf_pos < chunk.buf_len)
		{
			init_message_schedule(&chunk);
			update_block(&chunk);
			chunk.buf_pos += 16;
		}
	}
	else
	{
		while ((status = set_u64_block(&chunk.block, data, BIG_END)) > 0)
		{
			init_message_schedule(&chunk);
			update_block(&chunk);
		}
		if (status != DONE)
			return (free_u64_block(&chunk.block) & 0);
	}
	if ((*hash = malloc(sizeof(**hash) * (4 * 16 + 1))))
		u64_be_to_hex(chunk.hash, hash, 4);
	return (free_u64_block(&chunk.block));
}
