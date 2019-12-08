#include <stdint.h>
#include "kryptos_blake.h"

uint32_t	g_blake_256_constant_tab[] = {
	0x243F6A88, 0x85A308D3, 0x13198A2E, 0x03707344,
	0xA4093822, 0x299F31D0, 0x082EFA98, 0xEC4E6C89,
	0x452821E6, 0x38D01377, 0xBE5466CF, 0x34E90C6C,
	0xC0AC29B7, 0xC97C50DD, 0x3F84D5B5, 0xB5470917};

uint64_t	g_blake_512_constatn_tab[] = {
	0x243F6A8885A308D3, 0x13198A2E03707344, 0xA4093822299F31D0, 0x082EFA98EC4E6C89,
	0x452821E638D01377, 0xBE5466CF34E90C6C, 0xC0AC29B7C97C50DD, 0x3F84D5B5B5470917,
	0x9216D5D98979FB1B, 0xD1310BA698DFB5AC, 0x2FFD72DBD01ADFB7, 0xB8E1AFED6A267E96,
	0xBA7C9045F12C7F99, 0x24A19947B3916CF7, 0x0801F2E2858EFC16, 0x636920D871574E69};

uint8_t	g_blake_sigma_tab[] = {
	{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
	{14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
	{11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4},
	{7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
	{9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13},
	{2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
	{12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11},
	{13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
	{6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5},
	{10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0}};

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
	for (int i = 0; i < 14; i++)
	{
	
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

static void	init_state(blake256_chunk *chunk)
{

}

int	blake_224(void *data, char **hash, char *salt, uint8_t type)
{
	chunk.hash[A] = 0xC1059ED8;
	chunk.hash[B] = 0x367CD507;
	chunk.hash[C] = 0x3070DD17;
	chunk.hash[D] = 0xF70E5939;
	chunk.hash[E] = 0xFFC00B31;
	chunk.hash[F] = 0x68581511;
	chunk.hash[G] = 0x64F98FA7;
	chunk.hash[H] = 0xBEFA4FA4;
}

int	blake_384(void *data, char **hash, char *salt, uint8_t type)
{
	chunk.hash[A] = 0xCBBB9D5DC1059ED8;
	chunk.hash[B] = 0x629A292A367CD507;
	chunk.hash[C] = 0x9159015A3070DD17;
	chunk.hash[D] = 0x152FECD8F70E5939;
	chunk.hash[E] = 0x67332667FFC00B31;
	chunk.hash[F] = 0x8EB44A8768581511;
	chunk.hash[G] = 0xDB0C2E0D64F98FA7;
	chunk.hash[H] = 0x47B5481DBEFA4FA4;
}

int	blake_512(void *data, char **hash, char *salt, uint8_t type)
{
	chunk.hash[A] = 0x6A09E667F3BCC908;
	chunk.hash[B] = 0xBB67AE8584CAA73B;
	chunk.hash[C] = 0x3C6EF372FE94F82B;
	chunk.hash[D] = 0xA54FF53A5F1D36F1;
	chunk.hash[E] = 0x510E527FADE682D1;
	chunk.hash[F] = 0x9B05688C2B3E6C1F;
	chunk.hash[G] = 0x1F83D9ABFB41BD6B;
	chunk.hash[H] = 0x5BE0CD19137E2179;
}

int	blake_256(void *data, char **hash, char *salt, uint8_t type)
{
	blake256_chunk	chunk;
	int				status;

	if (!init_u32_block(&chunk.block, 16, 64, type))
		return (0);
	chunk.buf_pos = 0;
	chunk.hash[A] = 0x6A09E667;
	chunk.hash[B] = 0xBB67AE85;
	chunk.hash[C] = 0x3C6EF372;
	chunk.hash[D] = 0xA54FF53A;
	chunk.hash[E] = 0x510E527F;
	chunk.hash[F] = 0x9B05688C;
	chunk.hash[G] = 0x1F83D9AB;
	chunk.hash[H] = 0x5BE0CD19;
	if (salt)
		hex_to_u32_be(salt, &chunk.salt, 4);
	if (type == KRY_BUFFER)
	{
		chunk.buf_len = pad_hash_u8_to_u32(data, &chunk.block.data, BIG_END);
		while (chunk.buf_pos < chunk.buf_len)
		{
			init_state(&chunk);
			update_block(&chunk);
			chunk.buf_pos += 16;
		}
	}
	else
	{
		while ((status = set_u32_block(&chunk.block, data, BIG_END)) > 0)
		{
			init_state(&chunk);
			update_block(&chunk);
		}
		if (status != DONE)
			return (free_u32_block(&chunk.block) & 0);
	}
	if ((*hash = malloc(sizeof(**hash) * (8 * 8 + 1))))
		u32_be_to_hex(chunk.hash, hash, 8);
	return (free_u32_block(&chunk.block));
}
