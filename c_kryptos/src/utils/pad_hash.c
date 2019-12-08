#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include "kryptos.h"
#include "kryptos_utils.h"

#define U32_LE_PAD_LEN1(x) (uint32_t)(x * 8) % (1ULL << 32)
#define U32_LE_PAD_LEN2(x) (uint32_t)(x * 8) / (1ULL << 32)
#define U32_BE_PAD_LEN1(x) (uint32_t)(x * 8) / (1ULL << 32)
#define U32_BE_PAD_LEN2(x) (uint32_t)(x * 8) % (1ULL << 32)

#define U64_LE_PAD_LEN1(x) (x * 8)
#define U64_LE_PAD_LEN2(x) (x / (ULLONG_MAX / 8) * 8)
#define U64_BE_PAD_LEN1(x) (x / (ULLONG_MAX / 8) * 8)
#define U64_BE_PAD_LEN2(x) (x * 8)

uint32_t	pad1_u8_to_u32(char *in, uint32_t **out, uint8_t type)
{
	uint64_t	len;
	uint64_t	out_len;
	uint64_t	i;

	len = strlen(in);
	i = (len * 8) + 65;
	out_len = (i + (512 - (i % 512))) / 32;
	if ((*out = malloc(sizeof(**out) * out_len)))
	{
		if (type == LITTLE_END)
			i = u8_to_u32_le((uint8_t *)in, out, len);
		else
			i = u8_to_u32_be((uint8_t *)in, out, len);
		(*out)[i++] += (type == LE ? U32_LE_PAD_ONE(len) : U32_BE_PAD_ONE(len));
		while (i < out_len - 2)
			(*out)[i++] = 0;
		(*out)[i++] = (type == LE ? U32_LE_PAD_LEN1(len) : U32_BE_PAD_LEN1(len));
		(*out)[i] = (type == LE ? U32_LE_PAD_LEN2(len) : U32_BE_PAD_LEN2(len));
	}
	return (out_len);
}

uint64_t	pad1_u8_to_u64(char *in, uint64_t **out, uint8_t type)
{
	uint64_t	len;
	uint64_t	out_len;
	uint64_t	i;

	len = strlen(in);
	i = (len * 8) + 129;
	out_len = (i + (1024 - (i % 1024))) / 64;
	if ((*out = malloc(sizeof(**out) * out_len)))
	{
		if (type == LITTLE_END)
			i = u8_to_u64_le((uint8_t *)in, out, len);
		else
			i = u8_to_u64_be((uint8_t *)in, out, len);
		(*out)[i++] += (type == LE ? U64_LE_PAD_ONE(len) : U64_BE_PAD_ONE(len));
		while (i < out_len - 2)
			(*out)[i++] = 0;
		(*out)[i++] = (type == LE ? U64_LE_PAD_LEN1(len) : U64_BE_PAD_LEN1(len));
		(*out)[i] = (type == LE ? U64_LE_PAD_LEN2(len) : U64_BE_PAD_LEN2(len));
	}
	return (out_len);
}

uint32_t	pad2_u8_to_u32(char *in, uint32_t **out, uint8_t type)
{
	uint64_t	len;
	uint64_t	out_len;
	uint64_t	i;

	len = strlen(in);
	i = (len * 8) + 65;
	out_len = (i + (512 - (i % 512))) / 32;
	if ((*out = malloc(sizeof(**out) * out_len)))
	{
		if (type == LITTLE_END)
			i = u8_to_u32_le((uint8_t *)in, out, len);
		else
			i = u8_to_u32_be((uint8_t *)in, out, len);
		(*out)[i++] += (type == LE ? U32_LE_PAD_ONE(len) : U32_BE_PAD_ONE(len));
		while (i < out_len - 2)
			(*out)[i++] = 0;
		(*out)[out_len - 3] |= 1UL << (type == LE ? 24 : 0);
		(*out)[i++] = (type == LE ? U32_LE_PAD_LEN1(len) : U32_BE_PAD_LEN1(len));
		(*out)[i] = (type == LE ? U32_LE_PAD_LEN2(len) : U32_BE_PAD_LEN2(len));
	}
	return (out_len);
}

uint64_t	pad2_u8_to_u64(char *in, uint64_t **out, uint8_t type)
{
	uint64_t	len;
	uint64_t	out_len;
	uint64_t	i;

	len = strlen(in);
	i = (len * 8) + 129;
	out_len = (i + (1024 - (i % 1024))) / 64;
	if ((*out = malloc(sizeof(**out) * out_len)))
	{
		if (type == LITTLE_END)
			i = u8_to_u64_le((uint8_t *)in, out, len);
		else
			i = u8_to_u64_be((uint8_t *)in, out, len);
		(*out)[i++] += (type == LE ? U64_LE_PAD_ONE(len) : U64_BE_PAD_ONE(len));
		while (i < out_len - 2)
			(*out)[i++] = 0;
		(*out)[out_len - 3] |= 1ULL << (type == LE ? 56 : 0);
		(*out)[i++] = (type == LE ? U64_LE_PAD_LEN1(len) : U64_BE_PAD_LEN1(len));
		(*out)[i] = (type == LE ? U64_LE_PAD_LEN2(len) : U64_BE_PAD_LEN2(len));
	}
	return (out_len);
}
