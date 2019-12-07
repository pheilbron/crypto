#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "crypto.h"
#include "crypto_utils.h"

#define U32_LE_PAD_LEN1(x) (uint32_t)(x * 8) % (1ULL << 32)
#define U32_LE_PAD_LEN2(x) (uint32_t)(x * 8) / (1ULL << 32)
#define U32_BE_PAD_LEN1(x) (uint32_t)(x * 8) / (1ULL << 32)
#define U32_BE_PAD_LEN2(x) (uint32_t)(x * 8) % (1ULL << 32)

uint32_t	md_pad_u8_to_u32(char *in, uint32_t **out, uint8_t type)
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
