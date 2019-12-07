#include "kryptos_utils.h"

int	u64_le_to_hex(uint64_t *in, char **out, uint8_t len)
{
	uint8_t	i;

	i = 0;
	while (i < len)
	{
		(*out)[(i * 16) + 0] = HEX[(in[i] & U32_LE_DIGIT1L) >> U32_LE_SHIFT1L];
		(*out)[(i * 16) + 1] = HEX[(in[i] & U32_LE_DIGIT1R) >> U32_LE_SHIFT1R];
		(*out)[(i * 16) + 2] = HEX[(in[i] & U32_LE_DIGIT2L) >> U32_LE_SHIFT2L];
		(*out)[(i * 16) + 3] = HEX[(in[i] & U32_LE_DIGIT2R) >> U32_LE_SHIFT2R];
		(*out)[(i * 16) + 4] = HEX[(in[i] & U32_LE_DIGIT3L) >> U32_LE_SHIFT3L];
		(*out)[(i * 16) + 5] = HEX[(in[i] & U32_LE_DIGIT3R) >> U32_LE_SHIFT3R];
		(*out)[(i * 16) + 6] = HEX[(in[i] & U32_LE_DIGIT4L) >> U32_LE_SHIFT4L];
		(*out)[(i * 16) + 7] = HEX[(in[i] & U32_LE_DIGIT4R) >> U32_LE_SHIFT4R];
		(*out)[(i * 16) + 8] = HEX[(in[i] & U64_LE_DIGIT1L) >> U64_LE_SHIFT1L];
		(*out)[(i * 16) + 9] = HEX[(in[i] & U64_LE_DIGIT1R) >> U64_LE_SHIFT1R];
		(*out)[(i * 16) + 10] = HEX[(in[i] & U64_LE_DIGIT2L) >> U64_LE_SHIFT2L];
		(*out)[(i * 16) + 11] = HEX[(in[i] & U64_LE_DIGIT2R) >> U64_LE_SHIFT2R];
		(*out)[(i * 16) + 12] = HEX[(in[i] & U64_LE_DIGIT3L) >> U64_LE_SHIFT3L];
		(*out)[(i * 16) + 13] = HEX[(in[i] & U64_LE_DIGIT3R) >> U64_LE_SHIFT3R];
		(*out)[(i * 16) + 14] = HEX[(in[i] & U64_LE_DIGIT4L) >> U64_LE_SHIFT4L];
		(*out)[(i * 16) + 15] = HEX[(in[i] & U64_LE_DIGIT4R) >> U64_LE_SHIFT4R];
		i++;
	}
	(*out)[i * 16] = '\0';
	return (len);
}
