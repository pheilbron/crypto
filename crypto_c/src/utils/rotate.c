#include <stdint.h>
#include "crypto_utils.h"

uint64_t	rot_l(uint64_t x, uint8_t shift, uint8_t data_size)
{
	uint64_t	mask;

	mask = 0;
	for (uint8_t i = 0; i < data_size; i++)
		mask |= 1 << i;
	if (shift < data_size)
		return (((x << shift) | (x >> (data_size - shift))) & mask);
	return (x);
}

uint64_t	rot_r(uint64_t x, uint8_t shift, uint8_t data_size)
{
	uint64_t	mask;

	mask = 0;
	for (uint8_t i = 0; i < data_size; i++)
		mask |= 1 << i;
	if (shift < data_size)
		return (((x >> shift) | (x << (data_size - shift))) & mask);
	return (x);
}
