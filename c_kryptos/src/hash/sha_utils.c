#include <stdint.h>
#include "kryptos_sha_utils.h"

uint32_t	u32_ch(uint32_t a, uint32_t b, uint32_t c)
{
	return ((a & b) ^ (~a & c));
}

uint64_t	u64_ch(uint64_t a, uint64_t b, uint64_t c)
{
	return ((a & b) ^ (~a & c));
}

uint32_t	u32_maj(uint32_t a, uint32_t b, uint32_t c)
{
	return ((a & b) ^ (a & c) ^ (b & c));
}

uint64_t	u64_maj(uint64_t a, uint64_t b, uint64_t c)
{
	return ((a & b) ^ (a & c) ^ (b & c));
}
