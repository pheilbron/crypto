#ifndef KRYPTOS_SHA_UTILS_H
# define KRYPTOS_SHA_UTILS_H

# define ONLOAD 1
# define OFFLOAD 2

# define S0 1
# define S1 2

uint32_t	u32_ch(uint32_t a, uint32_t b, uint32_t c);
uint64_t	u64_ch(uint64_t a, uint64_t b, uint64_t c);
uint32_t	u32_maj(uint32_t a, uint32_t b, uint32_t c);
uint64_t	u64_maj(uint64_t a, uint64_t b, uint64_t c);

#endif
