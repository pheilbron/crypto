#ifndef KRYPTOS_UTILS_H
# define KRYPTOS_UTILS_H

# include <stdint.h>
# include <stdlib.h>

# define U64_BE_DIGIT1L 0xF000000000000000
# define U64_BE_DIGIT1R 0xF00000000000000
# define U64_BE_DIGIT2L 0xF0000000000000
# define U64_BE_DIGIT2R 0xF000000000000
# define U64_BE_DIGIT3L 0xF00000000000
# define U64_BE_DIGIT3R 0xF0000000000
# define U64_BE_DIGIT4L 0xF000000000
# define U64_BE_DIGIT4R 0xF00000000
# define U32_BE_DIGIT1L 0xF0000000
# define U32_BE_DIGIT1R 0xF000000
# define U32_BE_DIGIT2L 0xF00000
# define U32_BE_DIGIT2R 0xF0000
# define U32_BE_DIGIT3L 0xF000
# define U32_BE_DIGIT3R 0xF00
# define U32_BE_DIGIT4L 0xF0
# define U32_BE_DIGIT4R 0xF

# define U64_BE_SHIFT1L 60
# define U64_BE_SHIFT1R 56
# define U64_BE_SHIFT2L 52
# define U64_BE_SHIFT2R 48
# define U64_BE_SHIFT3L 44
# define U64_BE_SHIFT3R 40
# define U64_BE_SHIFT4L 36
# define U64_BE_SHIFT4R 32
# define U32_BE_SHIFT1L 28
# define U32_BE_SHIFT1R 24
# define U32_BE_SHIFT2L 20
# define U32_BE_SHIFT2R 16
# define U32_BE_SHIFT3L 12
# define U32_BE_SHIFT3R 8
# define U32_BE_SHIFT4L 4
# define U32_BE_SHIFT4R 0

# define U32_LE_DIGIT1L 0xF0
# define U32_LE_DIGIT1R 0xF
# define U32_LE_DIGIT2L 0xF000
# define U32_LE_DIGIT2R 0xF00
# define U32_LE_DIGIT3L 0xF00000
# define U32_LE_DIGIT3R 0xF0000
# define U32_LE_DIGIT4L 0xF0000000
# define U32_LE_DIGIT4R 0xF000000
# define U64_LE_DIGIT1L 0xF000000000
# define U64_LE_DIGIT1R 0xF00000000
# define U64_LE_DIGIT2L 0xF00000000000
# define U64_LE_DIGIT2R 0xF0000000000
# define U64_LE_DIGIT3L 0xF0000000000000
# define U64_LE_DIGIT3R 0xF000000000000
# define U64_LE_DIGIT4L 0xF000000000000000
# define U64_LE_DIGIT4R 0xF00000000000000

# define U32_LE_SHIFT1L 4
# define U32_LE_SHIFT1R 0
# define U32_LE_SHIFT2L 12
# define U32_LE_SHIFT2R 8
# define U32_LE_SHIFT3L 20
# define U32_LE_SHIFT3R 16
# define U32_LE_SHIFT4L 28
# define U32_LE_SHIFT4R 24
# define U64_LE_SHIFT1L 36
# define U64_LE_SHIFT1R 32
# define U64_LE_SHIFT2L 44
# define U64_LE_SHIFT2R 40
# define U64_LE_SHIFT3L 52
# define U64_LE_SHIFT3R 48
# define U64_LE_SHIFT4L 60
# define U64_LE_SHIFT4R 56

# define HEX "0123456789abcdef"

#define U32_LE_PAD_ONE(x) (1UL << 31) >> ((3 - (x % 4)) * 8)
#define U32_BE_PAD_ONE(x) (1UL << 31) >> ((x % 4) * 8)
#define U64_LE_PAD_ONE(x) (1ULL << 63) >> ((7 - (x % 8)) * 8)
#define U64_BE_PAD_ONE(x) (1ULL << 63) >> ((x % 8) * 8)

int			u32_be_to_hex(uint32_t *in, char **out, uint8_t len);
int			u32_le_to_hex(uint32_t *in, char **out, uint8_t len);
int			u64_be_to_hex(uint64_t *in, char **out, uint8_t len);
int			u64_le_to_hex(uint64_t *in, char **out, uint8_t len);

int			u8_to_u32_be(uint8_t *in, uint32_t **out, int len);
int			u8_to_u32_le(uint8_t *in, uint32_t **out, int len);
int			u8_to_u64_be(uint8_t *in, uint64_t **out, int len);
int			u8_to_u64_le(uint8_t *in, uint64_t **out, int len);

uint32_t	pad_hash_u8_to_u32(char *in, uint32_t **out, uint8_t type);
uint64_t	pad_hash_u8_to_u64(char *in, uint64_t **out, uint8_t type);
void		pad_pkcs7(char *in, char *out, int in_len, int block_size);
int			unpad_pkcs7(char *in, char *out, int block_size);

uint64_t	rot_l(uint64_t x, uint8_t shift, uint8_t data_size);
uint64_t	rot_r(uint64_t x, uint8_t shift, uint8_t data_size);

char		*nrandom(size_t n);

#endif
