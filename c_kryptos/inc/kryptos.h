#ifndef KRYPTOS_H
# define KRYPTOS_H

# define HASH 1
# define ENC 2

# define CBC 1
# define CFB 2
# define CTR 3
# define ECB 4
# define OFB 5
# define PCBC 6

# define MD5 1
# define SHA1 1 << 1
# define SHA224 1 << 2
# define SHA256 1 << 3
# define SHA384 1 << 4
# define SHA512 1 << 5
# define SHA512_224 1 << 6
# define SHA512_256 1 << 7
# define WHIRLPOOL 1 << 8
# define ALL_MD 0x1FF

# define LITTLE_END 1
# define LE 1
# define BIG_END 2
# define BE 2

# define KRY_FILE 1
# define KRY_BUFFER 2

int		krp_hash_buffer(char *buffer, char **hash, void (*f)());
int		krp_hash_file(char *file_name, char **hash, void (*f)());

int		md5(void *data, char **hash, uint8_t type);
int		sha1(void *data, char **hash, uint8_t type);
int		sha224(void *data, char **hash, uint8_t type);
int		sha256(void *data, char **hash, uint8_t type);
int		sha384(void *data, char **hash, uint8_t type);
int		sha512(void *data, char **hash, uint8_t type);
int		sha512_224(void *data, char **hash, uint8_t type);
int		sha512_256(void *data, char **hash, uint8_t type);

#endif
