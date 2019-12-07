#ifndef CRYPTO_H
# define CRYPTO_H

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

int		crypto_hash_buffer(char *buffer, char **hash, void (*hash)());
int		crypto_hash_file(char *file_name, char **hash, void (*hash)());

int		md5(char *data, char **hash, uint8_t type);
int		sha1(char *data, char **hash, uint8_t type);
int		sha224(char *data, char **hash, uint8_t type);
int		sha256(char *data, char **hash, uint8_t type);
int		sha384(char *data, char **hash, uint8_t type);
int		sha512(char *data, char **hash, uint8_t type);
int		sha512_224(char *data, char **hash, uint8_t type);
int		sha512_256(char *data, char **hash, uint8_t type);

#endif
