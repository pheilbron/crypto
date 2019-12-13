#ifndef KRYPTOS_H
# define KRYPTOS_H

# define MD5 1
# define SHA1 1 << 1
# define SHA224 1 << 2
# define SHA256 1 << 3
# define SHA384 1 << 4
# define SHA512 1 << 5
# define SHA512_224 1 << 6
# define SHA512_256 1 << 7
# define WHIRLPOOL 1 << 8

# define CBC 1
# define CFB 2
# define CTR 3
# define ECB 4
# define OFB 5
# define PCBC 6

# define LITTLE_END 1
# define LE 1
# define BIG_END 2
# define BE 2

# define KRY_FILE 1
# define KRY_BUFFER 2

typedef	uint16_t	kry_algorithm_data;

typedef struct	s_kry_algorithm
{
	kry_algorithm_data	type : 13;
	kry_algorithm_data	mode : 3;
	char				*name;
	int					(*f)();
	void				(*pbkdf)();
}				kry_algorithm;

typedef	struct	s_kry_context
{
	kry_algorithm_data	algorithm;
	char				*key;
	char				*salt;
	char				*iv;
}				kry_context;

kry_context	*get_context(kry_algorithm_data algorithm, char *password,
		void (*pbkdf)());

int		krp_enc_buffer(char *buffer, char **out, kry_context *c);
int		krp_enc_file(char *file_name, char **out, kry_context *c);

int		md5(void *data, char **hash, uint8_t type);
int		sha1(void *data, char **hash, uint8_t type);
int		sha224(void *data, char **hash, uint8_t type);
int		sha256(void *data, char **hash, uint8_t type);
int		sha384(void *data, char **hash, uint8_t type);
int		sha512(void *data, char **hash, uint8_t type);
int		sha512_224(void *data, char **hash, uint8_t type);
int		sha512_256(void *data, char **hash, uint8_t type);

int		des_cbc(void *data, char **enc, uint8_t type);
int		des_cfb(void *data, char **enc, uint8_t type);
int		des_ctr(void *data, char **enc, uint8_t type);
int		des_ecb(void *data, char **enc, uint8_t type);
int		des_ofb(void *data, char **enc, uint8_t type);
int		des_pcbc(void *data, char **enc, uint8_t type);

#endif
