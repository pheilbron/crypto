#ifndef CRYPTO_FILE
# define CRYPTO_FILE

# include <stdint.h>
# include "crypto_error.h"

typedef struct	s_crypto_file
{
	int			fd;
	char		*name;
	char		*data;
	t_error		e;
}				t_crypto_file;

t_ssl_file		*init_crypto_file(void);
int				open_crypto_file(t_crypto_file *file);
int				free_crypto_file(t_crypto_file *file);

#endif
