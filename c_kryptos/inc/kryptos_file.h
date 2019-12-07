#ifndef KRYPTOS_FILE
# define KRYPTOS_FILE

# include <stdint.h>
# include "kryptos_error.h"

typedef struct	s_kry_file
{
	int		fd;
	char	*name;
	int		e;
}				kry_file;

kry_file		*init_kry_file(void);
int				open_kry_file(kry_file *file);
int				free_kry_file(kry_file *file);

#endif
