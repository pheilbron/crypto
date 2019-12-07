#include <stdlib.h>
#include "crypto_file.h"
#include "crypto_error.h"

t_crypto_file	*init_crypto_file(void)
{
	t_crypto_file	*file;

	if (!(file = malloc(sizeof(*file))))
		return (NULL);
	file->fd = 0;
	file->name = NULL;
	file->data = NULL;
	file->flag = 0;
	new_error(&(file->e));
	return (file);
}

int			open_ssl_file(t_crypto_file *file)
{
	if ((file->fd = open(data[i], O_DIRECTORY)) >= 0)
	{
		close(file->fd);
		return (ft_error_new(&(file->e), 2, INV_DIR, file->reference));
	}
	if ((file->fd = open(file->reference, O_RDONLY)) < 0)
		ft_error_new(&(file->e), 2, INV_FILE, file->reference);
	return (file->e.no);
}

int			clean_ssl_file(t_crypto_file *file)
{
	if (file->reference && file->fd > 0)
		free(file->reference);
	if (file->data && file->fd != PARSE_ERROR)
		free(file->data);
	free(file);
	return (1);
}
