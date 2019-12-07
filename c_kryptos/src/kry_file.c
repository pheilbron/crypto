#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include "kryptos_file.h"
#include "kryptos_error.h"

kry_file	*init_kry_file(void)
{
	kry_file	*file;

	if (!(file = malloc(sizeof(*file))))
		return (NULL);
	file->fd = 0;
	file->name = NULL;
	file->e = 1;
	return (file);
}

int	open_kry_file(kry_file *file)
{
	if ((file->fd = open(file->name, O_RDONLY)) < 0)
		file->e = INV_FILE;
	return (file->e);
}

int	clean_kry_file(kry_file *file)
{
	if (file->name)
		free(file->name);
	free(file);
	return (1);
}
