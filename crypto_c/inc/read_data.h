#ifndef READ_DATA_H
# define READ_DATA_H

# define BUF_SIZE 4096

struct	s_holder
{
	char	buf[BUF_SIZE];
	int		i;
	int		len;
};

int		crypto_read(int fd, char *buf, int size);

#endif
