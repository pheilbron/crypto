#ifndef NREAD_H
# define NREAD_H

# define BUF_SIZE 4096

struct	s_holder
{
	char	buf[BUF_SIZE];
	int		i;
	int		len;
};

int		nread(int fd, char *buf, int size);

#endif
