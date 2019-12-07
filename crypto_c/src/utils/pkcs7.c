#include "crypto_utils.h"

void	pad_pkcs7(char *in, char *out, int in_len, int block_size)
{
	int		i;
	char	pad;

	i = 0;
	while (in[i] && i < in_len && i < block_size)
	{
		out[i] = in[i];
		i++;
	}
	pad = block_size - i;
	while (i < block_size)
		out[i++] = pad;
}

int		unpad_pkcs7(char *in, char *out, int block_size)
{
	int		i;
	char	pad;

	pad = in[block_size - 1];
	i = block_size - 1;
	while (block_size - 1 - i < pad && i >= 0)
	{
		if (in[i] != pad)
			return (0);
		i--;
	}
	out[i + 1] = '\0';
	while (i >= 0)
	{
		out[i] = in[i];
		i--;
	}
	return (1);
}
