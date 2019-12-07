#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include "crypto.h"
#include "crypto_md_block.h"
#include "crypto_utils.h"
#include "read_data.h"

int			init_u32_md_block(t_u32_md_block *block, uint8_t hash_size,
		short bit_len_size, uint8_t type)
{
	short	i;

	block->size = hash_size;
	if (type == MD_FILE &&
			!(block->data = malloc(sizeof(*(block->data)) * block->size)))
		return (0);
	block->bit_len_size = bit_len_size / 32;
	if (!(block->bit_len = malloc(sizeof(*(block->bit_len)) *
					block->bit_len_size)))
		return (free_u32_md_block(block) & 0);
	i = 0;
	while (i < block->bit_len_size)
		block->bit_len[i++] = 0;
	block->padding = (hash_size * 32 * -2) + bit_len_size;
	return (1);
}

static void	u32_increment(uint32_t **bit_len, uint8_t bit_len_size,
		uint32_t size)
{
	uint8_t	i;

	i = 0;
	while (i < bit_len_size &&
			(uint32_t)((*bit_len)[i] + size * 8) < (size * 8))
		i++;
	if (i >= bit_len_size)
		i--;
	if (i > 0)
	{
		(*bit_len)[i]++;
		while (i > 0)
			(*bit_len)[i--] = 0;
	}
	(*bit_len)[i] += size * 8;
}

static int	u32_pad(t_u32_md_block **data, uint8_t type, int size_set)
{
	int	i;
	int	j;

	i = size_set / 4;
	j = 0;
	if (size_set % 4 == 0)
		(*data)->data[i] = 0;
	if ((*data)->padding < 0)
	{
		(*data)->padding = (((*data)->padding + (size_set * 8) + 8 +
					((size_set * 8 + 8) % 32)) * -1) % ((*data)->size * 32);
		(*data)->data[i++] += (type == LE ? U32_LE_PAD_ONE(size_set) :
				U32_BE_PAD_ONE(size_set));
		(*data)->padding -= ((*data)->padding % 32);
	}
	while (i < (*data)->size && (*data)->padding > 0)
	{
		(*data)->data[i++] = 0;
		(*data)->padding -= 32;
	}
	while (i < (*data)->size)
		(*data)->data[i++] = (*data)->bit_len[type == LITTLE_END ? j++ :
			(*data)->bit_len_size - j++ - 1];
	return (i);
}

int			set_u32_md_block(t_u32_md_block *out, t_ssl_file *in, uint8_t type)
{
	char	data[out->size * 4];
	int		size;

	if (out->padding == 0)
	{
		close(in->fd);
		return ((out->padding = DONE));
	}
	if (((size = ft_ssl_read(in->fd, data, out->size * 4)) > 0) &&
			out->padding < 0)
	{
		type == BIG_END ? u8_to_u32_be((uint8_t *)data, &(out->data), size) :
			u8_to_u32_le((uint8_t *)data, &(out->data), size);
		u32_increment(&(out->bit_len), out->bit_len_size, size);
		if (size == (int)(out->size * 4))
			return (size);
	}
	else if (size == -1)
		return (SYS_ERROR);
	if (out->padding > 0 || size < (int)(out->size * 4))
		return (u32_pad(&out, type, size));
	return (out->padding * -1);
}

int			free_u32_md_block(t_u32_md_block *block)
{
	if (block->data)
		free(block->data);
	if (block->bit_len)
		free(block->bit_len);
	return (1);
}
