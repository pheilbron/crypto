#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include "kryptos.h"
#include "kryptos_block.h"
#include "kryptos_utils.h"
#include "kryptos_file.h"
#include "nread.h"

int	init_u64_block(u64_block *block, int size, int bit_len_size, char type)
{
	block->data = NULL;
	block->bit_len = NULL;
	block->size = size;
	if (type == KRY_FILE &&
			!(block->data = malloc(sizeof(*(block->data)) * block->size)))
		return (0);
	block->bit_len_size = bit_len_size / 64;
	if (!(block->bit_len = malloc(sizeof(*(block->bit_len)) *
					block->bit_len_size)))
		return (free_u64_block(block) & 0);
	for (int i = 0; i < block->bit_len_size; i++)
		block->bit_len[i] = 0;
	block->padding = (size * 64 * -2) + bit_len_size;
	return (1);
}

static void	u64_increment(uint64_t **bit_len, int bit_len_size, uint32_t size)
{
	uint8_t	i;

	i = 0;
	while (i < bit_len_size &&
			(uint64_t)((*bit_len)[i] + size * 8) < (size * 8))
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

static int	u64_pad(u64_block **data, uint8_t endian, int size_set)
{
	int	i;
	int	j;

	i = size_set / 8;
	j = 0;
	if (size_set % 8 == 0)
		(*data)->data[i] = 0;
	if ((*data)->padding < 0)
	{
		(*data)->padding = (((*data)->padding + (size_set * 8) + 8 +
					((size_set * 8 + 8) % 64)) * -1) % ((*data)->size * 64);
		(*data)->data[i++] += (endian == LE ? U64_LE_PAD_ONE(size_set) :
				U64_BE_PAD_ONE(size_set));
		(*data)->padding -= ((*data)->padding % 64);
	}
	while (i < (*data)->size && (*data)->padding > 0)
	{
		(*data)->data[i++] = 0;
		(*data)->padding -= 64;
	}
	while (i < (*data)->size)
		(*data)->data[i++] = (*data)->bit_len[endian == LITTLE_END ? j++ :
			(*data)->bit_len_size - j++ - 1];
	return (i);
}

int			set_u64_block(u64_block *out, kry_file *in, uint8_t endian)
{
	char	data[out->size * 8];
	int		size;

	if (out->padding == 0)
	{
		close(in->fd);
		return ((out->padding = DONE));
	}
	if (((size = nread(in->fd, data, out->size * 8)) > 0) && out->padding < 0)
	{
		endian == BIG_END ? u8_to_u64_be((uint8_t *)data, &(out->data), size) :
			u8_to_u64_le((uint8_t *)data, &(out->data), size);
		u64_increment(&(out->bit_len), out->bit_len_size, size);
		if (size == (int)(out->size * 8))
			return (size);
	}
	else if (size == -1)
		return (SYS_ERROR);
	if (out->padding > 0 || size < (int)(out->size * 8))
		return (u64_pad(&out, endian, size));
	return (out->padding * -1);
}

int			free_u64_block(u64_block *block)
{
	if (block->data)
		free(block->data);
	if (block->bit_len)
		free(block->bit_len);
	return (1);
}
