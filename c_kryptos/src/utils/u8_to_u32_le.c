#include "kryptos_utils.h"

int	u8_to_u32_le(uint8_t *in, uint32_t **out, int len)
{
	int	in_i;
	int	out_i;

	in_i = 0;
	out_i = 0;
	(*out)[out_i] = 0;
	while (in_i < len)
	{
		if (in_i % 4 == 0)
			(*out)[out_i] = 0;
		(*out)[out_i] |= (((uint32_t)(in[in_i])) <<
				((in_i % 4) * 8));
		if (in_i % 4 == 3)
			out_i++;
		in_i++;
	}
	return (out_i);
}
