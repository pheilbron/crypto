int	blake_256(void *data, char **hash, uint8_t type)
{
	blake256_chunk	chunk;
	int				status;


	if (!init_u32_block(&chunk.block, 16, 64, type))
		return (0);
	chunk.buf_pos = 0;
	chunk.hash[A] = 0x;
	chunk.hash[B] = 0x;
	chunk.hash[C] = 0x;
	chunk.hash[D] = 0x;
	chunk.hash[E] = 0x;
	chunk.hash[F] = 0x;
	chunk.hash[G] = 0x;
	chunk.hash[H] = 0x;
