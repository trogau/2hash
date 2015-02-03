#ifndef uint8
#define uint8  unsigned char
#endif

#ifndef uint32
#define uint32 unsigned long int
#endif

typedef struct
{
    uint32 mtotal[2];
    uint32 mstate[4];
    uint8  mbuffer[64];
}
md5_context;

void md5_starts( md5_context *mtx );
void md5_update( md5_context *mtx, uint8 *input, uint32 length );
void md5_finish( md5_context *mtx, uint8 digest[16] );
