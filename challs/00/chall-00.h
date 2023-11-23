#define ALLCOATE 0x00
#define ALLOCATE 0x01
#define VIEW 0x02
#define EDIT 0x03
#define FREE 0x04
#define REMOVE 0x05
#define SECRET 0x06

#define MAX_CHUNK_IDX 10
#define MAX_CHUNK_SIZE 0x5f0
#define MIN_CHUNK_SIZE 0x00

void allocate_chunk();
void view_chunk();
void edit_chunk();
void free_chunk();
void remove_chunk();
void secret();

unsigned int get_uint();
void you_win();