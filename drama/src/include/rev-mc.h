#include "utils.h"
#include "unistd.h"


typedef struct {
	char* 		v_addr; 
	uint64_t 	p_addr;
} addr_tuple;

typedef struct 
{
    uint64_t type; // 类型标识符
    uint64_t num;  // 数量或计数
} mask_type;

//----------------------------------------------------------
// 			Functions

//定义了reverse-memory-controller函数
void rev_mc(size_t sets_cnt, size_t threshold, size_t rounds, size_t m_size, char* o_file, uint64_t flags);
