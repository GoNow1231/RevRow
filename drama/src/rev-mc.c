#include <stdbool.h>
#include <time.h>
#include <stdlib.h>
#include <sched.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <assert.h>
#include <inttypes.h>
#include <string.h>


#include <vector>
#include <functional>
#include <algorithm>
#include <bitset>  

#include "rev-mc.h"

#define BOOL_XOR(a,b) ((a) != (b))
#define O_HEADER "base,probe,time\n"
#define ALIGN_TO(X, Y) ((X) & (~((1LL<<(Y))-1LL))) // Mask out the lower Y bits,低Y位置0
#define LS_BITMASK(X)  ((1LL<<(X))-1LL) // Mask only the lower X bits，仅保存低x位


#define SET_SIZE 50 // 每个row至少需要这么多的地址用于集合
#define NUM_DRAM_BANKS 16 // 仍保留为16，但在此语境下表示需要找到的行集合数量

#define Bank0_addr ((1ULL << 7) ^ (1ULL << 14))  // 0x2040 (a_6 ^ a_13)
#define Bank1_addr ((1ULL << 15) ^ (1ULL << 18)) // 0x24000 (a_14 ^ a_17)
#define Bank2_addr ((1ULL << 16) ^ (1ULL << 19)) // 0x48000 (a_15 ^ a_18)
#define Bank3_addr ((1ULL << 17) ^ (1ULL << 20)) // 0x90000 (a_16 ^ a_19)


// from https://stackoverflow.com/questions/1644868/define-macro-for-debug-printing-in-c
#define verbose_printerr(fmt, ...) \
	do { if (flags & F_VERBOSE) { fprintf(stderr, fmt, ##__VA_ARGS__); } } while(0)


// 移除 typedef std::vector<addr_tuple> set_t;

//-------------------------------------------
//2个Helper函数 (found_enough 已移除)
bool is_in(char* val, std::vector<char*> arr);
// 修改 print_sets 的函数声明
void print_sets(const std::vector<std::vector<addr_tuple>>& sets_array, uint64_t flags); 

//-------------------------------------------
//返回两个地址访问之间的延迟(CPU时钟周期)，若a1和a2位于同一BANK或row，时间会变长
//本版本暂时用不到，但是在row function解析时会用到
uint64_t time_tuple(volatile char* a1, volatile char* a2, size_t rounds) {
//volatile防止编译器优化,保证每次读取都是从内存中读的,而非从寄存器中读取
    uint64_t* time_vals = (uint64_t*) calloc(rounds, sizeof(uint64_t));//相对于malloc,会把分配的所有内存bit设置是0
    uint64_t t0;
    sched_yield();//主动让出CPU,减少上下文切换对测量的干扰
    for (size_t i = 0; i < rounds; i++) {
        mfence();//内存加锁
        t0 = rdtscp();//记录时钟周期
        //交替访问
        *a1;
        *a2;
        time_vals[i] = rdtscp() - t0; //记录延迟
        lfence();//内存解锁
        //从cache中清除,保证下次是从内存中加载的1
        clflush(a1);
        clflush(a2);

    }

    uint64_t mdn = median(time_vals, rounds);//多rounds取中位数来减少噪声干扰
    free(time_vals);
    return mdn;
}

//----------------------------------------------------------
//生成一个随机的,按照指定字节数对齐的内存地址，没看懂
char* get_rnd_addr(char* base, size_t m_size, size_t align) {
    //由两部分组成
    //第一部分是由align确定的,低位为0(位数与align相关)
    //第二部分由align确定的,低位为0(位数与align相关),数值上限由m_size确定
        return (char*) ALIGN_TO((uint64_t) base, (uint64_t) align) + ALIGN_TO(rand() % m_size, (uint64_t) align);
}

//----------------------------------------------------------
//从一个64bit的entry中获得pfn，&0x3fffffffffffff，也就是保留了低54位（认为低54是pfn）
uint64_t get_pfn(uint64_t entry) {
    return ((entry) & 0x3fffffffffffff);//entry的结构特点
}

//----------------------------------------------------------
//核心代码! 输入是一个虚拟地址，获取虚拟地址对应的物理地址
uint64_t get_phys_addr(uint64_t v_addr) 
{
    //条目存储,在proc/self/pagemap中每一个页都对应着一个entry条目,并且顺序的放置,每个条目大小为8B
    uint64_t entry;
    //v_addr/4096,除以页面大小（这里是默认了4k）,得到页号（4K大小的页号）,乘上sizeof(entry)得到该条目在pagemap文件中的偏移量
    //什么tmd代码！！！更改成hugepage这里不用改是吧？？？？
    uint64_t offset = (v_addr/4096) * sizeof(entry);
    //物理页框号page frame number
    uint64_t pfn;  

    int fd = open("/proc/self/pagemap", O_RDONLY);
    assert(fd >= 0);
    //在fd的offset处读取sizeof(entry)给entry
    int bytes_read = pread(fd, &entry, sizeof(entry), offset);
    close(fd);
    assert(bytes_read  == 8);
    assert(entry & (1ULL << 63));//和页存在位与一下,保证存在

    pfn = get_pfn(entry);
    assert(pfn != 0);

    //组合物理页框号和页内偏移
    return ((pfn*4096) | (v_addr & 4095)); 
}


//----------------------------------------------------------
//元组：(虚拟地址,对应的物理地址)，调用get_phys_addr得到一个虚拟地址对应的物理地址，返回一个addr_tuple地址对元组
addr_tuple gen_addr_tuple(char* v_addr) {
    return (addr_tuple) { v_addr, get_phys_addr((uint64_t) v_addr)};
}

//----------------------------------------------------------
std::vector<uint8_t> get_dram_fn(uint64_t addr, std::vector<uint64_t> fn_masks) {
    std::vector<uint8_t> addr_dram;
    for (auto fn:fn_masks) {
        addr_dram.push_back(__builtin_parityl( addr & fn));
    }
    return addr_dram;
}

//----------------------------------------------------------
//通过bank function来查找地址对应的bank号码 (此函数仍用于筛选 Bank 0 地址)
int which_bank(uint64_t p_addr){

    std::vector<uint64_t> bank_functions = {
        //正确的bank掩码
        Bank0_addr,
        Bank1_addr,
        Bank2_addr,
        Bank3_addr
    };
    
    int bank_num = 0;
    int it = 1;

    for (uint64_t current_fn_mask: bank_functions)
    {
        bank_num += __builtin_parityl(p_addr & current_fn_mask) * it;
        it <<= 1;
    }

    return bank_num;
}


//----------------------------------------------------------
void rev_mc(size_t sets_cnt, size_t threshold, size_t rounds, size_t m_size, char* o_file, uint64_t flags) {    

    time_t t;

    int o_fd = 0;//输出文件
    int huge_fd = 0;

    // 修改声明: 从 C 风格数组改为 std::vector
    std::vector<std::vector<addr_tuple>> row_sets(NUM_DRAM_BANKS); // 用于存储16个Row的地址集合，初始化为16个空vector
    std::vector<addr_tuple> active_base_rows; // 存储已找到的16个Row的基础地址 (v_addr, p_addr)
    std::vector<uint64_t> identified_base_row_p_addrs; // 存储已找到的16个Row的基础物理地址（用于判重）

    //time获得一个long int(UNIX时间戳);
    srand((unsigned) time(&t));//根据当前时间随机生成数字,保证地址采样的随机性

    if (flags & F_EXPORT) {//详细输出控制部分，写入表头
        if (o_file == NULL) {
            fprintf(stderr, "[ERROR] - Missing export file name\n");
            exit(1);
        }
        if((o_fd = open(o_file, O_CREAT|O_RDWR)) == -1) {//-1是出错,不然返回的是文件描述符(>=0的整数)
            perror("[ERROR] - Unable to create export file");
            exit(1);
        }
        dprintf(o_fd, O_HEADER);//写入表头
    }

    mem_buff_t mem = {
        .buffer = NULL,
        .size   = m_size,
        .flags  = flags ,
    };

    alloc_buffer(&mem);//完成内存缓冲区的占用,大小是m_size,默认是5GB,需要考量这个是否真的分配了这么多有效的地址

    int current_row_idx = 0; // 当前正在填充的Row集合的索引

    while (current_row_idx < sets_cnt) { // 循环直到找到并填充了 sets_cnt (即16个) 不同的Row
        addr_tuple base_addr_tuple;
        bool new_base_found = false;

        // 1. 寻找一个位于 Bank 0 且尚未被识别为新 Row 的基础地址
        while (!new_base_found) {
            char* base_v_addr = get_rnd_addr(mem.buffer, mem.size, CL_SHIFT);
            base_addr_tuple = gen_addr_tuple(base_v_addr);

            // 检查地址是否在 Bank 0
            if (which_bank(base_addr_tuple.p_addr) == 0) {
                // 检查此物理地址是否已作为其他 Row 的基础地址
                bool is_unique_base_p_addr = true;
                for (const auto& existing_p_addr : identified_base_row_p_addrs) {
                    if (existing_p_addr == base_addr_tuple.p_addr) {
                        is_unique_base_p_addr = false;
                        break;
                    }
                }

                if (is_unique_base_p_addr) {
                    active_base_rows.push_back(base_addr_tuple); // 记录这个基础地址元组
                    identified_base_row_p_addrs.push_back(base_addr_tuple.p_addr); // 记录物理地址用于判重
                    // 修改 push_back 调用
                    row_sets[current_row_idx].push_back(base_addr_tuple); // 将基础地址添加到自己的集合中
                    new_base_found = true;
                    verbose_printerr("[LOG] - Found new base address for Row %d: v_addr: %p, p_addr: %lx\n",
                                     current_row_idx, base_addr_tuple.v_addr, base_addr_tuple.p_addr);
                }
            }
        }

        // 2. 填充当前 Row 集合，直到其地址数量达到 SET_SIZE
        while (row_sets[current_row_idx].size() < SET_SIZE) {
            char* probe_v_addr = get_rnd_addr(mem.buffer, mem.size, CL_SHIFT);
            addr_tuple probe_addr_tuple = gen_addr_tuple(probe_v_addr);

            // 确保探测地址也在 Bank 0
            if (which_bank(probe_addr_tuple.p_addr) == 0) {
                // 跳过与基础地址相同的地址，避免重复
                if (probe_addr_tuple.p_addr == base_addr_tuple.p_addr) {
                    continue;
                }

                // 检查探测地址是否已在当前集合中，避免重复添加
                bool already_in_set = false;
                // 修改 for 循环中的类型推断
                for (const auto& existing_tuple : row_sets[current_row_idx]) {
                    if (existing_tuple.p_addr == probe_addr_tuple.p_addr) {
                        already_in_set = true;
                        break;
                    }
                }
                if (already_in_set) {
                    continue;
                }

                // 测量基础地址和探测地址之间的时延
                uint64_t latency = time_tuple(base_addr_tuple.v_addr, probe_addr_tuple.v_addr, rounds);

                // 如果时延小于阈值，则认为它们在同一Row，添加到集合中
                if (latency < threshold) {
                    // 修改 push_back 调用
                    row_sets[current_row_idx].push_back(probe_addr_tuple);
                    verbose_printerr("[LOG] - Added v_addr: %p (p_addr: %lx) to Row %d (base p_addr: %lx), Latency: %lu\n",
                                     probe_addr_tuple.v_addr, probe_addr_tuple.p_addr, current_row_idx, base_addr_tuple.p_addr, latency);
                }
            }
        }
        current_row_idx++; // 移动到下一个要填充的Row
    }

    //打印收集到的Row集合信息
    if (flags & F_VERBOSE) {
        print_sets(row_sets, flags); // 传递flags
    }

    free_buffer(&mem);
}


// Fin.

//----------------------------------------------------------
//          Helpers

bool is_in(char* val, std::vector<char*> arr) {
    for (auto v: arr) {
        if (val == v) {
            return true;
        }
    }
    return false;
}

//----------------------------------------------------------
// 用于输出不同Row集合的地址对
// 修改 print_sets 的函数定义
void print_sets(const std::vector<std::vector<addr_tuple>>& sets_array, uint64_t flags) {

    for (int idx = 0; idx < NUM_DRAM_BANKS; idx++) {
        // 确保只打印有实际收集到地址的集合
        if (!sets_array[idx].empty()) {
            verbose_printerr("[LOG] - ROW %d\tSize: %ld\n", idx, sets_array[idx].size());    
            // 修改 for 循环中的类型推断
            for (const auto& tmp: sets_array[idx]) {
                verbose_printerr("\tv_addr:%p - p_addr:%p\n", tmp.v_addr, (void*) tmp.p_addr);
            }
        }
    }    
}