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


#define SET_SIZE 100 // 每个bank至少需要这么多的地址用于row function解析

#define NUM_DRAM_BANKS 16//注意与main.c的SETS_std保持一致

#define Bank0_addr ((1ULL << 7) ^ (1ULL << 14))  // 0x2040 (a_6 ^ a_13)
#define Bank1_addr ((1ULL << 15) ^ (1ULL << 18)) // 0x24000 (a_14 ^ a_17)
#define Bank2_addr ((1ULL << 16) ^ (1ULL << 19)) // 0x48000 (a_15 ^ a_18)
#define Bank3_addr ((1ULL << 17) ^ (1ULL << 20)) // 0x90000 (a_16 ^ a_19)


// from https://stackoverflow.com/questions/1644868/define-macro-for-debug-printing-in-c
#define verbose_printerr(fmt, ...) \
	do { if (flags & F_VERBOSE) { fprintf(stderr, fmt, ##__VA_ARGS__); } } while(0)



typedef std::vector<addr_tuple> set_t; //定义一个存放addr_tuple地址对的集合体，存放存在bank conflict的地址

//-------------------------------------------
//3个Helper函数
bool is_in(char* val, std::vector<char*> arr);
bool found_enough(std::vector<set_t> sets, uint64_t set_cnt, size_t set_size);
void print_sets(std::vector<set_t> sets);

//-------------------------------------------
//返回两个地址访问之间的延迟(CPU时钟周期)，若a1和a2位于同一BANK或row，时间会变长
//本版本暂时用不到，但是在row function解析时会用到
// uint64_t time_tuple(volatile char* a1, volatile char* a2, size_t rounds) {
// //volatile防止编译器优化,保证每次读取都是从内存中读的,而非从寄存器中读取
//     uint64_t* time_vals = (uint64_t*) calloc(rounds, sizeof(uint64_t));//相对于malloc,会把分配的所有内存bit设置是0
//     uint64_t t0;
//     sched_yield();//主动让出CPU,减少上下文切换对测量的干扰
//     for (size_t i = 0; i < rounds; i++) {
//         mfence();//内存加锁
//         t0 = rdtscp();//记录时钟周期
//         //交替访问
//         *a1;
//         *a2;
//         time_vals[i] = rdtscp() - t0; //记录延迟
//         lfence();//内存解锁
//         //从cache中清除,保证下次是从内存中加载的1
//         clflush(a1);
//         clflush(a2);

//     }

//     uint64_t mdn = median(time_vals, rounds);////多rounds取中位数来减少噪声干扰
//     free(time_vals);
//     return mdn;
// }

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
//通过bank function来查找地址对应的bank号码
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

    std::vector<set_t> sets[NUM_DRAM_BANKS];//set的集合
    std::vector<char*> used_addr;//记录已经使用过的地址,放置重复采样

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

    int bank_num;

    while (!found_enough(*sets, sets_cnt, SET_SIZE)) {
        //生成一个随机地址地址对
        char* rnd_addr = get_rnd_addr(mem.buffer, mem.size, CL_SHIFT);
        if (is_in(rnd_addr, used_addr))
            continue;

        used_addr.push_back(rnd_addr);

        addr_tuple tp = gen_addr_tuple(rnd_addr);
        
        //进行检索，查看这个地址应该添加到哪个bank集合中
        bank_num = which_bank(tp.p_addr);

        //根据bank_num，把这个addr_tuple tp添加到对应的sets里
        // 确保 bank_num 在有效范围内，防止越界访问
        if ((bank_num >= 0) && (bank_num < NUM_DRAM_BANKS)) {
            // 直接将地址对添加到对应 Bank 的集合中
            (*sets)[bank_num].push_back(tp);
            // 打印日志，指示地址被添加到哪个 Bank
            verbose_printerr("[LOG] - Added %p (p_addr: %lx) to Bank %d\n", tp.v_addr, tp.p_addr, bank_num);
        } else {
            verbose_printerr("[LOG] - Added %p (p_addr: %lx) has wrong!!!!!\n", tp.v_addr, tp.p_addr, bank_num);
            exit(1);
        }
    }

    //打印
    if (flags & F_VERBOSE) {
        print_sets(*sets);
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
//如果 found_sets 超过预期数量 set_cnt，报错并退出程序,set_size自定义，为每个bank想要的地址数目
bool found_enough(std::vector<set_t> sets, uint64_t set_cnt, size_t set_size) {

    size_t found_sets = 0;
    
    //遍历查看所有的set,统计set的大小比set_size大的set数字
    for (int i =0; i < sets.size(); i++) {
        set_t curr_set = sets[i];
        if (curr_set.size() >= set_size) {
            found_sets += 1;
        }
    }

    if (found_sets > set_cnt) {
        fprintf(stderr, "[ERROR] - Found too many sets. Is %ld the correct number of sets?\n", set_cnt);
        exit(1);
    } 
    //
    return (found_sets == set_cnt) ? true : false;
}

//用于输出不同集合的地址对
void print_sets(std::vector<set_t> sets) {
//sets.size获取set的数目
//sets[idx].size获取第idx个set的大小
//输出示例:
// [LOG] - Set: 0    Size: 2
//     v_addr:0x1000 - p_addr:0x2000
//     v_addr:0x1008 - p_addr:0x2008
// [LOG] - Set: 1    Size: 1
//     v_addr:0x1010 - p_addr:0x2010
    for (int idx = 0; idx < sets.size(); idx++) {
        fprintf(stderr, "[LOG] - BANK: %d\tSize: %ld\n", idx, sets[idx].size());    
        for (auto tmp: sets[idx]) {
            fprintf(stderr, "\tv_addr:%p - p_addr:%p\n", tmp.v_addr, (void*) tmp.p_addr);
        }
    }    
}
