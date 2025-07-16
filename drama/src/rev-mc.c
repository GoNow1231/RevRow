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
#include <cstdio> // For getchar()
#include <map>    // For std::map to count masked values

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


//-------------------------------------------
// 新增的 next_bit_permutation 函数实现 (从 utils.c 移入)
/**
 * @brief 生成具有相同设置位数的下一个更大的整数（Gosper's Hack）。
 *
 * 此函数实现了 Gosper's Hack 算法，用于计算给定整数 `v` 的下一个更大的整数，
 * 且该整数拥有与 `v` 相同数量的设置（1）位。
 * 例如，如果 `v` 是一个二进制表示中包含 K 个 1 的数，此函数将返回下一个
 * 拥有 K 个 1 的更大的数。当所有具有 K 个 1 的组合都被遍历后，它可能会返回一个
 * 拥有 K 个 1 的更大的数。
 *
 * @param v 输入的无符号64位整数。
 * @return 具有与 `v` 相同数量设置位但值更大的下一个整数。
 */
static uint64_t next_bit_permutation(uint64_t v) {
        uint64_t t = v | (v - 1);
        return (t + 1) | (((~t & -~t) - 1) >> (__builtin_ctzl(v) + 1));
}

// 用于存储众数超过阈值时的信息
struct HighModeEntry {
    uint64_t mask;
    size_t set_idx;
};


//-------------------------------------------
//2个Helper函数
bool is_in(char* val, std::vector<char*> arr);
// 修改 print_sets 的函数声明，匹配 find_row_function 的参数类型
void print_sets(const std::vector<std::vector<addr_tuple>>& sets_array, size_t rounds, uint64_t flags); 

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
    uint64_t entry;
    uint64_t offset = (v_addr/4096) * sizeof(entry);
    uint64_t pfn;  

    int fd = open("/proc/self/pagemap", O_RDONLY);
    assert(fd >= 0);
    int bytes_read = pread(fd, &entry, sizeof(entry), offset);
    close(fd);
    assert(bytes_read  == 8);
    assert(entry & (1ULL << 63));//和页存在位与一下,保证存在

    pfn = get_pfn(entry);
    assert(pfn != 0);

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
// find_row_function 函数实现
void find_row_function(const std::vector<std::vector<addr_tuple>>& row_sets, std::vector<uint64_t> fn_masks, mem_buff_t mem, uint64_t threshold, size_t rounds, uint64_t flags) {

    verbose_printerr("~~~~~~~~~~ Starting Row Mask Iteration and Validation Output ~~~~~~~~~~\n");

    uint64_t row_mask = LS_BITMASK(13); 
    uint64_t last_mask = (row_mask<<(31-13)); 
    row_mask <<= 10; 

    // 存储符合众数 > 10 条件的掩码和集合索引
    std::vector<HighModeEntry> high_mode_results;

    while (row_mask != 0 && (row_mask & LS_BITMASK(CL_SHIFT))) {
        row_mask = next_bit_permutation(row_mask);
    }
    if (row_mask == 0) {
        verbose_printerr("[ERROR] - Initial row mask generation failed or no valid starting mask after CL_SHIFT adjustment.\n");
        return;
    }


    while (row_mask < last_mask) {
        verbose_printerr("---当前掩码是 0x%0lx (bits: %s)=====================<<<<<<<\n", row_mask, bit_string(row_mask));

        for (size_t set_idx = 0; set_idx < row_sets.size(); ++set_idx) {
            const auto& addr_pool = row_sets[set_idx]; 

            if (addr_pool.empty()) {
                verbose_printerr("  [WARN] - Row Set %zu is empty. Skipping.\n", set_idx);
                continue;
            }

            std::map<uint64_t, int> masked_value_counts;
            uint64_t current_mode_value = 0;
            int max_count = 0;

            for (const auto& addr_entry : addr_pool) {
                uint64_t masked_val = addr_entry.p_addr & row_mask;
                masked_value_counts[masked_val]++;
            }

            for (const auto& pair : masked_value_counts) {
                if (pair.second > max_count) {
                    max_count = pair.second;
                    current_mode_value = pair.first;
                }
            }

            // 输出简化的统计结果
            verbose_printerr("  在第 %zu 集合上的统计结果:\n", set_idx);
            verbose_printerr("    Mode Masked Value: 0x%0lx\n", current_mode_value);
            verbose_printerr("    Count: %d/%d\n", max_count, (int)SET_SIZE);
            
            // 如果众数 > 10，则记录该掩码和集合索引
            if (max_count > 10) {
                high_mode_results.push_back({.mask = row_mask, .set_idx = set_idx});
            }
        }
        verbose_printerr("\n"); 

        row_mask = next_bit_permutation(row_mask);
        while (row_mask != 0 && (row_mask & LS_BITMASK(CL_SHIFT))) {
            row_mask = next_bit_permutation(row_mask);
        }
        if (row_mask == 0 && (last_mask != 0 || LS_BITMASK(16) != 0)) { 
             verbose_printerr("[LOG] - All relevant row mask permutations exhausted.\n");
             break; 
        }
    }
    
    // 最后输出众数 > 10 的详细信息
    verbose_printerr("\n~~~~~~~~~~ Detailed Results for Masks with Mode Count > 10 ~~~~~~~~~~\n");
    if (high_mode_results.empty()) {
        verbose_printerr("No masks found with mode count > 10 in any set.\n");
    } else {
        for (const auto& entry : high_mode_results) {
            const auto& target_addr_pool = row_sets[entry.set_idx];
            
            verbose_printerr("\nMask: 0x%0lx (bits: %s) on Row Set %zu\n",
                             entry.mask, bit_string(entry.mask), entry.set_idx);
            
            if (!target_addr_pool.empty()) {
                const addr_tuple& base_addr = target_addr_pool[0];
                verbose_printerr("  Base PAddr: 0x%0lx masked to 0x%0lx\n", base_addr.p_addr, (base_addr.p_addr & entry.mask));
                verbose_printerr("  All Addresses Masked (Full Set):\n");
                for (const auto& tmp : target_addr_pool) { // 遍历包括基地址在内的所有地址
                    verbose_printerr("    - PAddr: 0x%0lx masked to 0x%0lx\n", tmp.p_addr, (tmp.p_addr & entry.mask));
                }
            } else {
                verbose_printerr("  (目标行集合为空，这不应该发生，因为已被添加到 high_mode_results。)\n");
            }
        }
    }
    verbose_printerr("~~~~~~~~~~ Detailed Results Output Complete ~~~~~~~~~~\n");
}

//----------------------------------------------------------
void rev_mc(size_t sets_cnt, size_t threshold, size_t rounds, size_t m_size, char* o_file, uint64_t flags) {    

    time_t t;

    int o_fd = 0;//输出文件
    int huge_fd = 0;

    std::vector<std::vector<addr_tuple>> row_sets(NUM_DRAM_BANKS); 
    std::vector<addr_tuple> active_base_rows; 
    std::vector<uint64_t> identified_base_row_p_addrs; 

    srand((unsigned) time(&t));

    if (flags & F_EXPORT) {
        if (o_file == NULL) {
            fprintf(stderr, "[ERROR] - Missing export file name\n");
            exit(1);
        }
        if((o_fd = open(o_file, O_CREAT|O_RDWR)) == -1) {
            perror("[ERROR] - Unable to create export file");
            exit(1);
        }
        dprintf(o_fd, O_HEADER);
    }

    mem_buff_t mem = {
        .buffer = NULL,
        .size   = m_size,
        .flags  = flags ,
    };

    alloc_buffer(&mem);

    int current_row_idx = 0; 

    while (current_row_idx < sets_cnt) { 
        addr_tuple base_addr_tuple;
        bool new_base_found = false;

        while (!new_base_found) {
            char* base_v_addr = get_rnd_addr(mem.buffer, mem.size, CL_SHIFT);
            base_addr_tuple = gen_addr_tuple(base_v_addr);

            if (which_bank(base_addr_tuple.p_addr) == 0) {
                bool is_unique_base_p_addr = true;
                for (const auto& existing_p_addr : identified_base_row_p_addrs) {
                    if (existing_p_addr == base_addr_tuple.p_addr) {
                        is_unique_base_p_addr = false;
                        break;
                    }
                }

                if (is_unique_base_p_addr) {
                    active_base_rows.push_back(base_addr_tuple); 
                    identified_base_row_p_addrs.push_back(base_addr_tuple.p_addr); 
                    row_sets[current_row_idx].push_back(base_addr_tuple); 
                    new_base_found = true;
                    // 精简输出
                    verbose_printerr("[LOG] - Found base for Row %d: VAddr: %p, PAddr: %lx\n",
                                     current_row_idx, base_addr_tuple.v_addr, base_addr_tuple.p_addr);
                }
            }
        }

        while (row_sets[current_row_idx].size() < SET_SIZE) {
            char* probe_v_addr = get_rnd_addr(mem.buffer, mem.size, CL_SHIFT);
            addr_tuple probe_addr_tuple = gen_addr_tuple(probe_v_addr);

            if (which_bank(probe_addr_tuple.p_addr) == 0) {
                if (probe_addr_tuple.p_addr == base_addr_tuple.p_addr) {
                    continue;
                }

                bool already_in_set = false;
                for (const auto& existing_tuple : row_sets[current_row_idx]) {
                    if (existing_tuple.p_addr == probe_addr_tuple.p_addr) {
                        already_in_set = true;
                        break;
                    }
                }
                if (already_in_set) {
                    continue;
                }

                uint64_t latency = time_tuple(base_addr_tuple.v_addr, probe_addr_tuple.v_addr, rounds);

                if (latency < threshold) {
                    row_sets[current_row_idx].push_back(probe_addr_tuple);
                }
            }
        }
        // 每个集合完成后，输出其总结信息
        verbose_printerr("[LOG] - Row %d completed. Base VAddr: %p, Base PAddr: %lx, Total Addresses: %zu\n",
                         current_row_idx, base_addr_tuple.v_addr, base_addr_tuple.p_addr, row_sets[current_row_idx].size());
        current_row_idx++; 
    }

    if (flags & F_VERBOSE) {
        // 更新此处，传递 rounds 参数
        print_sets(row_sets, rounds, flags); 
    }
    
    // 在进行 Row 掩码破解前，提示用户敲击回车
    if (flags & F_VERBOSE) {
        printf("\nPress ENTER to continue with row mask cracking...\n");
        int c;
        while ((c = getchar()) != '\n' && c != EOF);
    }

    std::vector<uint64_t> bank_functions_for_row_crack = {
        Bank0_addr,
        Bank1_addr,
        Bank2_addr,
        Bank3_addr
    };

    find_row_function(row_sets, bank_functions_for_row_crack, mem, threshold, rounds, flags);

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
// 用于输出不同Row集合的地址对 (更新此处，接收 rounds 参数)
void print_sets(const std::vector<std::vector<addr_tuple>>& sets_array, size_t rounds, uint64_t flags) {

    for (int idx = 0; idx < NUM_DRAM_BANKS; idx++) {
        if (!sets_array[idx].empty()) {
            verbose_printerr("[LOG] - ROW %d\tSize: %ld\n", idx, sets_array[idx].size());    
            
            // 获取当前Row集合的基地址（第一个地址）
            char* base_v_addr_in_set = sets_array[idx][0].v_addr;

            for (const auto& tmp: sets_array[idx]) {
                // 计算当前地址与集合基地址之间的访问时延
                uint64_t latency = time_tuple(base_v_addr_in_set, tmp.v_addr, rounds);
                verbose_printerr("\tv_addr:%p - p_addr:%p - Latency to Base: %lu\n", 
                                 tmp.v_addr, (void*) tmp.p_addr, latency);
            }
        }
    }    
}

