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


#define SET_SIZE 40 // elements per set 
#define VALID_THRESH    0.75f //成功阈值
#define SET_THRESH      0.95f //集合阈值
#define BITSET_SIZE 256  // bitset used to exploit bitwise operations 
#define ROW_SET_CNT 5

//禁用两个错误的bank function
//#define Bank0_addr ((1ULL << 6) ^ (1ULL << 13))  // 0x2040 (a_6 ^ a_13)
//#define Bank1_addr ((1ULL << 14) ^ (1ULL << 17)) // 0x24000 (a_14 ^ a_17)
#define Bank2_addr ((1ULL << 15) ^ (1ULL << 18)) // 0x48000 (a_15 ^ a_18)
#define Bank3_addr ((1ULL << 16) ^ (1ULL << 19)) // 0x90000 (a_16 ^ a_19)


// from https://stackoverflow.com/questions/1644868/define-macro-for-debug-printing-in-c
#define verbose_printerr(fmt, ...) \
	do { if (flags & F_VERBOSE) { fprintf(stderr, fmt, ##__VA_ARGS__); } } while(0)



typedef std::vector<addr_tuple> set_t; //定义一个存放addr_tuple地址对的集合体，存放存在bank conflict的地址
typedef std::vector<mask_type>  type_t; //用于后面查看不同的映射的效果

//-------------------------------------------
//5个Helper函数
bool is_in(char* val, std::vector<char*> arr);
bool found_enough(std::vector<set_t> sets, uint64_t set_cnt, size_t set_size);
void filter_sets(std::vector<set_t>& sets, size_t set_size);
void print_sets(std::vector<set_t> sets);
void verify_sets(std::vector<set_t>& sets, uint64_t threshold, size_t rounds);

//-------------------------------------------
//返回两个地址访问之间的延迟(CPU时钟周期)，若a1和a2位于同一BANK或row，时间会变长
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

    uint64_t mdn = median(time_vals, rounds);////多rounds取中位数来减少噪声干扰
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
// https://www.cs.umd.edu/~gasarch/TOPICS/factoring/fastgauss.pdf
// gaussian elimination in GF2 

//冗余掩码消除
std::vector<uint64_t> reduce_masks(std::vector<uint64_t> masks) {

    size_t height, width, height_t, width_t;

    height = masks.size();//掩码？这个地方怎么收集到的信息
    width = 0;
    for (auto m:masks) {
        uint64_t max_one = 64 - __builtin_clzl(m);
        width = (max_one > width)? max_one:width;
    }
    
    height_t = width;
    width_t = height;

    std::vector<std::vector<bool>> mtx(height, std::vector<bool>(width));
    std::vector<std::vector<bool>> mtx_t(height_t, std::vector<bool>(width_t)); 
    std::vector<uint64_t> filtered_masks;

    for (size_t i =0; i<height;i++) {
        for (size_t j=0; j<width; j++) {
            mtx[i][width - j - 1] = (masks[i] & (1ULL<<(j)));
        }
    }

    for (size_t i =0; i<height;i++) {   
        for (size_t j=0; j<width; j++) {
            mtx_t[j][i] = mtx[i][j];
        }
    }

    int64_t pvt_col = 0;

    while (pvt_col < width_t) {
        for (uint64_t row = 0; row < height_t; row++) {
            if (mtx_t[row][pvt_col]) {
                filtered_masks.push_back(masks[pvt_col]);
                for (size_t c=0; c<width_t; c++) {
                    if (c == pvt_col)
                        continue;
                    if (!(mtx_t[row][c]))
                        continue;

                    // column sum
                    for (size_t r=0; r<height_t; r++) {
                        mtx_t[r][c] = BOOL_XOR(mtx_t[r][c], mtx_t[r][pvt_col]); 
                    }  

                }
                break;
            }
        }
        pvt_col++;
    }

    return filtered_masks;

}

//----------------------------------------------------------
// from https://graphics.stanford.edu/~seander/bithacks.html#NextBitPermutation
//Bank掩码消除
uint64_t next_bit_permutation(uint64_t v) {
        uint64_t t = v | (v - 1);
        return (t + 1) | (((~t & -~t) - 1) >> (__builtin_ctzl(v) + 1));
}

//----------------------------------------------------------
//枚举：尝试找出能够区分集合的地址位
std::vector<uint64_t> find_functions(std::vector<set_t> sets, size_t max_fn_bits, size_t msb, uint64_t flags) {

    std::vector<uint64_t> masks;//初始化一个空列表，用于存储最终找到的函数掩码。
    verbose_printerr("~~~~~~~~~~ Candidate functions ~~~~~~~~~~\n");
    
    // 外层循环，按函数复杂性（涉及的比特位数）进行迭代
    // bits会从1增加到max_fn_bits（此程序中为6）
    // 这意味着它会先找所有1-bit的函数，再找2-bit的，以此类推
    for (size_t bits = 1L; bits <= max_fn_bits; bits++) {
        
        //生成一个初始掩码，它有 `bits` 个1。例如，bits=3时，fn_mask = 0b111
        uint64_t fn_mask = ((1L<<(bits))-1);
        //定义搜索的上界。last_mask是当这`bits`个1全部移动到最高位时的形态
        uint64_t last_mask = (fn_mask<<(msb-bits));
        //将掩码左移`CL_SHIFT`位，以跳过用于缓存行内偏移的最低6位地址
        //因为低6位一定不参与bank地址的运算,都去做cache line了
    	fn_mask <<= CL_SHIFT;
        //输出当前正在计算的掩码设计多少个位
        verbose_printerr("[ LOG ] - #Bits: %ld \n", bits);

        //内层循环，遍历所有可能的`bits`个1的组合
        //它会从当前的fn_mask开始，一直到last_mask为止
        while (fn_mask != last_mask) {
            //如果fn_mask低6位不是0,则跳过,查看下一个有效的位组合
            if (fn_mask & LS_BITMASK(6)){
                fn_mask = next_bit_permutation(fn_mask);
                verbose_printerr("[ ATTENTION ] - #fn_mask: 0x%0lx \t\t bits: %s [cache line have data]: ERROR!!!\n", fn_mask, bit_string(fn_mask));
                continue;
            }

            //遍历每一个地址集合（即每一个推测出的DRAM Bank）
            for (size_t idx = 0; idx<sets.size(); idx++) {
                set_t curr_set = sets[idx];
                size_t inner_cnt = 0;
                //set内循环,将所有地址与该集合的第一个地址进行比较
                for (size_t i = 1; i < curr_set.size(); i++) {
                    uint64_t res_base = __builtin_parityl(curr_set[0].p_addr & fn_mask);
                    uint64_t res_probe = __builtin_parityl(curr_set[i].p_addr & fn_mask);
                    if (res_base != res_probe) {
                        verbose_printerr("[ ATTENTION ] - #fn_mask: 0x%0lx \t\t bits: %s [NOTMATCH]: ERROR!!!\n", fn_mask, bit_string(fn_mask));
                        goto next_mask;
                    }
                }
            }
        
            verbose_printerr("\t [ CONGRATULATIONS ]Candidate Function: 0x%0lx \t\t bits: %s\n", fn_mask, bit_string(fn_mask));
            masks.push_back(fn_mask);    
                 
            next_mask:
            fn_mask = next_bit_permutation(fn_mask);
        }
    }

    verbose_printerr("~~~~~~~~~~ Found Functions ~~~~~~~~~~\n");
    masks = reduce_masks(masks);
    if (flags & F_VERBOSE) {
	    for (auto m: masks) {
        	fprintf(stderr, "\t Valid Function: 0x%0lx \t\t bits: %s\n", m, bit_string(m));
    	}    
    }
    for (auto m: masks) {
	    fprintf(stdout, "Bank_mask: 0x%0lx \t\t bits: %s\n", m, bit_string(m));
    }
    return masks;

}

std::vector<int> find_set_bits(uint64_t val) {
    std::vector<int> set_bits;
    for (int i = 0; i<64; i++) {
            if (!(val & (1ULL << i)))
                continue;

            set_bits.push_back(i);
        }
    return set_bits;
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
/* 
It currently finds some of the interesting bits for the row addressing. 
@TODO 	still need to figure out which bits are used for the row addressing and which 
	are from the bank selection. This is currently done manually 
*/
//???????????
uint64_t find_row_mask(std  ::vector<set_t>& sets, std::vector<uint64_t> fn_masks, mem_buff_t mem, uint64_t threshold, uint64_t flags) {

    addr_tuple base_addr = gen_addr_tuple(get_rnd_addr(mem.buffer, mem.size, 0));
    std::vector<set_t> same_row_sets;

    verbose_printerr("~~~~~~~~~~ Looking for row bits ~~~~~~~~~~\n");


    for (int i = 0; i < 2; i++) {
        verbose_printerr("[LOG] - Set #%d\n", i);
        addr_tuple base_addr = sets[i][0];
        std::vector<uint8_t> base_dram = get_dram_fn((uint64_t)base_addr.p_addr, fn_masks);
        same_row_sets.push_back({base_addr});
        uint64_t cnt = 0;
        while (cnt < ROW_SET_CNT) {

            addr_tuple tmp = gen_addr_tuple(get_rnd_addr(mem.buffer, mem.size, 0));
            if (get_dram_fn((uint64_t) tmp.p_addr, fn_masks) != base_dram) 
                continue;

            uint64_t time = time_tuple((volatile char*)base_addr.v_addr, (volatile char*)tmp.v_addr, 1000);
            
            if (time > threshold) 
		continue;

            
	    verbose_printerr("[LOG] - %lx - %lx\t Time: %ld <== GOTCHA\n", base_addr.p_addr, tmp.p_addr, time);
            
            same_row_sets[i].push_back(tmp);
            cnt++;            
        }
    }

    uint64_t row_mask = LS_BITMASK(16); // use 16 bits for the row
    uint64_t last_mask = (row_mask<<(40-16));
    row_mask <<= CL_SHIFT; // skip the lowest 6 bits since they're used for CL addressing

    while (row_mask < last_mask) {
        if (row_mask & LS_BITMASK(CL_SHIFT)){
                row_mask = next_bit_permutation(row_mask);
                continue;
        }

        for (auto addr_pool:same_row_sets) {
            addr_tuple base_addr = addr_pool[0];
            for (int i = 1; i < addr_pool.size(); i++) {
                addr_tuple tmp = addr_pool[i];
                if ((tmp.p_addr & row_mask) != (base_addr.p_addr & row_mask)) {
                    goto next_mask;
                }
            }
    
        }
        
        break;

        next_mask:
        row_mask = next_bit_permutation(row_mask);
    }
  	
   // super hackish way to recover the real row mask  
    for (auto m:fn_masks) {
	uint64_t lsb = (1<<(__builtin_ctzl(m)+1));
	if (lsb & row_mask) {
    		row_mask ^= (1<<__builtin_ctzl(m));
	}
    }
    verbose_printerr("[LOG] - Row mask: 0x%0lx \t\t bits: %s\n", row_mask, bit_string(row_mask));	
    printf("0x%lx\n", row_mask);
    return 0;

}

//负责将掩码结果转换为0,1,2,3等提纯的数据
uint64_t num_transfer(uint64_t binary_num,int function_num) {
    uint64_t result = 0;
    if(function_num == 0){
        if(binary_num&(1ULL<<6)){
            result += 1;
        }
        if (binary_num&(1ULL<<13))
        {       
            result += 2;
        }
        return result;
    }
    else if (function_num == 1){
        if(binary_num&(1ULL<<14)){
            result += 1;
        }
        if (binary_num&(1ULL<<17))
        {       
            result += 2;
        }
        return result;
    }
    else if (function_num == 2){
        if(binary_num&(1ULL<<15)){
            result += 1;
        }
        if (binary_num&(1ULL<<18))
        {       
            result += 2;
        }
        return result;
    }
    else if (function_num == 3){
        if(binary_num&(1ULL<<16)){
            result += 1;
        }
        if (binary_num&(1ULL<<19))
        {       
            result += 2;
        }
        return result;
    }
    result = 4;
    return result;
}
//----------------------------------------------------------
//验证Bank Function的正确性
std::vector<uint64_t> Check_bank_functions(std::vector<set_t> sets, uint64_t flags) {
    std::vector<uint64_t> result_masks; //用于存储验证通过的掩码，尽管这里主要目的是输出统计
    std::vector<uint64_t> bank_functions_to_check = {
        //待检测的bank掩码
        //Bank0_addr,
        //Bank1_addr,
        Bank2_addr,
        Bank3_addr
    };
    type_t mask_result_statistic= {
        {0, 0}, // 第一个mask_type: type=0, num=0
        {1, 0}, // 第二个mask_type: type=1, num=0
        {2, 0}, // 第三个mask_type: type=2, num=0
        {3, 0}  // 第四个mask_type: type=3, num=0
    };
    
    int function_num = 0;
    //外循环:这四个bank function
    for(uint64_t current_fn_mask: bank_functions_to_check){
        verbose_printerr("[ ATTENTION ] - Checking bank function is:0x%0lx \t\t bits: %s \t<<================NEW!!!\n", current_fn_mask, bit_string(current_fn_mask));
        verbose_printerr("================================================\n");

        uint64_t mask_num;

        //内循环:对每个集合进行测试
        for (size_t idx = 0; idx<sets.size(); idx++) {
            set_t curr_set = sets[idx];      
            //对每个地址的掩码计算后对应的bank地址进行统计      
            for (size_t i = 0; i < curr_set.size(); i++) {
                mask_num = num_transfer(curr_set[i].p_addr & current_fn_mask, function_num);
                if(mask_num == 0)
                {
                    mask_result_statistic[0].num++;
                }
                else if(mask_num == 1)
                {
                    mask_result_statistic[1].num++;
                }
                else if(mask_num == 2)
                {
                    mask_result_statistic[2].num++;
                }
                else if(mask_num == 3)
                {
                    mask_result_statistic[3].num++;
                }
                else if(mask_num == 4)
                {
                    verbose_printerr("\tsomething wrong\n");
                }
            }
            //输出本集合的统计数据
            verbose_printerr("\t[ ATTENTION ] - Checking SET is:0x%zu \t\t SET.SIZE is:%zu \n", idx, curr_set.size());
            verbose_printerr("\t[ RESULT-00 ] - :0x%0lx \n", mask_result_statistic[0].num);
            verbose_printerr("\t[ RESULT-01 ] - :0x%0lx \n", mask_result_statistic[1].num);
            verbose_printerr("\t[ RESULT-10 ] - :0x%0lx \n", mask_result_statistic[2].num);
            verbose_printerr("\t[ RESULT-11 ] - :0x%0lx \n", mask_result_statistic[3].num);
            verbose_printerr("------------------------------------------------\n");

            mask_result_statistic[0].num = 0;                       
            mask_result_statistic[1].num = 0;
            mask_result_statistic[2].num = 0;
            mask_result_statistic[3].num = 0;

        }
        function_num++;
        //输出本bank_function的统计数据,加一个判断bank_function正确与否的值!
    }
    return std::vector<long unsigned int>(); // 返回一个空的 long unsigned int 向量
}

//----------------------------------------------------------
//根据正确的Bank function，进一步地筛选出正确的bank地址集合
void valid_sets_fliter(std::vector<set_t>& sets, uint64_t flags){
    
    std::vector<uint64_t> bank_functions = {
        //正确的bank掩码
        //Bank0_addr,
        //Bank1_addr,
        Bank2_addr,
        Bank3_addr
    };

    int num_0 = 0;
    int num_1 = 0;
    int valid_num = 0;
    int error_add_num = 0;
    //外循环：对两个正确的掩码进行计算
    for(uint64_t current_fn_mask: bank_functions){
        verbose_printerr("[ ATTENTION ] - Valid bank function is:0x%0lx \t\t bits: %s \t<<================NEW!!!\n", current_fn_mask, bit_string(current_fn_mask));
        verbose_printerr("================================================\n");
        
        //内循环:对每个集合进行测试
        for (size_t idx = 0; idx<sets.size(); idx++) {
            
            //初始化
            num_0 = 0;
            num_1 = 0;
            valid_num = 0;
            error_add_num = 0;
            set_t curr_set = sets[idx];      
            
            //对每个地址的掩码计算后对应的bank地址进行统计      
            for (size_t i = 0; i < curr_set.size(); i++) {
                if(__builtin_parityl(curr_set[i].p_addr & current_fn_mask))
                {//bank地址是1
                    num_1++;
                }
                else
                {//bank地址是0
                    num_0++;
                }              
            }
            //判断正确的bankaddress应该是什么
            if(num_0 > num_1)
            {
                valid_num = 0;
            }
            else
            {
                valid_num = 1;
            }

            verbose_printerr("bank function(0x%0lx) on sets(%zu) is:%d\n", current_fn_mask, idx, valid_num);

            //对set进行筛选     
            for(auto s = curr_set.begin(); s != curr_set.end();)
            {
                if((__builtin_parityl(s->p_addr & current_fn_mask)) != valid_num)
                {
                    //不符合的地址直接删除掉
                    s = curr_set.erase(s);
                    error_add_num++;
                }     
                else
                {
                    s++;
                }
                
            }

            verbose_printerr("\terror number is:%d\n", error_add_num);
        }
    }
}
//----------------------------------------------------------
void rev_mc(size_t sets_cnt, size_t threshold, size_t rounds, size_t m_size, char* o_file, uint64_t flags) {    

    time_t t;

    int o_fd = 0;//输出文件
    int huge_fd = 0;

    std::vector<set_t> sets;//set的集合
    std::vector<char*> used_addr;//记录已经使用过的地址,放置重复采样
    std::vector<uint64_t> fn_masks;//存储函数掩码,用于后续推导内存映射

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

    while (!found_enough(sets, sets_cnt, SET_SIZE)) {
        char* rnd_addr = get_rnd_addr(mem.buffer, mem.size, CL_SHIFT);
        if (is_in(rnd_addr, used_addr))
            continue;

        used_addr.push_back(rnd_addr);

        addr_tuple tp = gen_addr_tuple(rnd_addr);
        
        bool found_set = false;
        for (size_t idx = 0; idx < sets.size(); idx++) {
            uint64_t time = 0;
            addr_tuple tmp = sets[idx][0];
            time = time_tuple((volatile char*) tmp.v_addr, (volatile char*)tp.v_addr, rounds);
            
            if (flags & F_EXPORT) {
                dprintf(o_fd, "%lx,%lx,%ld\n",(uint64_t) tp.v_addr, (uint64_t) tmp.v_addr,time);
            }
            
            if (time > threshold) {
                //verbose_printerr("[LOG] - [%ld] Set: %03ld -\t %lx - %lx\t Time: %ld\n", used_addr.size(), idx, tp.p_addr, tmp.p_addr, time);
                sets[idx].push_back(tp);
                found_set = true;
                break;
            }
        }

        if (!found_set) {
            sets.push_back({tp});
            //verbose_printerr( "[LOG] - Set: %03ld -\t %p                                    <== NEW!!\n", sets.size(), tp.v_addr);
        }
    }

    filter_sets(sets, SET_SIZE);

#ifdef DEBUG_SETS
    fprintf(stderr, "[ LOG ] - Cleansing sets. This may take a while... stay put\n");
    verify_sets(sets, threshold, rounds);
    fprintf(stderr, "[ LOG ] - Done\n");    
#endif     

    if (flags & F_VERBOSE) {
        print_sets(sets);
    }
    
    valid_sets_fliter(sets,flags);
    
    Check_bank_functions(sets,flags);
    //fn_masks = find_functions(sets, 2, 30, flags);
    //uint64_t row_mask = find_row_mask(sets, fn_masks, mem, threshold, flags);

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
//如果 found_sets 超过预期数量 set_cnt，报错并退出程序
bool found_enough(std::vector<set_t> sets, uint64_t set_cnt, size_t set_size) {

    size_t found_sets = 0;
    
    //遍历查看所有的set,统计set的大小比set_size大的set数字
    for (int i =0; i < sets.size(); i++) {
        set_t curr_set = sets[i];
        if (curr_set.size() > set_size) {
            found_sets += 1;
        }
    }

    if (found_sets > set_cnt) {
        fprintf(stderr, "[ERROR] - Found too many sets. Is %ld the correct number of sets?\n", set_cnt);
        exit(1);
    } 
    //SET_THRESH：一个比例阈值（0.95f），用于判断是否“足够多”
    return (found_sets >= (set_cnt * SET_THRESH)) ? true : false;
}

//设置一个set_size,比set_size小的set删除掉
void filter_sets(std::vector<set_t>& sets, size_t set_size) {

    for (auto s = sets.begin(); s < sets.end(); s++) {
        if (s->size() < set_size) {
            sets.erase(s);
            s -= 1;
        }
    }
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
        fprintf(stderr, "[LOG] - Set: %d\tSize: %ld\n", idx, sets[idx].size());    
        for (auto tmp: sets[idx]) {
            fprintf(stderr, "\tv_addr:%p - p_addr:%p\n", tmp.v_addr, (void*) tmp.p_addr);
        }
    }    
}

#ifdef DEBUG_SETS

void verify_sets(std::vector<set_t>& sets, uint64_t threshold, size_t rounds) {

    for (auto s: sets) {
        // test every address against all the addresses in the set 
        for (auto tp_base = s.begin(); tp_base < s.end(); tp_base++) {
            uint64_t conflicts = 0;
            for (auto tp_probe = s.begin(); tp_probe < s.end(); tp_probe++) {
                if (tp_base == tp_probe)
                    continue;

                uint64_t time = time_tuple((volatile char*) tp_base->v_addr,(volatile char*) tp_probe->v_addr, rounds);
                if (time>threshold){
                    conflicts += 1;
                }
            }
            if (!(conflicts > VALID_THRESH*s.size())) {
                fprintf(stderr, "[ LOG ] - Removing: %p\n", tp_base->v_addr);
                s.erase(tp_base--); // reset the iterator
            }
        }
    }
}

#endif 

