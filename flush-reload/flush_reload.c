#include <stdio.h>
#include <stdint.h>
#include <x86intrin.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#define CACHE_LINE_SIZE 64
#define CACHE_SIZE 32768 // 假设L1缓存大小为32KB
#define NUM_CACHE_LINES (CACHE_SIZE / CACHE_LINE_SIZE)
#define THRESHOLD 80
#define NUM_FLUSHES 10 // 每个缓存行进行的清除次数
#define SLEEP_TIME 1   // 攻击间隔时间（秒）
#define DURATION 600   // 程序运行时间（秒），即10分钟

uint8_t probe_array[NUM_CACHE_LINES * CACHE_LINE_SIZE];
int total_probes = 0;
int total_success = 0;

// 清除指定缓存行
void flush_cache_line(void* addr) {
    for (int i = 0; i < NUM_FLUSHES; i++) {
        _mm_clflush(addr);
    }
}

// 模拟受害者访问数据
void victim_access(volatile uint8_t* addr) {
    // 访问目标地址以确保其被加载到缓存中
    volatile uint8_t temp = *addr;
    (void)temp;
}

// 探测缓存行访问时间
void probe_cache(size_t* access_times) {
    unsigned int junk = 0;
    uint64_t start, end;

    for (size_t i = 0; i < NUM_CACHE_LINES; i++) {
        start = __rdtscp(&junk); // 开始计时
        volatile uint8_t temp = probe_array[i * CACHE_LINE_SIZE]; // 访问缓存行
        end = __rdtscp(&junk);   // 结束计时
        access_times[i] = end - start;
    }
}

// 分析访问时间以检测缓存行是否被访问
void analyze_access_times(size_t* access_times) {
    for (size_t i = 0; i < NUM_CACHE_LINES; i++) {
        if (access_times[i] > THRESHOLD) {
            total_success++;
        }
        total_probes++;
    }
}

int main() {
    size_t access_times[NUM_CACHE_LINES];
    time_t start_time = time(NULL);

    while (difftime(time(NULL), start_time) < DURATION) {
        // 预填充缓存
        for (size_t i = 0; i < NUM_CACHE_LINES; i++) {
            flush_cache_line(&probe_array[i * CACHE_LINE_SIZE]);
        }

        // 模拟受害者程序访问某些数据
        volatile uint8_t* victim_addr = &probe_array[0 * CACHE_LINE_SIZE];
        victim_access(victim_addr);

        // 清除缓存行
        for (size_t i = 0; i < NUM_CACHE_LINES; i++) {
            flush_cache_line(&probe_array[i * CACHE_LINE_SIZE]);
        }

        // 探测缓存
        probe_cache(access_times);

        // 分析访问时间
        analyze_access_times(access_times);

        // 暂停一段时间，以避免过载CPU
        sleep(SLEEP_TIME);
    }

    // 程序运行10分钟后，计算最终的攻击成功率
    double final_success_rate = (double)total_success / total_probes * 100.0;
    printf("10分钟后的攻击成功率: %.2f%%\n", final_success_rate);

    return 0;
}
