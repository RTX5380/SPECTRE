#include <stdio.h>
#include <stdint.h>
#include <x86intrin.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#define CACHE_LINE_SIZE 64
#define CACHE_SIZE 32768 // 假设L1缓存大小为32KB
#define NUM_CACHE_LINES (CACHE_SIZE / CACHE_LINE_SIZE)

#define NUM_PROBES 1000
#define THRESHOLD 80  // 调整阈值

uint8_t probe_array[NUM_CACHE_LINES * CACHE_LINE_SIZE];

void prime_cache() {
    for (size_t i = 0; i < NUM_CACHE_LINES; i++) {
        _mm_clflush(&probe_array[i * CACHE_LINE_SIZE]);
    }
}

void victim_access() {
    // 模拟受害者访问一些数据，连续访问
    for (size_t i = 0; i < NUM_CACHE_LINES; i++) {
        volatile uint8_t temp = probe_array[i * CACHE_LINE_SIZE];
        (void)temp;
    }
}

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

void analyze_access_times(size_t* access_times, int* success_count, int* total_probes) {
    for (size_t i = 0; i < NUM_CACHE_LINES; i++) {
        if (access_times[i] > THRESHOLD) {
            //printf("缓存行 %zu 被受害者驱逐，访问时间: %zu\n", i, access_times[i]);
            (*success_count)++;
        } else {
            //printf("缓存行 %zu 未被驱逐，访问时间: %zu\n", i, access_times[i]);
        }
        (*total_probes)++;
    }
}

int main() {
    int i=1;
    while(i){
        size_t access_times[NUM_CACHE_LINES];
        int success_count = 0;
        int total_probes = 0;

        // 预填充缓存
        prime_cache();

        // 模拟受害者的内存访问
        victim_access();

        // 探测缓存
        probe_cache(access_times);

        // 分析访问时间以检测驱逐情况
        analyze_access_times(access_times, &success_count, &total_probes);

        // 计算攻击成功率
        double success_rate = (double)success_count / total_probes * 100.0;
        printf("攻击成功率: %.2f%%\n", success_rate);

        sleep(1); // 可以设置一个延迟，避免CPU过载
    }

    return 0;
}
