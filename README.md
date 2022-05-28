# spectre_memtools
String and memory handling functions based around the Spectre misfeature.

### Functions:
```c
static inline void spectre_init();
```
Calculates accurate timing values for the rest of the `spectre_*` functions. This function is automatically called at the start of your program when compiled with GCC/clang.
```c
char read_memory_byte(const void * const address);
```
The core spectre function; reads the value stored at `address` speculatively.
```c
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
```
These functions are equivalent to their non `spectre_*` counterparts except that all `const` arguments are accessed speculatively.

### Notes
Some functions are unreliable when compiled at or above `-O2`, specifically the `spectre_*cpy` family.
