//(c) m1lkweed 2022, GPLv3+
#include <stdio.h>

#define SPECTRE_MEMTOOLS_IMPLEMENTATION

#include "spectre_memtools.h"

char secret[] = "The Magic Words are Squeamish Ossifrage.";

int main(){
	char buf[41] = {0};
	spectre_strncpy(buf, secret, spectre_strnlen(secret, 40));
	puts(spectre_memmem("aaaaaabaaaaa", 12, "baa", 3));
	puts(buf);
}
