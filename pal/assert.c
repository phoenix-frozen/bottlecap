#include "printk.h"

void __assert_fail(const char* assertion, const char* file, unsigned int line, const char* function) __attribute__((noreturn));
void __assert_fail(const char* assertion, const char* file, unsigned int line, const char* function) {
	if(function == NULL)
		printk("Assertion %s failed at %s:%u.\n", assertion, file, line);
	else
		printk("Assertion %s failed in %s at %s:%u.\n", assertion, function, file, line);

	while(1)
		;
}
