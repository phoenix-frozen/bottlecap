#include <stdio.h>

int main(void) {
#ifndef BOTTLE_CAP_TEST
	printf("Hello from main() (PAL)\n");

	return 0;
#else //BOTTLE_CAP_TEST
	printf("Hello from main()\n");

	return 0;
#endif //BOTTLE_CAP_TEST
}
