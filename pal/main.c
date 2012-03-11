#include <stdio.h>

#include "bottle.h"
#include "bottlecap.h"


#ifdef BOTTLE_CAP_TEST
#include <assert.h>
static void* guaranteed_allocate(size_t size) {
	void* temp = malloc(size);
	assert(temp != NULL);
	return temp;
}
#define malloc guaranteed_allocate

static bottle_t* generate_test_data() {
	bottle_t* bottle = malloc(sizeof(bottle_t));
	bottle->header = malloc(sizeof(*(bottle->header)));
	bottle->table = malloc(PAGE_SIZE);

	bottle->header->flags = 0;
	bottle->header->size  = PAGE_SIZE / sizeof(cap_t);

	return bottle;
}

#endif //BOTTLE_CAP_TEST

int main(void) {
#ifndef BOTTLE_CAP_TEST
	printf("Hello from main() (PAL)\n");

	return 0;
#else //BOTTLE_CAP_TEST
	printf("Hello from main()\n");

	bottle_t* bottle = generate_test_data();
	printf("bottle: %p\n", bottle);

	int rv = bottle_init(*bottle);
	printf("bottle_init(%p): %d\n", bottle, rv);
	assert(rv == 0);

	uint32_t slots = 0;
	rv = bottle_expire(*bottle, 1000, &slots);
	printf("bottle_expire(%p, %u): %d\n", bottle, slots, rv);
	assert(rv == 0);

	return 0;
#endif //BOTTLE_CAP_TEST
}
