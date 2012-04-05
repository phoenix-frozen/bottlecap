#include <stdio.h>
#include <stdint.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>

#include "params.h"

extern int do_real_work(void);

int main(void) {
	int fd_in = open("flicker.out", O_RDONLY);
	if(fd_in == -1) {
		printf("Couldn't open flicker.out\n");
		return -1;
	}

	int fd_out = open("flicker.in", O_CREAT | O_RDWR, 0644);

	if(fd_out == -1) {
		printf("Couldn't open flicker.in\n");
		return -1;
	}

	printf("Got descriptors %d and %d\n", fd_in, fd_out);

	struct stat sb;

	if(fstat(fd_in, &sb) == -1) {
		printf("Couldn't stat flicker.out\n");
		return -1;
	}

	printf("Input data is %d bytes.\n", (int32_t)sb.st_size);

	uint32_t mapsize = sb.st_size;
	if(mapsize % 4096 != 0) {
		mapsize = (mapsize / 4096) * 4096 + 4096;
	}

	void* data_in = mmap(NULL, mapsize, PROT_READ, MAP_SHARED, fd_in, 0);
	if(data_in == NULL || data_in == MAP_FAILED) {
		printf("Couldn't mmap flicker.out\n");
		return -1;
	}

	if(lseek(fd_out, 8191, SEEK_SET) != 8191) {
		printf("pre-seek fail\n");
		return -1;
	}
	if(write(fd_out, &fd_out, 1) != 1) {
		printf("write fail\n");
		return -1;
	}
	if(lseek(fd_out, 0, SEEK_SET) != 0) {
		printf("post-seek fail\n");
		return -1;
	}
	void* data_out = mmap(NULL, 8192, PROT_READ | PROT_WRITE, MAP_SHARED, fd_out, 0);
	if(data_out == NULL || data_out == MAP_FAILED) {
		printf("Couldn't mmap flicker.in\n");
		return -1;
	}

	printf("Got addresses %p and %p\n", data_in, data_out);

	close(fd_in);
	close(fd_out);

	printf("File descriptors closed.\n");

	if(pm_init(data_in, sb.st_size, data_out, 8192) != 1) {
		printf("Couldn't init parameter block\n");
		return -1;
	}

	printf("Init done. Starting real work.\n");
	printf("--------------------------------\n\n");

	int rv = do_real_work();
	printf("Real work reports: %d\n", rv);

	printf("\n--------------------------------\n");
	printf("Real work done, unmapping files.\n");

	munmap(data_in, sb.st_size);
	munmap(data_out, 8192);

	return rv;
}
