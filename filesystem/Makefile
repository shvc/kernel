
all: fuse-example.c
	$(CC) -o fuse-example -l fuse -D_FILE_OFFSET_BITS=64 $<

.PHONY: clean
clean:
	rm -f fuse-example *.o
