CC ?= gcc
CFLAGS ?= -static -O2 -Wall

probe: probe.c
	$(CC) $(CFLAGS) -o $@ $<

image: probe
	docker build -q -t sandbox-probe:local .

clean:
	rm -f probe initrd.gz
	rm -rf ramfs

.PHONY: image clean
