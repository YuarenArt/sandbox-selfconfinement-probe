CC ?= gcc
CFLAGS ?= -static -O2 -Wall -Wextra
IMAGE ?= sandbox-probe:local

probe: probe.c
	$(CC) $(CFLAGS) -o $@ $<

image: probe
	docker build -q -t $(IMAGE) . >/dev/null

clean:
	rm -f probe initrd.gz

.PHONY: image clean
