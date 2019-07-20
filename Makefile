# eCryptFS token decoder
# (C) Taddy Snow fotonix@pm.me

PROGRAM = epd
FILES = decode.c

all:
	gcc $(FILES) -o $(PROGRAM)

clean:
	rm -f $(PROGRAM)