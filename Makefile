# Author: Dominik Harmim <harmim6@gmail.com>

OUT := kry
ARGS := -g 1024

SRC := $(OUT).cpp
DOC := doc/doc.pdf
PACK := xharmi00.zip


.PHONY: build
build: $(OUT)

$(OUT): $(SRC)
	g++ -std=gnu++17 -W -Wall -Wextra -Werror -pedantic -O3 -lgmp -lgmpxx -lm \
		$^ -o $@


.PHONY: run
run: $(OUT)
	./$< $(ARGS)


.PHONY: pack
pack: $(PACK)

$(PACK): Makefile $(SRC) $(DOC)
	zip $@ $^


.PHONY: clean
clean:
	rm -f $(OUT) $(PACK)
