# To compile z80 emulator will need to increase cc heap
# *SetEval cc1$HeapMax 128

# To convert binary to aif format use
# *elf2aif sz81

# SDL libs and includes assumed to be in SDL under install dir
# Run from current folder i.e. no installation

# Run from current folder i.e. no installation
PREFIX?=.
BINDIR?=$(PREFIX)
DOCDIR?=$(PREFIX)
PACKAGE_DATA_DIR?=$(PREFIX)/data

# For sz81 OSS_SOUND_SUPPORT is now synonymous with SDL_SOUND_SUPPORT.
# Comment this out if you don't want sound support.
SOUNDDEF=-DOSS_SOUND_SUPPORT

# You won't need to alter these
TARGET=sz81
SOURCES=sdl_main.c common.c sound.c zx81config.c sdl_engine.c sdl_hotspots.c \
	sdl_input.c sdl_loadsave.c sdl_resources.c sdl_sound.c sdl_video.c \
	z80/z80.c z80/z80_ops.c zx81.c dissz80.c tables.c noscript.c w5100stub.c
OBJECT1=zx81config.o sdl_hotspots.o sdl_input.o sdl_loadsave.o sdl_resources.o
OBJECT3=z80/z80.o z80/z80_ops.o zx81.o dissz80.o tables.o noscript.o \
        sdl_sound.o sdl_video.o sdl_main.o common.o sound.o sdl_engine.o w5100.o

OBJECTS=$(OBJECT1) $(OBJECT3)

VERSION=2_3_12

# These should be ok for most.
CFLAGS+=-Wall -Wno-unused-result -ISDL -DVERSION=\"$(VERSION)\" -DENABLE_EMULATION_SPEED_ADJUST \
	-DPACKAGE_DATA_DIR=\"$(PACKAGE_DATA_DIR)\" $(SOUNDDEF) -DSZ81 -D_DZ80_EXCLUDE_SCRIPT -DPLATFORM_RISCOS 
# options:
# -DAPU
# -DZXPAND
# -DZXNU
# -DZXMORE (-DZXMSHMEM)
# -DZXMROML=0xF8 -DZXMRAML=0x13
# -DVDRIVE

LINK=$(CC)
#LDFLAGS=
LIBS= -LSDL -lSDL -Lsndrender -lsndrender -Lzxpand -lzxpand

# You won't need to alter anything below
all: $(SOURCES) $(TARGET)

$(TARGET): $(OBJECTS) sndrender/libsndrender.a zxpand/libzxpand.a
#am9511/am9511.o
#	g++ $(LDFLAGS) $(OBJECTS) $(LIBS) am9511/am9511.o -o $@
	g++ -static $(LDFLAGS) $(OBJECTS) $(LIBS) -o $@

$(OBJECT1): CGFLAGS = $(CFLAGS) -O1
$(OBJECT3): CGFLAGS = $(CFLAGS) -O3

$(OBJECTS): %.o: %.c
	gcc -static $(CGFLAGS) -c $< -o $@

# Workaround for Risc OS. Manually execute the Makefiles in the zxpand and sndrender directories first
#sndrender/libsndrender.a: sndrender/sndbuffer.cpp sndrender/sndchip.cpp sndrender/sndcounter.cpp sndrender/sndrender.cpp sndrender/sndinterface.cpp
#	cd sndrender && $(MAKE)

#zxpand/libzxpand.a: zxpand/zxpand_emu.cpp zxpand/zxpandclass.cpp zxpand/smbsd.cpp zxpand/zxpandcom.cpp zxpand/usart.cpp zxpand/zxpandcore.cpp zxpand/js.cpp zxpand/wildcard.cpp zxpand/ff.cpp
#	cd zxpand && CXXFLAGS='$(CFLAGS) -Wno-trigraphs' $(MAKE)

#am9511/am9511.o: am9511/am9511.cpp
#	cd am9511 && $(CXX) -c $(CFLAGS) am9511.cpp

.PHONY: all clean install

open%:
	-@if [ -n "`which pasmo 2> /dev/null`" ]; then \
		pasmo -v open8x/$@.asm open8x/$@.rom; \
		if [ -f open8x/$@.rom -a ! -e data/zx$*.rom ]; then \
			cp open8x/$@.rom data/zx$*.rom; \
		fi \
	else \
		echo "The Pasmo cross-assembler was not found: skipping $@"; \
	fi

clean:
	cd sndrender && $(MAKE) clean
	cd zxpand && $(MAKE) clean
	rm -f *.o *~ sz81 z80/*.o z80/*~ am9511/am9511.o stzxfs


