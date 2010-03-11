# Comment/uncomment these to choose an installation destination
# System wide installation
#PREFIX=/usr/local
#BINDIR=$(PREFIX)/bin
#DOCDIR=$(PREFIX)/share/doc/$(TARGET)
#PACKAGE_DATA_DIR=$(PREFIX)/share/$(TARGET)

# Local installation within your home folder
#PREFIX=$(HOME)/Games/$(TARGET)
#BINDIR=$(PREFIX)
#DOCDIR=$(PREFIX)/doc
#PACKAGE_DATA_DIR=$(PREFIX)/data

# Run from current folder i.e. no installation
PREFIX=.
BINDIR=$(PREFIX)
DOCDIR=$(PREFIX)
PACKAGE_DATA_DIR=$(PREFIX)/data

# Comment this out if you're not compiling on Linux, or some other
# platform with the OSS (Open Sound System) API available.
SOUNDDEF=-DOSS_SOUND_SUPPORT

# You won't need to alter these
TARGET=$(shell cat TARGET)
SOURCES=smain.c common.c sound.c z80.c sdl.c
OBJECTS=$(patsubst %.c, %.o, $(SOURCES))
VERSION=$(shell cat VERSION)

# These should be ok for most
SDL_CONFIG=sdl-config
CFLAGS=-O3 -Wall `$(SDL_CONFIG) --cflags` -DVERSION=\"$(VERSION)\" \
	-DPACKAGE_DATA_DIR=\"$(PACKAGE_DATA_DIR)\" $(SOUNDDEF) -DSZ81 
LINK=$(CC)
LDFLAGS=
LIBS=`$(SDL_CONFIG) --libs` 

# You won't need to alter anything below
all: $(SOURCES) $(TARGET)

$(TARGET): $(OBJECTS)
	$(LINK) $(LDFLAGS) $(OBJECTS) $(LIBS) -o $@

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

.PHONY: all clean install

clean:
	rm -f *.o

install:
	@if [[ "$(PREFIX)" == .* ]] ; then \
		echo "Installing into the current folder is not allowed."; \
		exit 2; \
	fi
	mkdir -p $(BINDIR)
	mkdir -p $(DOCDIR)
	mkdir -p $(PACKAGE_DATA_DIR)
	cp $(TARGET) $(BINDIR)
	cp AUTHORS COPYING ChangeLog NEWS README $(DOCDIR)
	cp data/*.bmp $(PACKAGE_DATA_DIR)
	if [ -f data/zx80.rom ]; then cp data/zx80.rom $(PACKAGE_DATA_DIR); fi
	if [ -f data/zx81.rom ]; then cp data/zx81.rom $(PACKAGE_DATA_DIR); fi
	
uninstall:
	@echo "Uninstalling is not currently implemented."

