# A very simple CMake for testing
set(PROJECT picozx81)
cmake_minimum_required(VERSION 3.13)

project(${PROJECT} C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)

find_package(SDL REQUIRED)

message(SDL_INCLUDE_DIR "${SDL_INCLUDE_DIR}")
include_directories(z80)
include_directories(${SDL_INCLUDE_DIR})

OPTION(SUPPORT_SOUND "Set to true to support sound" OFF)
OPTION(PICOZX "Set to true for reduced version" ON)

set(ZX81_SOURCES
	sdl_main.c
	common.c
	sound.c
	zx81config.c
	#w5100.c
	sdl_engine.c
	sdl_hotspots.c
	sdl_input.c
	sdl_loadsave.c
	sdl_resources.c
	sdl_sound.c
	sdl_video.c
	z80/z80.c
	z80/z80_ops.c
	zx81.c
	dissz80.c
	tables.c
	noscript.c
	)

set(SOUND_SOURCES
	sndrender/sndbuffer.cpp
	sndrender/sndchip.cpp 
	sndrender/sndcounter.cpp
	sndrender/sndrender.cpp
	sndrender/sndinterface.cpp
)

set(PACKAGE_DATA_DIR "../data")

execute_process(COMMAND cat ../VERSION OUTPUT_VARIABLE VERSION OUTPUT_STRIP_TRAILING_WHITESPACE)
message(VERSION="${VERSION}")

add_executable(${PROJECT})

target_sources(${PROJECT} PRIVATE ${ZX81_SOURCES})
if (SUPPORT_SOUND)
target_sources(${PROJECT} PRIVATE ${SOUND_SOURCES})
endif()

target_compile_definitions(${PROJECT} PRIVATE -DVERSION="${VERSION}" -DPACKAGE_DATA_DIR="${PACKAGE_DATA_DIR}"
-DENABLE_EMULATION_SPEED_ADJUST -DSZ81 -D_DZ80_EXCLUDE_SCRIPT
	)

if (PICOZX)
target_compile_definitions(${PROJECT} PRIVATE -DZXPICO)
endif()

target_link_libraries(${PROJECT} ${SDL_LIBRARY} -lrt)
if (SUPPORT_SOUND)
target_compile_definitions(${PROJECT} PRIVATE -DOSS_SOUND_SUPPORT -DUSE_SND_EXTERNAL_BUFFER)
endif()

