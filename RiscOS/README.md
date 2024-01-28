# Build and Run
## To run on Pi
sz81 uses SDL1.2. The latest Raspberry Pi OS (bookworm) defaults to Wayland for Pi4 and Pi5. When SDL1.2 is used with wayland the resize flag is not respected. This means that the sz81 window can be resized by the user, even though the underlying code does not support this. The following can prevent the resize:

1. Install sdl12-compat  
`sudo apt install libsdl1.2-compat`

2. Use sdl12-compat  
Modify the symlink `libSDL.so` at:
`/lib/aarch64-linux-gnu` to point to the `.so` at `/lib/aarch64-linux-gnu/sdl12-compat`

3. Configure SDL to use wayland and run sz81  
`export SDL_VIDEODRIVER=wayland;./sz81`

## To build on Risc OS
The script `mkrisc.sh` creates a directory tree under `riscroot` that can be copied to Risc OS to compile with the gcc available from !PackMan

The SDL 1.2 libraries and includes must be downloaded from !Packman and placed where they can be found from the Makefile

### Notes
1. The compiler heap size needs to be increased to build the z80 emulator  
`*SetEval cc1$HeapMax 128`
2. The executable needs to be converted to aif format  
`*elf2aif sz81`
3. The app types for the ! files should be changed back to obey (the type is lost when saving to github)
4. dot extensions result in files with slash. ie. saving `prog.p` results in a file named `prog/p`
