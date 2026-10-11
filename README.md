# LinuxFixes

for people playing on linux through proton.

when you move the camera far away and a new area loads in, the game can freeze for a long time. a big part of that freeze on linux is wine's memory allocator being slow, so this swaps it for mimalloc.

no settings, just enable it. source is in the src folder.

uses mimalloc by microsoft (MIT license).
