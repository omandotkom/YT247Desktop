YT247Desktop - Running and Building on Windows

Run the prebuilt app
- Put `ffmpeg.exe` in the same folder as `YT247Desktop.exe`.
- If Windows reports "libstdc++-6.dll was not found", copy these DLLs next to the EXE:
  - `libstdc++-6.dll`
  - `libgcc_s_seh-1.dll`
  - `libwinpthread-1.dll`
  These are commonly available in `C:\\Program Files\\Git\\mingw64\\bin` if you have Git for Windows installed.

Building from source (CMake)
- MSVC (recommended)
  - `cmake -S . -B build -G "Visual Studio 17 2022" -A x64`
  - `cmake --build build --config Release`

- MinGW + Ninja (fast, no Visual Studio required)
  - Install tools (PowerShell):
    - If needed, install Scoop: `iwr -useb get.scoop.sh | iex`
    - `scoop install gcc ninja`
    - Reopen terminal, or ensure PATH for this session:
      - `$env:Path = "$env:USERPROFILE\\scoop\\apps\\gcc\\current\\bin;$env:USERPROFILE\\scoop\\shims;$env:Path"`
  - Configure and build:
    - `cmake -S . -B build-mingw-ninja -G Ninja -DCMAKE_BUILD_TYPE=Release`
    - `cmake --build build-mingw-ninja --parallel`
  - Output: `build-mingw-ninja\\YT247Desktop.exe`

- MinGW (Makefiles)
  - `cmake -S . -B build -G "MinGW Makefiles" -DCMAKE_BUILD_TYPE=Release`
  - `cmake --build build --config Release`

Notes
- The app expects `ffmpeg.exe` to live next to the EXE.
- On MinGW, the CMake config links static `libstdc++`/`libgcc` to reduce extra DLLs; for GUI builds it also sets `-mwindows` and wide-entry `-municode`.
