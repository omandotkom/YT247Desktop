cmake_minimum_required(VERSION 3.16)
project(YT247Desktop LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Single-file, pure Win32 GUI app for portability
add_executable(YT247Desktop WIN32 src/main.cpp)

if(WIN32)
    set_target_properties(YT247Desktop PROPERTIES WIN32_EXECUTABLE ON)
    target_link_libraries(YT247Desktop PRIVATE user32 gdi32 comdlg32 shell32)
    # When building with MinGW, prefer static libstdc++/libgcc to avoid
    # requiring libstdc++-6.dll/libgcc_s_seh-1.dll on end-user machines.
    if(MINGW)
        # Strip symbols and statically link GCC/STD++ runtimes.
        # Full "-static" can over-static-link system libs, so keep it scoped.
        target_link_options(YT247Desktop PRIVATE -static-libstdc++ -static-libgcc -Wl,-s)
        # Ensure GUI subsystem (no console window) and use wide-entrypoint (wWinMain)
        target_link_options(YT247Desktop PRIVATE -mwindows -municode)
    elseif(MSVC)
        # Force Windows subsystem on MSVC builds as well
        target_link_options(YT247Desktop PRIVATE /SUBSYSTEM:WINDOWS)
    endif()
endif()

message(STATUS "YT247Desktop ready. Configure with CMake and build.")
