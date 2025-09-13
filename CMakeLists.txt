cmake_minimum_required(VERSION 3.20)
project(YT247Desktop)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include(FetchContent)

# --- Dependencies ---

# GLFW for windowing and input
FetchContent_Declare(
  glfw
  GIT_REPOSITORY https://github.com/glfw/glfw.git
  GIT_TAG 3.3.8
)
FetchContent_MakeAvailable(glfw)

# GLAD for OpenGL function loading
FetchContent_Declare(
  glad
  GIT_REPOSITORY https://github.com/Dav1dde/glad.git
  GIT_TAG v0.1.36
)
FetchContent_MakeAvailable(glad)
# When building GLAD, specify that we want an OpenGL 3.3 core profile
# This must be set before the add_library(glad ...) call inside glad's CMakeLists.txt
set(GLAD_PROFILE "core")
set(GLAD_API "gl=3.3")
set(GLAD_GENERATOR "c")
# Tell glad to be quiet, it's very noisy
set(GLAD_GENERATOR_C_ARGS "--quiet")


# ImGui for the UI
FetchContent_Declare(
  imgui
  GIT_REPOSITORY https://github.com/ocornut/imgui.git
  GIT_TAG v1.88
)
FetchContent_MakeAvailable(imgui)

# NFD for native file dialogs
FetchContent_Declare(
    nfd
    GIT_REPOSITORY https://github.com/btzy/nativefiledialog-extended.git
    GIT_TAG release-v1.1.2
)
FetchContent_MakeAvailable(nfd)

# --- Executable Target ---

add_executable(YT247Desktop src/main.cpp)

# --- Linking Dependencies ---

# Link GLFW
target_link_libraries(YT247Desktop PRIVATE glfw)

# Link GLAD
# We need to include the glad source file directly and link its dependencies
# The glad library itself is just an interface library
target_include_directories(YT247Desktop PRIVATE ${glad_SOURCE_DIR}/include)
target_sources(YT247Desktop PRIVATE ${glad_BINARY_DIR}/src/glad.c)
if(WIN32)
    target_link_libraries(YT247Desktop PRIVATE opengl32)
elseif(APPLE)
    target_link_libraries(YT247Desktop PRIVATE "-framework OpenGL")
else()
    target_link_libraries(YT247Desktop PRIVATE OpenGL::GL)
endif()

# Link ImGui
# We include the sources for ImGui and its backends directly into our executable
target_sources(YT247Desktop PRIVATE
    ${imgui_SOURCE_DIR}/imgui.cpp
    ${imgui_SOURCE_DIR}/imgui_draw.cpp
    ${imgui_SOURCE_DIR}/imgui_tables.cpp
    ${imgui_SOURCE_DIR}/imgui_widgets.cpp
    ${imgui_SOURCE_DIR}/backends/imgui_impl_glfw.cpp
    ${imgui_SOURCE_DIR}/backends/imgui_impl_opengl3.cpp
)
target_include_directories(YT247Desktop PRIVATE
    ${imgui_SOURCE_DIR}
    ${imgui_SOURCE_DIR}/backends
)

# Link NFD
target_link_libraries(YT247Desktop PRIVATE nfd)


# --- Platform Specific Settings ---
if(WIN32)
    # Request a windowed application on Windows (no console)
    set_target_properties(YT247Desktop PROPERTIES WIN32_EXECUTABLE ON)
    # Add libraries needed for process creation and path management
    target_link_libraries(YT247Desktop PRIVATE shell32 user32)
endif()

if(APPLE)
    # Add frameworks needed on macOS
    target_link_libraries(YT247Desktop PRIVATE "-framework CoreFoundation -framework IOKit -framework Cocoa -framework Carbon")
endif()

# --- Final Touches ---
# Add include directories for all dependencies
target_include_directories(YT247Desktop PRIVATE
  ${glfw_SOURCE_DIR}/include
  ${glad_SOURCE_DIR}/include
  ${imgui_SOURCE_DIR}
  ${nfd_SOURCE_DIR}/src/include
)

message(STATUS "Project setup complete. Use 'cmake ..' and 'cmake --build .' to build.")
