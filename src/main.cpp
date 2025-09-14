// YT247Desktop - Minimal Win32 GUI app to stream a local video to YouTube Live via ffmpeg

#include <windows.h>
#include <commdlg.h>
#include <string>
#include <vector>
#include <sstream>

// Control IDs
enum : int {
    ID_EDIT_VIDEO = 1001,
    ID_BTN_BROWSE = 1002,
    ID_LBL_VALID  = 1003,
    ID_EDIT_KEY   = 1004,
    ID_BTN_START  = 1005,
    ID_LBL_STATUS = 1006,
    ID_EDIT_LOG   = 1007,
    ID_TIMER_PROC = 2001
};

static HWND g_hEditVideo = nullptr;
static HWND g_hBtnBrowse = nullptr;
static HWND g_hLblValid  = nullptr;
static HWND g_hEditKey   = nullptr;
static HWND g_hBtnStart  = nullptr;
static HWND g_hLblStatus = nullptr;
static HWND g_hEditLog   = nullptr;
static HFONT g_hFont     = nullptr;

static bool  g_isValidFile = false;
static bool  g_isStreaming = false;
static HANDLE g_hFfmpegProcess = nullptr;
static std::wstring g_ffmpegPath; // full path to ffmpeg.exe
static HANDLE g_hPipeRead = nullptr;
static HANDLE g_hPipeWrite = nullptr;
static HANDLE g_hLogThread = nullptr;
static HWND   g_hMainWnd   = nullptr;

// Custom message to append log text (lParam = wchar_t* allocated on heap)
constexpr UINT WM_APP_APPEND_LOG = WM_APP + 1;

// Utility: get directory containing current executable
static std::wstring GetExeDir() {
    wchar_t buf[MAX_PATH];
    DWORD len = GetModuleFileNameW(nullptr, buf, MAX_PATH);
    std::wstring path(buf, (len ? len : 0));
    size_t pos = path.find_last_of(L"\\/");
    if (pos != std::wstring::npos) {
        return path.substr(0, pos);
    }
    return L".";
}

// Utility: check if a file exists
static bool FileExists(const std::wstring& p) {
    DWORD attr = GetFileAttributesW(p.c_str());
    return (attr != INVALID_FILE_ATTRIBUTES) && !(attr & FILE_ATTRIBUTE_DIRECTORY);
}

// Utility: lowercase copy
static std::wstring ToLower(std::wstring s) {
    for (auto &ch : s) ch = (wchar_t)towlower(ch);
    return s;
}

// Utility: check known video extensions
static bool IsVideoExtension(const std::wstring& path) {
    size_t dot = path.find_last_of(L'.');
    if (dot == std::wstring::npos) return false;
    std::wstring ext = ToLower(path.substr(dot));
    static const wchar_t* exts[] = { L".mp4", L".mkv", L".avi", L".mov", L".webm" };
    for (auto e : exts) {
        if (ext == e) return true;
    }
    return false;
}

// Append wide text to the log edit and scroll to the bottom
static void AppendLog(const std::wstring& text) {
    if (!g_hEditLog) return;
    int len = GetWindowTextLengthW(g_hEditLog);
    SendMessageW(g_hEditLog, EM_SETSEL, len, len);
    SendMessageW(g_hEditLog, EM_REPLACESEL, FALSE, (LPARAM)text.c_str());
    SendMessageW(g_hEditLog, EM_SCROLLCARET, 0, 0);
}

// Convert narrow text (UTF-8 preferred, fallback to ANSI) to wide
static std::wstring ToWideBestEffort(const char* data, int nbytes) {
    int wlen = MultiByteToWideChar(CP_UTF8, 0, data, nbytes, nullptr, 0);
    UINT cp = CP_UTF8;
    if (wlen == 0) { cp = CP_ACP; wlen = MultiByteToWideChar(CP_ACP, 0, data, nbytes, nullptr, 0); }
    std::wstring w;
    if (wlen > 0) {
        w.resize(wlen);
        MultiByteToWideChar(cp, 0, data, nbytes, &w[0], wlen);
    }
    return w;
}

struct LogThreadCtx { HANDLE hRead; HWND hwnd; };

static DWORD WINAPI LogThreadProc(LPVOID lp) {
    LogThreadCtx* ctx = (LogThreadCtx*)lp;
    const DWORD BUFSZ = 4096;
    char buf[BUFSZ];
    DWORD n = 0;
    std::string pending;
    while (ctx && ReadFile(ctx->hRead, buf, BUFSZ, &n, nullptr) && n > 0) {
        pending.append(buf, buf + n);
        size_t pos;
        while ((pos = pending.find('\n')) != std::string::npos) {
            std::string line = pending.substr(0, pos + 1);
            pending.erase(0, pos + 1);
            std::wstring w = ToWideBestEffort(line.data(), (int)line.size());
            if (w.empty()) continue;
            size_t bytes = (w.size() + 1) * sizeof(wchar_t);
            wchar_t* copy = (wchar_t*)HeapAlloc(GetProcessHeap(), 0, bytes);
            if (!copy) continue;
            memcpy(copy, w.c_str(), bytes);
            PostMessageW(ctx->hwnd, WM_APP_APPEND_LOG, 0, (LPARAM)copy);
        }
    }
    // Flush remainder
    if (!pending.empty()) {
        std::wstring w = ToWideBestEffort(pending.data(), (int)pending.size());
        if (!w.empty()) {
            size_t bytes = (w.size() + 1) * sizeof(wchar_t);
            wchar_t* copy = (wchar_t*)HeapAlloc(GetProcessHeap(), 0, bytes);
            if (copy) { memcpy(copy, w.c_str(), bytes); PostMessageW(ctx->hwnd, WM_APP_APPEND_LOG, 0, (LPARAM)copy); }
        }
    }
    if (ctx) HeapFree(GetProcessHeap(), 0, ctx);
    return 0;
}

// Update validity label based on file path in edit
static void UpdateValidityLabel(HWND hwnd) {
    wchar_t buf[MAX_PATH];
    GetWindowTextW(g_hEditVideo, buf, MAX_PATH);
    std::wstring p = buf;
    if (!p.empty() && FileExists(p)) {
        if (!IsVideoExtension(p)) {
            // It's a file but not a video extension
            g_isValidFile = false;
            SetWindowTextW(g_hLblValid, L"File bukan video!");
        } else {
            g_isValidFile = true;
            SetWindowTextW(g_hLblValid, L"Valid");
        }
    } else {
        g_isValidFile = false;
        if (!p.empty()) SetWindowTextW(g_hLblValid, L"File tidak valid");
        else SetWindowTextW(g_hLblValid, L"");
    }
    InvalidateRect(g_hLblValid, nullptr, TRUE);
}

// Pick a file with common dialog
static bool BrowseForVideo(HWND owner, std::wstring& outPath) {
    wchar_t fileBuf[MAX_PATH] = {0};
    OPENFILENAMEW ofn = {0};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = owner;
    ofn.lpstrFilter = L"Video Files\0*.mp4;*.mkv;*.avi;*.mov;*.webm\0All Files\0*.*\0\0";
    ofn.lpstrFile = fileBuf;
    ofn.nMaxFile = MAX_PATH;
    ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST | OFN_HIDEREADONLY;
    ofn.lpstrTitle = L"Pilih file video";
    if (GetOpenFileNameW(&ofn)) {
        outPath = fileBuf;
        return true;
    }
    return false;
}

// Build and start ffmpeg process; returns true on success
static bool StartFfmpeg(HWND hwnd) {
    wchar_t videoPath[MAX_PATH];
    GetWindowTextW(g_hEditVideo, videoPath, MAX_PATH);
    std::wstring video = videoPath;

    wchar_t keyBuf[512];
    GetWindowTextW(g_hEditKey, keyBuf, 512);
    std::wstring key = keyBuf;

    if (!FileExists(video)) {
        MessageBoxW(hwnd, L"File tidak valid", L"Error", MB_ICONERROR | MB_OK);
        return false;
    }
    if (!IsVideoExtension(video)) {
        MessageBoxW(hwnd, L"File bukan video!", L"Error", MB_ICONERROR | MB_OK);
        return false;
    }
    if (key.empty()) {
        MessageBoxW(hwnd, L"Stream Key kosong", L"Error", MB_ICONERROR | MB_OK);
        return false;
    }

    // Command line arguments for ffmpeg
    std::wstring args =
        L"-stream_loop -1 -readrate 1.05 -i \"" + video +
        L"\" -f fifo -fifo_format flv -map 0:v -map 0:a -attempt_recovery 1 -max_recovery_attempts 20 -recover_any_error 1 -tag:v 7 -tag:a 10 -recovery_wait_time 2 -flags +global_header -c copy rtmp://a.rtmp.youtube.com/live2/" + key;

    // Create pipes for stdout/stderr
    SECURITY_ATTRIBUTES sa{}; sa.nLength = sizeof(sa); sa.bInheritHandle = TRUE; sa.lpSecurityDescriptor = nullptr;
    if (!CreatePipe(&g_hPipeRead, &g_hPipeWrite, &sa, 0)) {
        MessageBoxW(hwnd, L"Gagal membuat pipe", L"Error", MB_ICONERROR | MB_OK);
        return false;
    }
    // Ensure read end is not inherited by child
    SetHandleInformation(g_hPipeRead, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOW si{}; si.cb = sizeof(si);
    si.dwFlags |= STARTF_USESTDHANDLES;
    si.hStdOutput = g_hPipeWrite;
    si.hStdError  = g_hPipeWrite;
    PROCESS_INFORMATION pi{};

    // CreateProcessW requires modifiable command line buffer
    std::vector<wchar_t> cmd(args.begin(), args.end());
    cmd.push_back(L'\0');

    BOOL ok = CreateProcessW(
        g_ffmpegPath.c_str(),      // lpApplicationName
        cmd.data(),                 // lpCommandLine (args only)
        nullptr, nullptr, TRUE,     // inherit handles for redirected stdout/err
        CREATE_NO_WINDOW,           // no console window
        nullptr, nullptr,
        &si, &pi);

    if (!ok) {
        if (g_hPipeRead) { CloseHandle(g_hPipeRead); g_hPipeRead = nullptr; }
        if (g_hPipeWrite) { CloseHandle(g_hPipeWrite); g_hPipeWrite = nullptr; }
        MessageBoxW(hwnd, L"Gagal menjalankan ffmpeg", L"Error", MB_ICONERROR | MB_OK);
        return false;
    }

    // We can close the write end in the parent after the child inherits it
    if (g_hPipeWrite) { CloseHandle(g_hPipeWrite); g_hPipeWrite = nullptr; }

    // Keep process handle to monitor/stop
    if (g_hFfmpegProcess) CloseHandle(g_hFfmpegProcess);
    g_hFfmpegProcess = pi.hProcess;
    CloseHandle(pi.hThread);
    g_isStreaming = true;
    SetWindowTextW(g_hLblStatus, L"Streaming started...");
    SetWindowTextW(g_hBtnStart, L"Stop Stream");
    SetTimer(hwnd, ID_TIMER_PROC, 2000, nullptr);

    // Start background thread to read ffmpeg output and stream to UI
    LogThreadCtx* ctx = (LogThreadCtx*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(LogThreadCtx));
    if (ctx) {
        ctx->hRead = g_hPipeRead;
        ctx->hwnd  = hwnd;
        g_hLogThread = CreateThread(nullptr, 0, LogThreadProc, ctx, 0, nullptr);
    }
    return true;
}

static void StopFfmpeg(HWND hwnd) {
    if (g_hFfmpegProcess) {
        TerminateProcess(g_hFfmpegProcess, 0);
        WaitForSingleObject(g_hFfmpegProcess, 2000);
        CloseHandle(g_hFfmpegProcess);
        g_hFfmpegProcess = nullptr;
    }
    if (g_hPipeRead) { CloseHandle(g_hPipeRead); g_hPipeRead = nullptr; }
    if (g_hPipeWrite) { CloseHandle(g_hPipeWrite); g_hPipeWrite = nullptr; }
    if (g_hLogThread) { WaitForSingleObject(g_hLogThread, 1000); CloseHandle(g_hLogThread); g_hLogThread = nullptr; }
    g_isStreaming = false;
    KillTimer(hwnd, ID_TIMER_PROC);
    SetWindowTextW(g_hLblStatus, L"Streaming stopped.");
    SetWindowTextW(g_hBtnStart, L"Start Stream");
}

// Check for ffmpeg.exe in exe directory; show error and quit if missing
static bool VerifyFfmpegOrDie(HWND owner) {
    std::wstring dir = GetExeDir();
    g_ffmpegPath = dir + L"\\ffmpeg.exe";
    if (!FileExists(g_ffmpegPath)) {
        MessageBoxW(owner, L"Error 1: FFMPEG tidak ditemukan", L"Error", MB_ICONERROR | MB_OK);
        return false;
    }
    return true;
}

// Window procedure
static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_CREATE: {
        // Use default GUI font
        g_hFont = (HFONT)GetStockObject(DEFAULT_GUI_FONT);

        const int M = 12;   // margin
        const int H = 26;   // control height
        const int LBLW = 90;// label width
        const int BTN_W = 110;
        const int WND_W = 600;

        // Row A: Path video
        CreateWindowW(L"STATIC", L"Path video", WS_CHILD | WS_VISIBLE,
            M, M+2, LBLW, H, hwnd, nullptr, nullptr, nullptr);

        g_hEditVideo = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL,
            M + LBLW + 8, M, WND_W - (M + LBLW + 8) - (BTN_W + 8) - M, H, hwnd, (HMENU)ID_EDIT_VIDEO, nullptr, nullptr);

        g_hBtnBrowse = CreateWindowW(L"BUTTON", L"Browse...", WS_CHILD | WS_VISIBLE | WS_TABSTOP,
            WND_W - (BTN_W + M), M, BTN_W, H, hwnd, (HMENU)ID_BTN_BROWSE, nullptr, nullptr);

        g_hLblValid = CreateWindowW(L"STATIC", L"", WS_CHILD | WS_VISIBLE,
            M + LBLW + 8, M + H + 6, 200, H, hwnd, (HMENU)ID_LBL_VALID, nullptr, nullptr);

        // Row B: Stream Key
        const int row2Y = M + H + 6 + H + 10;
        CreateWindowW(L"STATIC", L"Stream Key", WS_CHILD | WS_VISIBLE,
            M, row2Y+2, LBLW, H, hwnd, nullptr, nullptr, nullptr);

        g_hEditKey = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL,
            M + LBLW + 8, row2Y, WND_W - (M + LBLW + 8) - (BTN_W + 8) - M, H, hwnd, (HMENU)ID_EDIT_KEY, nullptr, nullptr);

        g_hBtnStart = CreateWindowW(L"BUTTON", L"Start Stream", WS_CHILD | WS_VISIBLE | WS_TABSTOP,
            WND_W - (BTN_W + M), row2Y, BTN_W, H, hwnd, (HMENU)ID_BTN_START, nullptr, nullptr);

        // Status label under inputs
        g_hLblStatus = CreateWindowW(L"STATIC", L"", WS_CHILD | WS_VISIBLE,
            M, row2Y + H + 10, WND_W - 2*M, H, hwnd, (HMENU)ID_LBL_STATUS, nullptr, nullptr);

        // Log output box (multiline, read-only)
        const int logY = row2Y + H + 10 + H + 10;
        g_hEditLog = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_CHILD | WS_VISIBLE | ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL | WS_VSCROLL,
            M, logY, WND_W - 2*M, 200, hwnd, (HMENU)ID_EDIT_LOG, nullptr, nullptr);

        // Apply font
        HWND ctrls[] = { g_hEditVideo, g_hBtnBrowse, g_hLblValid, g_hEditKey, g_hBtnStart, g_hLblStatus, g_hEditLog };
        for (HWND c : ctrls) if (c) SendMessageW(c, WM_SETFONT, (WPARAM)g_hFont, TRUE);

        if (!VerifyFfmpegOrDie(hwnd)) {
            PostQuitMessage(0);
            return -1;
        }

        g_hMainWnd = hwnd;
        return 0;
    }
    case WM_COMMAND: {
        int id = LOWORD(wParam);
        int code = HIWORD(wParam);
        if (id == ID_BTN_BROWSE && code == BN_CLICKED) {
            std::wstring path;
            if (BrowseForVideo(hwnd, path)) {
                if (!IsVideoExtension(path)) {
                    MessageBoxW(hwnd, L"File bukan video!", L"Error", MB_ICONERROR | MB_OK);
                }
                SetWindowTextW(g_hEditVideo, path.c_str());
                UpdateValidityLabel(hwnd);
            }
        } else if (id == ID_EDIT_VIDEO && code == EN_CHANGE) {
            UpdateValidityLabel(hwnd);
        } else if (id == ID_BTN_START && code == BN_CLICKED) {
            if (!g_isStreaming) {
                StartFfmpeg(hwnd);
            } else {
                StopFfmpeg(hwnd);
            }
        }
        return 0;
    }
    case WM_CTLCOLORSTATIC: {
        HDC hdc = (HDC)wParam;
        HWND hCtl = (HWND)lParam;
        if (hCtl == g_hLblValid) {
            SetBkMode(hdc, TRANSPARENT);
            COLORREF color = g_isValidFile ? RGB(0,128,0) : RGB(200,0,0);
            SetTextColor(hdc, color);
            return (LRESULT)GetSysColorBrush(COLOR_BTNFACE);
        }
        return DefWindowProcW(hwnd, msg, wParam, lParam);
    }
    case WM_TIMER: {
        if (wParam == ID_TIMER_PROC && g_hFfmpegProcess) {
            DWORD wait = WaitForSingleObject(g_hFfmpegProcess, 0);
            if (wait == WAIT_OBJECT_0) {
                // process ended
                CloseHandle(g_hFfmpegProcess);
                g_hFfmpegProcess = nullptr;
                g_isStreaming = false;
                KillTimer(hwnd, ID_TIMER_PROC);
                SetWindowTextW(g_hLblStatus, L"Streaming stopped.");
                SetWindowTextW(g_hBtnStart, L"Start Stream");
                if (g_hPipeRead) { CloseHandle(g_hPipeRead); g_hPipeRead = nullptr; }
                if (g_hLogThread) { WaitForSingleObject(g_hLogThread, 1000); CloseHandle(g_hLogThread); g_hLogThread = nullptr; }
            }
        }
        return 0;
    }
    case WM_APP_APPEND_LOG: {
        if (lParam) {
            wchar_t* text = (wchar_t*)lParam;
            AppendLog(text);
            HeapFree(GetProcessHeap(), 0, text);
        }
        return 0;
    }
    case WM_CLOSE:
        if (g_isStreaming) StopFfmpeg(hwnd);
        DestroyWindow(hwnd);
        return 0;
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

int APIENTRY wWinMain(HINSTANCE hInstance, HINSTANCE, LPWSTR, int nCmdShow) {
    // In case the binary was linked as a console app on some toolchains,
    // make sure any attached console stays hidden.
    if (HWND hc = GetConsoleWindow()) {
        ShowWindow(hc, SW_HIDE);
        FreeConsole();
    }

    const wchar_t CLASS_NAME[] = L"YT247DesktopWindow";

    WNDCLASSEXW wc{};
    wc.cbSize        = sizeof(wc);
    wc.style         = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc   = WndProc;
    wc.hInstance     = hInstance;
    wc.hIcon         = LoadIcon(nullptr, IDI_APPLICATION);
    wc.hCursor       = LoadCursor(nullptr, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    wc.lpszClassName = CLASS_NAME;
    wc.hIconSm       = wc.hIcon;

    if (!RegisterClassExW(&wc)) {
        MessageBoxW(nullptr, L"Failed to register window class", L"Error", MB_ICONERROR | MB_OK);
        return 1;
    }

    HWND hwnd = CreateWindowExW(0, CLASS_NAME, L"YT247Desktop V.1 -beta",
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
        CW_USEDEFAULT, CW_USEDEFAULT, 640, 460,
        nullptr, nullptr, hInstance, nullptr);

    if (!hwnd) return 1;
    // Center window on the work area
    RECT rc; GetWindowRect(hwnd, &rc);
    int w = rc.right - rc.left; int h = rc.bottom - rc.top;
    RECT wa; SystemParametersInfoW(SPI_GETWORKAREA, 0, &wa, 0);
    int x = wa.left + ((wa.right - wa.left) - w) / 2;
    int y = wa.top  + ((wa.bottom - wa.top) - h) / 2;
    SetWindowPos(hwnd, nullptr, x, y, 0, 0, SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE);
    ShowWindow(hwnd, nCmdShow);
    UpdateWindow(hwnd);

    // Message loop
    MSG msg;
    while (GetMessageW(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    return (int)msg.wParam;
}
