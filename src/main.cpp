// YT247Desktop - Minimal Win32 GUI app to stream a local video to YouTube Live via ffmpeg

#include <windows.h>
#include <commdlg.h>
#include <string>
#include <vector>
#include <sstream>
#include <algorithm>

// Control IDs
enum : int {
    ID_EDIT_VIDEO = 1001,
    ID_BTN_BROWSE = 1002,
    ID_LBL_VALID  = 1003,
    ID_EDIT_KEY   = 1004,
    ID_BTN_START  = 1005,
    ID_BTN_STOP   = 1008,
    ID_BTN_CLEARLOG = 1009,
    ID_LBL_ARG_HDR = 1019,
    ID_EDIT_ARGS   = 1020,
    ID_BTN_COPYARGS = 1021,
    ID_INFO_HEADER = 1010,
    ID_INFO_L_SIZE = 1011,
    ID_INFO_V_SIZE = 1012,
    ID_INFO_L_DUR  = 1013,
    ID_INFO_V_DUR  = 1014,
    ID_INFO_L_BR   = 1015,
    ID_INFO_V_BR   = 1016,
    ID_INFO_L_RES  = 1017,
    ID_INFO_V_RES  = 1018,
    ID_LBL_STATUS = 1006,
    ID_EDIT_LOG   = 1007,
    ID_TIMER_PROC = 2001
};

static HWND g_hEditVideo = nullptr;
static HWND g_hBtnBrowse = nullptr;
static HWND g_hLblValid  = nullptr;
static HWND g_hEditKey   = nullptr;
static HWND g_hBtnStart  = nullptr;
static HWND g_hBtnStop   = nullptr;
static HWND g_hBtnClearLog = nullptr;
static HWND g_hLblStatus = nullptr;
static HWND g_hEditLog   = nullptr;
static HFONT g_hFont     = nullptr;

// Video info controls
static HWND g_hInfoHeader = nullptr;
static HWND g_hInfoLSize = nullptr;  static HWND g_hInfoVSize = nullptr;
static HWND g_hInfoLDur = nullptr;   static HWND g_hInfoVDur = nullptr;
static HWND g_hInfoLBr = nullptr;    static HWND g_hInfoVBr = nullptr;
static HWND g_hInfoLRes = nullptr;   static HWND g_hInfoVRes = nullptr;

static bool  g_isValidFile = false;
static bool  g_isStreaming = false;
static HANDLE g_hFfmpegProcess = nullptr;
static std::wstring g_ffmpegPath; // full path to ffmpeg.exe
static HANDLE g_hPipeRead = nullptr;
static HANDLE g_hPipeWrite = nullptr;
static HANDLE g_hPipeStdinRead = nullptr;
static HANDLE g_hPipeStdinWrite = nullptr;
static HANDLE g_hLogThread = nullptr;
static HWND   g_hMainWnd   = nullptr;
static HWND   g_hLblArgHdr = nullptr;
static HWND   g_hEditArgs  = nullptr;
static HWND   g_hBtnCopyArgs = nullptr;

// Scrolling
static int    g_scrollPos = 0;       // current vertical scroll position in pixels
static int    g_contentHeight = 0;   // total content height in pixels

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

// Try load custom icons from app folder (app.ico). Returns handles if found.
static void LoadCustomIcons(HICON& outLarge, HICON& outSmall) {
    outLarge = nullptr; outSmall = nullptr;
    std::wstring ico = GetExeDir() + L"\\app.ico";
    int cxLarge = GetSystemMetrics(SM_CXICON);
    int cyLarge = GetSystemMetrics(SM_CYICON);
    int cxSmall = GetSystemMetrics(SM_CXSMICON);
    int cySmall = GetSystemMetrics(SM_CYSMICON);
    HICON hLarge = (HICON)LoadImageW(nullptr, ico.c_str(), IMAGE_ICON, cxLarge, cyLarge, LR_LOADFROMFILE);
    HICON hSmall = (HICON)LoadImageW(nullptr, ico.c_str(), IMAGE_ICON, cxSmall, cySmall, LR_LOADFROMFILE);
    if (hLarge) outLarge = hLarge;
    if (hSmall) outSmall = hSmall;
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

static void RecalcScrollBar(HWND hwnd) {
    RECT rc; GetClientRect(hwnd, &rc);
    int page = rc.bottom - rc.top;
    if (page < 0) page = 0;
    SCROLLINFO si{}; si.cbSize = sizeof(si);
    si.fMask = SIF_RANGE | SIF_PAGE | SIF_POS;
    si.nMin = 0;
    si.nMax = (g_contentHeight > 0) ? (g_contentHeight - 1) : 0;
    si.nPage = (UINT)page;
    if (g_scrollPos > si.nMax - (int)si.nPage + 1) g_scrollPos = std::max(0, si.nMax - (int)si.nPage + 1);
    si.nPos = g_scrollPos;
    SetScrollInfo(hwnd, SB_VERT, &si, TRUE);
}

// Build the ffmpeg arguments (without executable), based on selected video and key
static std::wstring BuildFfmpegArgs(const std::wstring& video, const std::wstring& key) {
    if (video.empty() || key.empty()) return L"";
    return L"-stream_loop -1 -readrate 1.05 -i \"" + video +
           L"\" -f fifo -fifo_format flv -map 0:v -map 0:a -attempt_recovery 1 -max_recovery_attempts 20 -recover_any_error 1 -tag:v 7 -tag:a 10 -recovery_wait_time 2 -flags +global_header -c copy rtmp://a.rtmp.youtube.com/live2/" + key;
}

// Update the visible args preview field when inputs change
static void UpdateArgsPreview() {
    if (!g_hEditArgs) return;
    wchar_t videoPath[MAX_PATH]; GetWindowTextW(g_hEditVideo, videoPath, MAX_PATH);
    wchar_t keyBuf[512]; GetWindowTextW(g_hEditKey, keyBuf, 512);
    std::wstring video = videoPath; std::wstring key = keyBuf;
    if (!video.empty() && FileExists(video) && IsVideoExtension(video) && !key.empty()) {
        std::wstring args = BuildFfmpegArgs(video, key);
        SetWindowTextW(g_hEditArgs, args.c_str());
    } else {
        SetWindowTextW(g_hEditArgs, L"");
    }
}

// Human-friendly bytes formatting
static std::wstring FormatBytes(unsigned long long bytes) {
    const wchar_t* units[] = { L"B", L"KB", L"MB", L"GB", L"TB" };
    double v = (double)bytes;
    int u = 0;
    while (v >= 1024.0 && u < 4) { v /= 1024.0; ++u; }
    wchar_t buf[64];
    if (u == 0) swprintf(buf, 64, L"%llu %s", bytes, units[u]);
    else swprintf(buf, 64, L"%.1f %s", v, units[u]);
    return buf;
}

static std::wstring FormatDurationHMS(unsigned long long hundredNs) {
    unsigned long long total_ms = hundredNs / 10000ULL;
    unsigned long long total_sec = total_ms / 1000ULL;
    unsigned long long h = total_sec / 3600ULL;
    unsigned long long m = (total_sec % 3600ULL) / 60ULL;
    unsigned long long s = total_sec % 60ULL;
    wchar_t buf[64]; swprintf(buf, 64, L"%02llu:%02llu:%02llu", h, m, s);
    return buf;
}

static std::wstring FormatBitrate(unsigned long br) {
    if (br == 0) return L"";
    wchar_t buf[64];
    if (br >= 1000000UL) swprintf(buf, 64, L"%.1f Mbps", br / 1000000.0);
    else if (br >= 1000UL) swprintf(buf, 64, L"%.1f Kbps", br / 1000.0);
    else swprintf(buf, 64, L"%lu bps", br);
    return buf;
}

#include <shobjidl.h>
#include <propkey.h>
#include <propvarutil.h>

static void ClearVideoInfoFields() {
    if (g_hInfoVSize) SetWindowTextW(g_hInfoVSize, L"");
    if (g_hInfoVDur)  SetWindowTextW(g_hInfoVDur,  L"");
    if (g_hInfoVBr)   SetWindowTextW(g_hInfoVBr,   L"");
    if (g_hInfoVRes)  SetWindowTextW(g_hInfoVRes,  L"");
}

static void RefreshVideoInfo(const std::wstring& path) {
    // File size
    WIN32_FILE_ATTRIBUTE_DATA fad;
    if (GetFileAttributesExW(path.c_str(), GetFileExInfoStandard, &fad)) {
        ULARGE_INTEGER sz; sz.HighPart = fad.nFileSizeHigh; sz.LowPart = fad.nFileSizeLow;
        SetWindowTextW(g_hInfoVSize, FormatBytes(sz.QuadPart).c_str());
    } else {
        SetWindowTextW(g_hInfoVSize, L"");
    }

    // Use Shell property store for duration/bitrate/resolution
    IPropertyStore* store = nullptr;
    HRESULT hr = SHGetPropertyStoreFromParsingName(path.c_str(), nullptr, GPS_DEFAULT, IID_PPV_ARGS(&store));
    if (SUCCEEDED(hr) && store) {
        PROPVARIANT pv; PropVariantInit(&pv);
        unsigned long long dur100ns = 0ULL;
        unsigned long long sizeBytes = 0ULL;
        // capture size for fallback bitrate
        {
            WIN32_FILE_ATTRIBUTE_DATA fad2;
            if (GetFileAttributesExW(path.c_str(), GetFileExInfoStandard, &fad2)) { ULARGE_INTEGER s; s.HighPart = fad2.nFileSizeHigh; s.LowPart = fad2.nFileSizeLow; sizeBytes = s.QuadPart; }
        }
        // Duration
        if (SUCCEEDED(store->GetValue(PKEY_Media_Duration, &pv))) {
            if (pv.vt == VT_UI8 || pv.vt == VT_UI4) {
                dur100ns = (pv.vt == VT_UI8) ? pv.uhVal.QuadPart : pv.ulVal;
                SetWindowTextW(g_hInfoVDur, FormatDurationHMS(dur100ns).c_str());
            }
            PropVariantClear(&pv);
        } else {
            SetWindowTextW(g_hInfoVDur, L"");
        }
        // Average bitrate: compute from file size and duration if available
        unsigned long br = 0;
        if (dur100ns > 0 && sizeBytes > 0) {
            unsigned long long sec = (dur100ns / 10000000ULL); // 100ns to s
            if (sec > 0) {
                unsigned long long bps64 = (sizeBytes * 8ULL) / sec;
                br = (unsigned long)((bps64 > 0xFFFFFFFFULL) ? 0xFFFFFFFFUL : bps64);
            }
        }
        SetWindowTextW(g_hInfoVBr, FormatBitrate(br).c_str());
        // Resolution
        LONG w = 0, h = 0;
        if (SUCCEEDED(store->GetValue(PKEY_Video_FrameWidth, &pv))) {
            if (pv.vt == VT_UI4) w = (LONG)pv.ulVal; PropVariantClear(&pv);
        }
        if (SUCCEEDED(store->GetValue(PKEY_Video_FrameHeight, &pv))) {
            if (pv.vt == VT_UI4) h = (LONG)pv.ulVal; PropVariantClear(&pv);
        }
        if (w > 0 && h > 0) {
            wchar_t buf[64]; swprintf(buf, 64, L"%dx%d", w, h);
            SetWindowTextW(g_hInfoVRes, buf);
        } else {
            SetWindowTextW(g_hInfoVRes, L"");
        }
        store->Release();
    } else {
        SetWindowTextW(g_hInfoVDur, L"");
        SetWindowTextW(g_hInfoVBr, L"");
        SetWindowTextW(g_hInfoVRes, L"");
    }
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
        while ((pos = pending.find_first_of("\r\n")) != std::string::npos) {
            char delim = pending[pos];
            // Extract content without the delimiter
            std::string chunk = pending.substr(0, pos);
            pending.erase(0, pos + 1);
            // If CR is followed by LF, consume LF to avoid blank line
            if (delim == '\r' && !pending.empty() && pending[0] == '\n') {
                pending.erase(0, 1);
            }
            std::wstring w = ToWideBestEffort(chunk.data(), (int)chunk.size());
            // For LF: append newline to keep line breaks
            bool replace = (delim == '\r');
            if (!replace) w += L"\r\n";
            if (w.empty()) continue;
            size_t bytes = (w.size() + 1) * sizeof(wchar_t);
            wchar_t* copy = (wchar_t*)HeapAlloc(GetProcessHeap(), 0, bytes);
            if (!copy) continue;
            memcpy(copy, w.c_str(), bytes);
            PostMessageW(ctx->hwnd, WM_APP_APPEND_LOG, replace ? 1 : 0, (LPARAM)copy);
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
            ClearVideoInfoFields();
        } else {
            g_isValidFile = true;
            SetWindowTextW(g_hLblValid, L"Valid");
            RefreshVideoInfo(p);
        }
    } else {
        g_isValidFile = false;
        if (!p.empty()) SetWindowTextW(g_hLblValid, L"File tidak valid");
        else SetWindowTextW(g_hLblValid, L"");
        ClearVideoInfoFields();
    }
    InvalidateRect(g_hLblValid, nullptr, TRUE);
    UpdateArgsPreview();
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

    // Command line arguments for ffmpeg (excluding program name)
    std::wstring args = BuildFfmpegArgs(video, key);

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
    // Create stdin pipe and attach as child's standard input
    if (!CreatePipe(&g_hPipeStdinRead, &g_hPipeStdinWrite, &sa, 0)) {
        if (g_hPipeRead) { CloseHandle(g_hPipeRead); g_hPipeRead = nullptr; }
        if (g_hPipeWrite) { CloseHandle(g_hPipeWrite); g_hPipeWrite = nullptr; }
        MessageBoxW(hwnd, L"Gagal membuat stdin pipe", L"Error", MB_ICONERROR | MB_OK);
        return false;
    }
    // Ensure the write end is NOT inherited by child
    SetHandleInformation(g_hPipeStdinWrite, HANDLE_FLAG_INHERIT, 0);
    si.hStdInput = g_hPipeStdinRead;
    PROCESS_INFORMATION pi{};

    // Build full command line with program name as argv[0]
    std::wstring cmdLine = L"\"" + g_ffmpegPath + L"\" " + args;
    std::vector<wchar_t> cmd(cmdLine.begin(), cmdLine.end());
    cmd.push_back(L'\0');

    BOOL ok = CreateProcessW(
        nullptr,                    // lpApplicationName (unused when full cmd provided)
        cmd.data(),                 // lpCommandLine (program + args)
        nullptr, nullptr, TRUE,     // inherit handles for redirected stdout/err
        CREATE_NO_WINDOW,           // no console window
        nullptr, nullptr,
        &si, &pi);

    if (!ok) {
        if (g_hPipeRead) { CloseHandle(g_hPipeRead); g_hPipeRead = nullptr; }
        if (g_hPipeWrite) { CloseHandle(g_hPipeWrite); g_hPipeWrite = nullptr; }
        if (g_hPipeStdinRead) { CloseHandle(g_hPipeStdinRead); g_hPipeStdinRead = nullptr; }
        if (g_hPipeStdinWrite) { CloseHandle(g_hPipeStdinWrite); g_hPipeStdinWrite = nullptr; }
        MessageBoxW(hwnd, L"Gagal menjalankan ffmpeg", L"Error", MB_ICONERROR | MB_OK);
        return false;
    }

    // We can close the write end in the parent after the child inherits it
    if (g_hPipeWrite) { CloseHandle(g_hPipeWrite); g_hPipeWrite = nullptr; }
    if (g_hPipeStdinRead) { CloseHandle(g_hPipeStdinRead); g_hPipeStdinRead = nullptr; }

    // Keep process handle to monitor/stop
    if (g_hFfmpegProcess) CloseHandle(g_hFfmpegProcess);
    g_hFfmpegProcess = pi.hProcess;
    CloseHandle(pi.hThread);
    g_isStreaming = true;
    SetWindowTextW(g_hLblStatus, L"Streaming started...");
    if (g_hBtnStop) EnableWindow(g_hBtnStop, TRUE);
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
        // Graceful: send 'q' to ffmpeg stdin and wait
        bool exited = false;
        if (g_hPipeStdinWrite) {
            const char q = 'q';
            DWORD written = 0;
            WriteFile(g_hPipeStdinWrite, &q, 1, &written, nullptr);
            CloseHandle(g_hPipeStdinWrite); g_hPipeStdinWrite = nullptr;
            DWORD w = WaitForSingleObject(g_hFfmpegProcess, 5000);
            if (w == WAIT_OBJECT_0) exited = true;
        }
        if (!exited) {
            TerminateProcess(g_hFfmpegProcess, 0);
            WaitForSingleObject(g_hFfmpegProcess, 2000);
        }
        CloseHandle(g_hFfmpegProcess);
        g_hFfmpegProcess = nullptr;
    }
    if (g_hPipeRead) { CloseHandle(g_hPipeRead); g_hPipeRead = nullptr; }
    if (g_hPipeWrite) { CloseHandle(g_hPipeWrite); g_hPipeWrite = nullptr; }
    if (g_hPipeStdinRead) { CloseHandle(g_hPipeStdinRead); g_hPipeStdinRead = nullptr; }
    if (g_hPipeStdinWrite) { CloseHandle(g_hPipeStdinWrite); g_hPipeStdinWrite = nullptr; }
    if (g_hLogThread) { WaitForSingleObject(g_hLogThread, 1000); CloseHandle(g_hLogThread); g_hLogThread = nullptr; }
    g_isStreaming = false;
    KillTimer(hwnd, ID_TIMER_PROC);
    SetWindowTextW(g_hLblStatus, L"Streaming stopped.");
    // Inform user to end stream in YouTube Studio
    MessageBoxW(hwnd,
        L"Proses stream sudah dihentikan, silahkan login ke Youtube Studio untuk melakukan end stream",
        L"Informasi",
        MB_ICONINFORMATION | MB_OK);
    if (g_hBtnStop) EnableWindow(g_hBtnStop, FALSE);
    // Clear log after stream fully stopped
    if (g_hEditLog) SetWindowTextW(g_hEditLog, L"");
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

        const int M = 12;      // margin
        const int H = 26;      // control height
        const int LBLW = 90;   // label width
        const int BTN_W = 110; // button width
        const int WND_W = 600;
        const int INPUTS_X = M + LBLW + 8; // left edge for input/value columns

        // Row A: Path video
        CreateWindowW(L"STATIC", L"Path video", WS_CHILD | WS_VISIBLE,
            M, M+4, LBLW, H, hwnd, nullptr, nullptr, nullptr);

        g_hEditVideo = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL,
            INPUTS_X, M, WND_W - INPUTS_X - (BTN_W + 8) - M, H, hwnd, (HMENU)ID_EDIT_VIDEO, nullptr, nullptr);

        g_hBtnBrowse = CreateWindowW(L"BUTTON", L"Browse...", WS_CHILD | WS_VISIBLE | WS_TABSTOP,
            WND_W - (BTN_W + M), M, BTN_W, H, hwnd, (HMENU)ID_BTN_BROWSE, nullptr, nullptr);

        const int validY = M + H + 8;
        g_hLblValid = CreateWindowW(L"STATIC", L"", WS_CHILD | WS_VISIBLE,
            INPUTS_X, validY, 200, H, hwnd, (HMENU)ID_LBL_VALID, nullptr, nullptr);

        // Video Information section below the Valid label
        const int INFO_LW = LBLW; // align info labels width with main labels
        const int infoY = validY + H + 8;
        g_hInfoHeader = CreateWindowW(L"STATIC", L"Video Information", WS_CHILD | WS_VISIBLE,
            M, infoY, WND_W - 2*M, H, hwnd, (HMENU)ID_INFO_HEADER, nullptr, nullptr);

        const int infoRowY0 = infoY + H + 4;
        const int INFO_GAP = 0; // align values exactly with input textbox left edge
        const int infoValX = INPUTS_X + INFO_GAP;
        const int infoValW = WND_W - infoValX - M;
        // Size
        g_hInfoLSize = CreateWindowW(L"STATIC", L"Ukuran file", WS_CHILD | WS_VISIBLE,
            M, infoRowY0 + 0*H, INFO_LW, H, hwnd, (HMENU)ID_INFO_L_SIZE, nullptr, nullptr);
        g_hInfoVSize = CreateWindowW(L"STATIC", L"", WS_CHILD | WS_VISIBLE,
            infoValX, infoRowY0 + 0*H, infoValW, H, hwnd, (HMENU)ID_INFO_V_SIZE, nullptr, nullptr);
        // Duration
        g_hInfoLDur = CreateWindowW(L"STATIC", L"Durasi", WS_CHILD | WS_VISIBLE,
            M, infoRowY0 + 1*H, INFO_LW, H, hwnd, (HMENU)ID_INFO_L_DUR, nullptr, nullptr);
        g_hInfoVDur = CreateWindowW(L"STATIC", L"", WS_CHILD | WS_VISIBLE,
            infoValX, infoRowY0 + 1*H, infoValW, H, hwnd, (HMENU)ID_INFO_V_DUR, nullptr, nullptr);
        // Bitrate
        g_hInfoLBr = CreateWindowW(L"STATIC", L"Bitrate", WS_CHILD | WS_VISIBLE,
            M, infoRowY0 + 2*H, INFO_LW, H, hwnd, (HMENU)ID_INFO_L_BR, nullptr, nullptr);
        g_hInfoVBr = CreateWindowW(L"STATIC", L"", WS_CHILD | WS_VISIBLE,
            infoValX, infoRowY0 + 2*H, infoValW, H, hwnd, (HMENU)ID_INFO_V_BR, nullptr, nullptr);
        // Resolution
        g_hInfoLRes = CreateWindowW(L"STATIC", L"Resolusi", WS_CHILD | WS_VISIBLE,
            M, infoRowY0 + 3*H, INFO_LW, H, hwnd, (HMENU)ID_INFO_L_RES, nullptr, nullptr);
        g_hInfoVRes = CreateWindowW(L"STATIC", L"", WS_CHILD | WS_VISIBLE,
            infoValX, infoRowY0 + 3*H, infoValW, H, hwnd, (HMENU)ID_INFO_V_RES, nullptr, nullptr);

        // Row B: Stream Key (below video info section)
        const int row2Y = infoRowY0 + 4*H + 8; // after 4 rows of info
        CreateWindowW(L"STATIC", L"Stream Key", WS_CHILD | WS_VISIBLE,
            M, row2Y+4, LBLW, H, hwnd, nullptr, nullptr, nullptr);

        g_hEditKey = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL,
            INPUTS_X, row2Y, WND_W - INPUTS_X - (2*BTN_W + 8) - M, H, hwnd, (HMENU)ID_EDIT_KEY, nullptr, nullptr);

        // Place Start to the left of Stop (Stop is on the right)
        g_hBtnStart = CreateWindowW(L"BUTTON", L"Start Stream", WS_CHILD | WS_VISIBLE | WS_TABSTOP,
            WND_W - (2*BTN_W + 8 + M), row2Y, BTN_W, H, hwnd, (HMENU)ID_BTN_START, nullptr, nullptr);

        g_hBtnStop = CreateWindowW(L"BUTTON", L"Stop Stream", WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_DISABLED,
            WND_W - (BTN_W + M), row2Y, BTN_W, H, hwnd, (HMENU)ID_BTN_STOP, nullptr, nullptr);

        // Stream Argument header and preview under Stream Key
        const int argHdrY = row2Y + H + 8;
        g_hLblArgHdr = CreateWindowW(L"STATIC", L"Stream Argument", WS_CHILD | WS_VISIBLE,
            M, argHdrY, WND_W - 2*M, H, hwnd, (HMENU)ID_LBL_ARG_HDR, nullptr, nullptr);

        const int argEditY = argHdrY + H + 4;
        const int argBtnW = BTN_W;
        const int argEditW = WND_W - (2*M) - argBtnW - 8;
        g_hEditArgs = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL | ES_READONLY | WS_TABSTOP,
            M, argEditY, argEditW, H, hwnd, (HMENU)ID_EDIT_ARGS, nullptr, nullptr);
        g_hBtnCopyArgs = CreateWindowW(L"BUTTON", L"Copy", WS_CHILD | WS_VISIBLE | WS_TABSTOP,
            M + argEditW + 8, argEditY, argBtnW, H, hwnd, (HMENU)ID_BTN_COPYARGS, nullptr, nullptr);

        // Status label under arguments
        const int statusY = argEditY + H + 8;
        g_hLblStatus = CreateWindowW(L"STATIC", L"", WS_CHILD | WS_VISIBLE,
            M, statusY, WND_W - 2*M, H, hwnd, (HMENU)ID_LBL_STATUS, nullptr, nullptr);

        // Log output box (multiline, read-only)
        const int logY = statusY + H + 8;
        g_hEditLog = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_CHILD | WS_VISIBLE | ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL | WS_VSCROLL,
            M, logY, WND_W - 2*M, 200, hwnd, (HMENU)ID_EDIT_LOG, nullptr, nullptr);

        // Clear Log button below the log box (right-aligned)
        const int clearY = logY + 200 + 8;
        g_hBtnClearLog = CreateWindowW(L"BUTTON", L"Clear Log", WS_CHILD | WS_VISIBLE | WS_TABSTOP,
            WND_W - (BTN_W + M), clearY, BTN_W, H, hwnd, (HMENU)ID_BTN_CLEARLOG, nullptr, nullptr);

        // Apply font
        HWND ctrls[] = { g_hEditVideo, g_hBtnBrowse, g_hLblValid, g_hInfoHeader,
                         g_hInfoLSize, g_hInfoVSize, g_hInfoLDur, g_hInfoVDur,
                         g_hInfoLBr, g_hInfoVBr, g_hInfoLRes, g_hInfoVRes,
                         g_hEditKey, g_hBtnStart, g_hBtnStop, g_hLblArgHdr, g_hEditArgs, g_hBtnCopyArgs,
                         g_hLblStatus, g_hEditLog, g_hBtnClearLog };
        for (HWND c : ctrls) if (c) SendMessageW(c, WM_SETFONT, (WPARAM)g_hFont, TRUE);

        if (!VerifyFfmpegOrDie(hwnd)) {
            PostQuitMessage(0);
            return -1;
        }

        // Compute total content height and initialize scrollbar
        g_contentHeight = clearY + H + M;
        RecalcScrollBar(hwnd);

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
        } else if (id == ID_EDIT_KEY && code == EN_CHANGE) {
            UpdateArgsPreview();
        } else if (id == ID_BTN_START && code == BN_CLICKED) {
            if (!g_isStreaming) {
                StartFfmpeg(hwnd);
            }
        } else if (id == ID_BTN_STOP && code == BN_CLICKED) {
            if (g_isStreaming) {
                StopFfmpeg(hwnd);
            }
        } else if (id == ID_BTN_CLEARLOG && code == BN_CLICKED) {
            if (g_hEditLog) SetWindowTextW(g_hEditLog, L"");
        } else if (id == ID_BTN_COPYARGS && code == BN_CLICKED) {
            // Copy current args preview to clipboard
            if (OpenClipboard(hwnd)) {
                EmptyClipboard();
                int len = GetWindowTextLengthW(g_hEditArgs);
                std::wstring s; s.resize(len);
                if (len > 0) GetWindowTextW(g_hEditArgs, &s[0], len + 1);
                size_t bytes = (s.size() + 1) * sizeof(wchar_t);
                HGLOBAL hMem = GlobalAlloc(GMEM_MOVEABLE, bytes);
                if (hMem) {
                    void* p = GlobalLock(hMem);
                    if (p) { memcpy(p, s.c_str(), bytes); GlobalUnlock(hMem); SetClipboardData(CF_UNICODETEXT, hMem); }
                }
                CloseClipboard();
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
    case WM_SIZE: {
        RecalcScrollBar(hwnd);
        return 0;
    }
    case WM_VSCROLL: {
        int action = LOWORD(wParam);
        SCROLLINFO si{}; si.cbSize = sizeof(si); si.fMask = SIF_ALL; GetScrollInfo(hwnd, SB_VERT, &si);
        int pos = si.nPos;
        switch (action) {
        case SB_LINEUP:   pos -= 20; break;
        case SB_LINEDOWN: pos += 20; break;
        case SB_PAGEUP:   pos -= (int)si.nPage; break;
        case SB_PAGEDOWN: pos += (int)si.nPage; break;
        case SB_THUMBTRACK: pos = si.nTrackPos; break;
        default: break;
        }
        if (pos < si.nMin) pos = si.nMin;
        int maxPos = si.nMax - (int)si.nPage + 1; if (pos > maxPos) pos = std::max(0, maxPos);
        if (pos != g_scrollPos) {
            int dy = g_scrollPos - pos; // positive dy moves content down
            g_scrollPos = pos;
            SetScrollPos(hwnd, SB_VERT, g_scrollPos, TRUE);
            ScrollWindowEx(hwnd, 0, dy, nullptr, nullptr, nullptr, nullptr, SW_INVALIDATE | SW_ERASE | SW_SCROLLCHILDREN);
        }
        return 0;
    }
    case WM_MOUSEWHEEL: {
        short delta = (short)HIWORD(wParam);
        // typical wheel = 120 units per notch; use 40px per notch
        int step = (delta / 120) * 40;
        if (step != 0) {
            SCROLLINFO si{}; si.cbSize = sizeof(si); si.fMask = SIF_ALL; GetScrollInfo(hwnd, SB_VERT, &si);
            int pos = g_scrollPos - step;
            if (pos < si.nMin) pos = si.nMin;
            int maxPos = si.nMax - (int)si.nPage + 1; if (pos > maxPos) pos = std::max(0, maxPos);
            if (pos != g_scrollPos) {
                int dy = g_scrollPos - pos;
                g_scrollPos = pos;
                SetScrollPos(hwnd, SB_VERT, g_scrollPos, TRUE);
                ScrollWindowEx(hwnd, 0, dy, nullptr, nullptr, nullptr, nullptr, SW_INVALIDATE | SW_ERASE | SW_SCROLLCHILDREN);
            }
        }
        return 0;
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
                if (g_hBtnStop) EnableWindow(g_hBtnStop, FALSE);
                if (g_hPipeStdinRead) { CloseHandle(g_hPipeStdinRead); g_hPipeStdinRead = nullptr; }
                if (g_hPipeStdinWrite) { CloseHandle(g_hPipeStdinWrite); g_hPipeStdinWrite = nullptr; }
                if (g_hPipeRead) { CloseHandle(g_hPipeRead); g_hPipeRead = nullptr; }
                if (g_hLogThread) { WaitForSingleObject(g_hLogThread, 1000); CloseHandle(g_hLogThread); g_hLogThread = nullptr; }
                if (g_hEditLog) SetWindowTextW(g_hEditLog, L"");
            }
        }
        return 0;
    }
    case WM_APP_APPEND_LOG: {
        if (lParam) {
            wchar_t* text = (wchar_t*)lParam;
            if (wParam == 1) {
                // Replace last line with this text (no newline expected)
                int lines = (int)SendMessageW(g_hEditLog, EM_GETLINECOUNT, 0, 0);
                int start = 0;
                if (lines > 0) {
                    start = (int)SendMessageW(g_hEditLog, EM_LINEINDEX, lines - 1, 0);
                    if (start < 0) start = 0;
                }
                int end = GetWindowTextLengthW(g_hEditLog);
                SendMessageW(g_hEditLog, EM_SETSEL, start, end);
                SendMessageW(g_hEditLog, EM_REPLACESEL, FALSE, (LPARAM)text);
                SendMessageW(g_hEditLog, EM_SCROLLCARET, 0, 0);
            } else {
                // Append new line
                AppendLog(text);
            }
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

    // Initialize COM for property store access
    HRESULT _comInitHr = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);

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
    // Try replace with custom icons if app.ico exists next to EXE
    HICON icLarge=nullptr, icSmall=nullptr; LoadCustomIcons(icLarge, icSmall);
    if (icLarge) wc.hIcon = icLarge;
    if (icSmall) wc.hIconSm = icSmall;

    if (!RegisterClassExW(&wc)) {
        MessageBoxW(nullptr, L"Failed to register window class", L"Error", MB_ICONERROR | MB_OK);
        return 1;
    }

    HWND hwnd = CreateWindowExW(0, CLASS_NAME, L"YT247Desktop V.1 -beta",
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX | WS_VSCROLL,
        CW_USEDEFAULT, CW_USEDEFAULT, 640, 600,
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
    if (SUCCEEDED(_comInitHr)) CoUninitialize();
    return (int)msg.wParam;
}
