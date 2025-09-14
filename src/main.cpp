// YT247Desktop - Minimal Win32 GUI app to stream a local video to YouTube Live via ffmpeg

// Networking must include Winsock2 before windows.h
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <commdlg.h>
#include <winhttp.h>
#include <wincrypt.h>
#include <bcrypt.h>
#include <shlobj.h>
#include <string>
#include <vector>
#include <sstream>
#include <algorithm>
#include <cstdint>

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
    ID_BTN_GOOGLE   = 1022,
    ID_BTN_SIGNOUT  = 1023,
    ID_LBL_EMAIL    = 1024,
    ID_INFO_HEADER = 1010,
    ID_INFO_L_SIZE = 1011,
    ID_INFO_V_SIZE = 1012,
    ID_INFO_L_DUR  = 1013,
    ID_INFO_V_DUR  = 1014,
    ID_INFO_L_BR   = 1015,
    ID_INFO_V_BR   = 1016,
    ID_INFO_L_RES  = 1017,
    ID_INFO_V_RES  = 1018,
    ID_INFO_L_ORI  = 1025,
    ID_INFO_V_ORI  = 1026,
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
static HWND g_hInfoLOr = nullptr;    static HWND g_hInfoVOr = nullptr;

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
static HWND   g_hBtnGoogle = nullptr;
static HWND   g_hBtnSignOut = nullptr;
static HWND   g_hLblEmail = nullptr;

// Scrolling
static int    g_scrollPos = 0;       // current vertical scroll position in pixels
static int    g_contentHeight = 0;   // total content height in pixels

// Custom message to append log text (lParam = wchar_t* allocated on heap)
constexpr UINT WM_APP_APPEND_LOG = WM_APP + 1;
// Timer for auth auto-refresh
constexpr UINT ID_TIMER_AUTH = 2002;
// Forward decl for early use
static void AppendLog(const std::wstring& text);

// Firebase/Google OAuth configuration (loaded from env at runtime)
// Set env vars before running:
//   YT247_FIREBASE_API_KEY, YT247_GOOGLE_CLIENT_ID, YT247_GOOGLE_CLIENT_SECRET (optional)
static std::wstring gFirebaseApiKey;     // from env YT247_FIREBASE_API_KEY
static std::wstring gGoogleClientId;     // from env YT247_GOOGLE_CLIENT_ID
static std::wstring gGoogleClientSecret; // from env YT247_GOOGLE_CLIENT_SECRET (optional)
static const wchar_t* kRedirectPath   = L"/callback";

// Auth state
static bool g_isSignedIn = false;
static std::wstring g_idToken;
static std::wstring g_refreshToken;
static std::wstring g_signedInEmail;
static std::wstring g_baseTitle;

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

// URL-encode ASCII string
static std::string UrlEncode(const std::string& s) {
    std::ostringstream o;
    const char* hex = "0123456789ABCDEF";
    for (unsigned char c : s) {
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c=='-' || c=='_' || c=='.' || c=='~') {
            o << (char)c;
        } else {
            o << '%' << hex[(c>>4)&0xF] << hex[c&0xF];
        }
    }
    return o.str();
}

static int HexVal(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
    if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
    return -1;
}

static std::string UrlDecode(const std::string& s) {
    std::string o; o.reserve(s.size());
    for (size_t i = 0; i < s.size(); ++i) {
        char c = s[i];
        if (c == '%') {
            if (i + 2 < s.size()) {
                int h1 = HexVal(s[i+1]);
                int h2 = HexVal(s[i+2]);
                if (h1 >= 0 && h2 >= 0) {
                    o.push_back((char)((h1 << 4) | h2));
                    i += 2; continue;
                }
            }
            // malformed, keep as-is
            o.push_back('%');
        } else if (c == '+') {
            o.push_back(' ');
        } else {
            o.push_back(c);
        }
    }
    return o;
}

static bool Base64ToBase64Url(std::string& b64) {
    for (char& c : b64) {
        if (c == '+') c = '-';
        else if (c == '/') c = '_';
    }
    while (!b64.empty() && b64.back() == '=') b64.pop_back();
    return true;
}

static bool Base64UrlEncode(const std::vector<uint8_t>& data, std::string& out) {
    if (data.empty()) { out.clear(); return true; }
    DWORD needed = 0;
    if (!CryptBinaryToStringA(data.data(), (DWORD)data.size(), CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, nullptr, &needed)) return false;
    std::string b64; b64.resize(needed);
    if (!CryptBinaryToStringA(data.data(), (DWORD)data.size(), CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, &b64[0], &needed)) return false;
    if (needed > 0 && b64.back() == '\0') b64.pop_back();
    Base64ToBase64Url(b64);
    out = b64; return true;
}

static bool Sha256(const std::string& in, std::vector<uint8_t>& out32) {
    BCRYPT_ALG_HANDLE hAlg = nullptr; BCRYPT_HASH_HANDLE hHash = nullptr;
    DWORD cbHash = 32, cbData = 0; out32.assign(32, 0);
    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) < 0) return false;
    if (BCryptCreateHash(hAlg, &hHash, nullptr, 0, nullptr, 0, 0) < 0) { BCryptCloseAlgorithmProvider(hAlg, 0); return false; }
    if (BCryptHashData(hHash, (PUCHAR)in.data(), (ULONG)in.size(), 0) < 0) { BCryptDestroyHash(hHash); BCryptCloseAlgorithmProvider(hAlg, 0); return false; }
    if (BCryptFinishHash(hHash, (PUCHAR)out32.data(), cbHash, 0) < 0) { BCryptDestroyHash(hHash); BCryptCloseAlgorithmProvider(hAlg, 0); return false; }
    BCryptDestroyHash(hHash); BCryptCloseAlgorithmProvider(hAlg, 0); return true;
}

static std::string RandomBase64Url(size_t bytes = 32) {
    std::vector<uint8_t> buf(bytes);
    BCryptGenRandom(nullptr, buf.data(), (ULONG)buf.size(), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    std::string out; Base64UrlEncode(buf, out); return out;
}

static std::string CodeChallengeFromVerifier(const std::string& verifier) {
    std::vector<uint8_t> hash; if (!Sha256(verifier, hash)) return std::string();
    std::string out; Base64UrlEncode(hash, out); return out;
}

static std::wstring Utf8ToWide(const std::string& s) {
    if (s.empty()) return L"";
    int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), nullptr, 0);
    std::wstring w; w.resize(n);
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), &w[0], n);
    return w;
}

static std::string WideToUtf8(const std::wstring& w) {
    if (w.empty()) return std::string();
    int n = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), nullptr, 0, nullptr, nullptr);
    std::string s; s.resize(n);
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), &s[0], n, nullptr, nullptr);
    return s;
}

static std::wstring GetEnvW(const wchar_t* name) {
    DWORD needed = GetEnvironmentVariableW(name, nullptr, 0);
    if (needed == 0) return L"";
    std::wstring buf; buf.resize(needed);
    DWORD got = GetEnvironmentVariableW(name, &buf[0], needed);
    if (got == 0) return L"";
    if (!buf.empty() && buf.back() == L'\0') buf.pop_back();
    return buf;
}

static std::wstring GetAppDataPath() {
    PWSTR path = nullptr; std::wstring out;
    if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_RoamingAppData, 0, nullptr, &path))) {
        out = path; CoTaskMemFree(path);
    }
    return out;
}

static void SaveRefreshTokenSecure(const std::wstring& token) {
    std::wstring dir = GetAppDataPath() + L"\\YT247Desktop";
    CreateDirectoryW(dir.c_str(), nullptr);
    std::wstring file = dir + L"\\refresh.bin";
    DATA_BLOB in{}; in.pbData = (BYTE*)token.c_str(); in.cbData = (DWORD)((token.size()+1) * sizeof(wchar_t));
    DATA_BLOB out{};
    if (CryptProtectData(&in, L"YT247Desktop", nullptr, nullptr, nullptr, 0, &out)) {
        HANDLE h = CreateFileW(file.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_HIDDEN, nullptr);
        if (h != INVALID_HANDLE_VALUE) {
            DWORD written=0; WriteFile(h, out.pbData, out.cbData, &written, nullptr); CloseHandle(h);
        }
        LocalFree(out.pbData);
    }
}

static bool RemoveRefreshTokenSecure() {
    std::wstring dir = GetAppDataPath() + L"\\YT247Desktop";
    std::wstring file = dir + L"\\refresh.bin";
    return DeleteFileW(file.c_str()) != 0;
}

static bool LoadRefreshTokenSecure(std::wstring& outToken) {
    outToken.clear();
    std::wstring dir = GetAppDataPath() + L"\\YT247Desktop";
    std::wstring file = dir + L"\\refresh.bin";
    HANDLE h = CreateFileW(file.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    DWORD size = GetFileSize(h, nullptr);
    if (size == INVALID_FILE_SIZE || size == 0) { CloseHandle(h); return false; }
    std::vector<BYTE> enc(size);
    DWORD read=0; if (!ReadFile(h, enc.data(), size, &read, nullptr) || read != size) { CloseHandle(h); return false; }
    CloseHandle(h);
    DATA_BLOB in{}; in.pbData = enc.data(); in.cbData = read;
    DATA_BLOB out{}; LPWSTR desc=nullptr;
    if (!CryptUnprotectData(&in, &desc, nullptr, nullptr, nullptr, 0, &out)) return false;
    if (desc) LocalFree(desc);
    std::wstring token((wchar_t*)out.pbData, out.cbData / sizeof(wchar_t));
    if (!token.empty() && token.back() == L'\0') token.pop_back();
    outToken = token;
    LocalFree(out.pbData);
    return !outToken.empty();
}

static std::string HttpPostForm(const wchar_t* host, INTERNET_PORT port, const wchar_t* path, const std::string& body) {
    std::string resp;
    HINTERNET h = WinHttpOpen(L"YT247Desktop/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!h) return resp;
    HINTERNET c = WinHttpConnect(h, host, port, 0);
    if (!c) { WinHttpCloseHandle(h); return resp; }
    HINTERNET r = WinHttpOpenRequest(c, L"POST", path, nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
    if (!r) { WinHttpCloseHandle(c); WinHttpCloseHandle(h); return resp; }
    std::wstring headers = L"Content-Type: application/x-www-form-urlencoded\r\n";
    BOOL ok = WinHttpSendRequest(r, headers.c_str(), (DWORD)-1, (LPVOID)body.data(), (DWORD)body.size(), (DWORD)body.size(), 0);
    if (ok) ok = WinHttpReceiveResponse(r, nullptr);
    if (ok) {
        for(;;) {
            DWORD avail=0; if (!WinHttpQueryDataAvailable(r, &avail) || avail==0) break;
            std::string chunk; chunk.resize(avail);
            DWORD read=0; if (!WinHttpReadData(r, &chunk[0], avail, &read) || read==0) break;
            chunk.resize(read); resp += chunk;
        }
    }
    WinHttpCloseHandle(r); WinHttpCloseHandle(c); WinHttpCloseHandle(h);
    return resp;
}

static std::string HttpPostJson(const wchar_t* host, INTERNET_PORT port, const std::wstring& pathWithQuery, const std::string& json) {
    std::string resp;
    HINTERNET h = WinHttpOpen(L"YT247Desktop/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!h) return resp;
    HINTERNET c = WinHttpConnect(h, host, port, 0);
    if (!c) { WinHttpCloseHandle(h); return resp; }
    HINTERNET r = WinHttpOpenRequest(c, L"POST", pathWithQuery.c_str(), nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
    if (!r) { WinHttpCloseHandle(c); WinHttpCloseHandle(h); return resp; }
    std::wstring headers = L"Content-Type: application/json\r\n";
    BOOL ok = WinHttpSendRequest(r, headers.c_str(), (DWORD)-1, (LPVOID)json.data(), (DWORD)json.size(), (DWORD)json.size(), 0);
    if (ok) ok = WinHttpReceiveResponse(r, nullptr);
    if (ok) {
        for(;;) {
            DWORD avail=0; if (!WinHttpQueryDataAvailable(r, &avail) || avail==0) break;
            std::string chunk; chunk.resize(avail);
            DWORD read=0; if (!WinHttpReadData(r, &chunk[0], avail, &read) || read==0) break;
            chunk.resize(read); resp += chunk;
        }
    }
    WinHttpCloseHandle(r); WinHttpCloseHandle(c); WinHttpCloseHandle(h);
    return resp;
}

static std::string ExtractJsonString(const std::string& json, const std::string& key) {
    std::string pat = "\"" + key + "\"";
    size_t k = json.find(pat); if (k==std::string::npos) return std::string();
    size_t c = json.find(':', k); if (c==std::string::npos) return std::string();
    size_t q1 = json.find('"', c); if (q1==std::string::npos) return std::string();
    size_t q2 = json.find('"', q1+1); if (q2==std::string::npos) return std::string();
    return json.substr(q1+1, q2-q1-1);
}

static unsigned int ToSecondsOr(const std::string& s, unsigned int fallback) {
    if (s.empty()) return fallback;
    unsigned long v = 0; for (char c : s) { if (c<'0'||c>'9') return fallback; v = v*10 + (c - '0'); if (v > 0xFFFFFFFFUL) return fallback; }
    return (unsigned int)v;
}

static void ScheduleAuthRefresh(HWND hwnd, unsigned int expiresSec) {
    unsigned int ms = ((expiresSec > 120 ? (expiresSec - 60) : 600)) * 1000U;
    SetTimer(hwnd, ID_TIMER_AUTH, ms, nullptr);
}

static std::string FirebaseLookupEmail(const std::wstring& idTokenW) {
    std::wstring path = L"/v1/accounts:lookup?key=" + gFirebaseApiKey;
    std::ostringstream j; j << "{\"idToken\":\"" << UrlEncode(WideToUtf8(idTokenW)) << "\"}";
    std::string resp = HttpPostJson(L"identitytoolkit.googleapis.com", INTERNET_DEFAULT_HTTPS_PORT, path, j.str());
    return ExtractJsonString(resp, "email");
}

static DWORD WINAPI FirebaseRefreshThread(LPVOID param) {
    HWND hwnd = (HWND)param;
    std::wstring tokenW = g_refreshToken;
    if (tokenW.empty()) {
        std::wstring saved;
        if (!LoadRefreshTokenSecure(saved)) return 0;
        tokenW = saved;
    }
    AppendLog(L"Menyegarkan sesi dari refresh token...\r\n");
    std::string body = std::string("grant_type=refresh_token&refresh_token=") + UrlEncode(WideToUtf8(tokenW));
    std::wstring path = L"/v1/token?key=" + gFirebaseApiKey;
    std::string resp = HttpPostForm(L"securetoken.googleapis.com", INTERNET_DEFAULT_HTTPS_PORT, path.c_str(), body);
    std::string idToken = ExtractJsonString(resp, "id_token");
    std::string refresh = ExtractJsonString(resp, "refresh_token");
    unsigned int expSec = ToSecondsOr(ExtractJsonString(resp, "expires_in"), 3600);
    if (idToken.empty() || refresh.empty()) { AppendLog(L"Gagal refresh sesi.\r\n"); return 0; }
    g_idToken = Utf8ToWide(idToken);
    g_refreshToken = Utf8ToWide(refresh);
    g_isSignedIn = true;
    SaveRefreshTokenSecure(g_refreshToken);

    // Lookup email if not known
    if (g_signedInEmail.empty()) {
        std::string em = FirebaseLookupEmail(g_idToken);
        g_signedInEmail = Utf8ToWide(em);
    }
    if (g_hLblEmail) SetWindowTextW(g_hLblEmail, g_signedInEmail.c_str());
    if (g_hBtnGoogle) ShowWindow(g_hBtnGoogle, SW_HIDE);
    if (g_hBtnSignOut) { ShowWindow(g_hBtnSignOut, SW_SHOW); EnableWindow(g_hBtnSignOut, TRUE); }
    if (g_hBtnStart && !g_isStreaming) EnableWindow(g_hBtnStart, TRUE);

    // Update title
    if (g_hMainWnd) {
        if (g_baseTitle.empty()) {
            int len = GetWindowTextLengthW(g_hMainWnd);
            if (len > 0) { std::vector<wchar_t> buf(len+1); GetWindowTextW(g_hMainWnd, buf.data(), len+1); g_baseTitle.assign(buf.data()); }
        }
        if (!g_signedInEmail.empty()) {
            std::wstring cur = g_baseTitle.empty() ? L"YT247Desktop" : g_baseTitle;
            std::wstring newTitle = cur + L" + " + g_signedInEmail;
            SetWindowTextW(g_hMainWnd, newTitle.c_str());
        }
    }

    SetWindowTextW(g_hLblStatus, L"Signed in (restored).");
    AppendLog(L"Sesi dipulihkan.\r\n");
    if (hwnd) ScheduleAuthRefresh(hwnd, expSec);
    return 0;
}

static void DoSignOut(HWND hwnd) {
    g_isSignedIn = false; g_idToken.clear(); g_refreshToken.clear(); g_signedInEmail.clear();
    KillTimer(hwnd, ID_TIMER_AUTH);
    RemoveRefreshTokenSecure();
    if (g_hLblStatus) SetWindowTextW(g_hLblStatus, L"Signed out.");
    if (g_hLblEmail) SetWindowTextW(g_hLblEmail, L"");
    if (g_hBtnStart) EnableWindow(g_hBtnStart, FALSE);
    if (g_hBtnSignOut) ShowWindow(g_hBtnSignOut, SW_HIDE);
    if (g_hBtnGoogle) ShowWindow(g_hBtnGoogle, SW_SHOW);
    if (g_hMainWnd) {
        if (!g_baseTitle.empty()) SetWindowTextW(g_hMainWnd, g_baseTitle.c_str());
    }
}

struct OAuthResult { std::string code; std::string state; };

static SOCKET CreateLoopbackListener(unsigned short& outPort) {
    SOCKET s = INVALID_SOCKET;
    WSADATA wsa; if (WSAStartup(MAKEWORD(2,2), &wsa) != 0) return INVALID_SOCKET;
    s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) return INVALID_SOCKET;
    sockaddr_in addr{}; addr.sin_family = AF_INET; addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK); addr.sin_port = 0;
    if (bind(s, (sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) { closesocket(s); WSACleanup(); return INVALID_SOCKET; }
    if (listen(s, 1) == SOCKET_ERROR) { closesocket(s); WSACleanup(); return INVALID_SOCKET; }
    int len=sizeof(addr); if (getsockname(s, (sockaddr*)&addr, &len)==0) { outPort = ntohs(addr.sin_port); }
    return s;
}

static OAuthResult WaitForOAuthCallback(SOCKET listener) {
    OAuthResult res; res.code.clear(); res.state.clear();
    sockaddr_in cli{}; int clen=sizeof(cli);
    SOCKET c = accept(listener, (sockaddr*)&cli, &clen);
    if (c == INVALID_SOCKET) return res;
    char buf[4096]; int r = recv(c, buf, sizeof(buf)-1, 0); if (r<0) { closesocket(c); return res; }
    buf[r] = 0;
    std::string req(buf);
    // Parse request line
    size_t sp1 = req.find(' '); if (sp1!=std::string::npos) {
        size_t sp2 = req.find(' ', sp1+1);
        if (sp2!=std::string::npos) {
            std::string path = req.substr(sp1+1, sp2-sp1-1);
            // Expect /callback?code=...&state=...
            size_t q = path.find('?');
            std::string qp = (q==std::string::npos) ? std::string() : path.substr(q+1);
            auto getq = [&](const char* key){
                std::string k = std::string(key) + "=";
                size_t p = qp.find(k);
                if (p==std::string::npos) return std::string();
                size_t e = qp.find('&', p);
                std::string v = qp.substr(p + k.size(), (e==std::string::npos)?std::string::npos:(e-p-k.size()));
                return v;
            };
            res.code = UrlDecode(getq("code"));
            res.state = UrlDecode(getq("state"));
        }
    }
    const char* resp = "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=UTF-8\r\nConnection: close\r\n\r\n<!doctype html><html><body><p>Authentication received. You can close this window.</p></body></html>";
    send(c, resp, (int)strlen(resp), 0);
    closesocket(c);
    return res;
}

static DWORD WINAPI GoogleSignInThread(LPVOID param) {
    HWND hwnd = (HWND)param;
    AppendLog(L"Memulai Google Sign-In...\r\n");
    unsigned short port=0; SOCKET listener = CreateLoopbackListener(port);
    if (listener == INVALID_SOCKET || port==0) { AppendLog(L"Gagal membuat listener lokal.\r\n"); return 0; }

    std::string state = RandomBase64Url(16);
    std::string verifier = RandomBase64Url(32);
    std::string challenge = CodeChallengeFromVerifier(verifier);

    std::ostringstream authUrl;
    authUrl << "https://accounts.google.com/o/oauth2/v2/auth?"
            << "client_id=" << UrlEncode(WideToUtf8(gGoogleClientId))
            << "&redirect_uri=" << UrlEncode("http://127.0.0.1:" + std::to_string(port) + "/callback")
            << "&response_type=code"
            << "&scope=" << UrlEncode("openid email profile")
            << "&code_challenge=" << UrlEncode(challenge)
            << "&code_challenge_method=S256"
            << "&access_type=offline&prompt=consent"
            << "&state=" << UrlEncode(state);

    std::wstring wurl = Utf8ToWide(authUrl.str());
    ShellExecuteW(nullptr, L"open", wurl.c_str(), nullptr, nullptr, SW_SHOWNORMAL);

    OAuthResult cb = WaitForOAuthCallback(listener);
    closesocket(listener); WSACleanup();
    if (cb.code.empty() || cb.state != state) { AppendLog(L"Login dibatalkan atau state tidak cocok.\r\n"); return 0; }

    // Exchange code for tokens
    std::ostringstream body;
    body << "grant_type=authorization_code"
         << "&code=" << UrlEncode(cb.code)
         << "&client_id=" << UrlEncode(WideToUtf8(gGoogleClientId))
         << "&redirect_uri=" << UrlEncode("http://127.0.0.1:" + std::to_string(port) + "/callback")
         << "&code_verifier=" << UrlEncode(verifier);
    // Include client_secret if provided (for clients that require it)
    if (!gGoogleClientSecret.empty()) {
        body << "&client_secret=" << UrlEncode(WideToUtf8(gGoogleClientSecret));
    }

    std::string tokResp = HttpPostForm(L"oauth2.googleapis.com", INTERNET_DEFAULT_HTTPS_PORT, L"/token", body.str());
    std::string id_token = ExtractJsonString(tokResp, "id_token");
    if (id_token.empty()) {
        std::string err = ExtractJsonString(tokResp, "error");
        std::string desc = ExtractJsonString(tokResp, "error_description");
        std::wstring w = L"Gagal tukar code ke id_token.";
        if (!err.empty()) { w += L" ("; w += Utf8ToWide(err); if (!desc.empty()) { w += L": "; w += Utf8ToWide(desc); } w += L")"; }
        w += L"\r\n";
        AppendLog(w);
        return 0;
    }

    // Sign in to Firebase
    std::string postBody = "id_token=" + UrlEncode(id_token) + "&providerId=google.com";
    std::ostringstream json;
    json << "{\"postBody\":\"" << postBody << "\",\"requestUri\":\"http://localhost\",\"returnSecureToken\":true,\"returnIdpCredential\":true}";
    std::wstring path = L"/v1/accounts:signInWithIdp?key=" + gFirebaseApiKey;
    std::string fbResp = HttpPostJson(L"identitytoolkit.googleapis.com", INTERNET_DEFAULT_HTTPS_PORT, path, json.str());
    std::string idTokenFb = ExtractJsonString(fbResp, "idToken");
    std::string refreshFb = ExtractJsonString(fbResp, "refreshToken");
    std::string emailFb = ExtractJsonString(fbResp, "email");
    unsigned int expSec = ToSecondsOr(ExtractJsonString(fbResp, "expiresIn"), 3600);
    if (idTokenFb.empty() || refreshFb.empty()) { AppendLog(L"Gagal login ke Firebase.\r\n"); return 0; }

    g_idToken = Utf8ToWide(idTokenFb);
    g_refreshToken = Utf8ToWide(refreshFb);
    g_isSignedIn = true;
    SaveRefreshTokenSecure(g_refreshToken);

    std::wstring status = L"Signed in";
    std::wstring emailW = Utf8ToWide(emailFb);
    if (!emailFb.empty()) { status += L" as "; status += emailW; }
    status += L".";
    SetWindowTextW(g_hLblStatus, status.c_str());
    AppendLog(L"Sukses Sign-In dengan Google.\r\n");

    // Update main window title to include email
    if (!emailW.empty() && g_hMainWnd) {
        int len = GetWindowTextLengthW(g_hMainWnd);
        std::wstring cur;
        if (len > 0) {
            std::vector<wchar_t> buf(len + 1);
            GetWindowTextW(g_hMainWnd, buf.data(), len + 1);
            cur.assign(buf.data());
        }
        if (g_baseTitle.empty()) g_baseTitle = cur;
        if (cur.empty()) cur = g_baseTitle.empty() ? L"YT247Desktop" : g_baseTitle;
        std::wstring newTitle = cur + L" + " + emailW;
        SetWindowTextW(g_hMainWnd, newTitle.c_str());
    }
    g_signedInEmail = emailW;
    if (g_hLblEmail) SetWindowTextW(g_hLblEmail, emailW.c_str());
    if (g_hBtnGoogle) ShowWindow(g_hBtnGoogle, SW_HIDE);
    if (g_hBtnSignOut) { ShowWindow(g_hBtnSignOut, SW_SHOW); EnableWindow(g_hBtnSignOut, TRUE); }
    if (g_hBtnStart && !g_isStreaming) EnableWindow(g_hBtnStart, TRUE);
    if (hwnd) ScheduleAuthRefresh(hwnd, expSec);
    return 0;
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
    if (g_hInfoVOr)   SetWindowTextW(g_hInfoVOr,   L"");
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
            // Orientation
            const wchar_t* orient = (h > w) ? L"Vertical" : (w > h) ? L"Horizontal" : L"Square";
            SetWindowTextW(g_hInfoVOr, orient);
        } else {
            SetWindowTextW(g_hInfoVRes, L"");
            SetWindowTextW(g_hInfoVOr, L"");
        }
        store->Release();
    } else {
        SetWindowTextW(g_hInfoVDur, L"");
        SetWindowTextW(g_hInfoVBr, L"");
        SetWindowTextW(g_hInfoVRes, L"");
        SetWindowTextW(g_hInfoVOr, L"");
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
            INPUTS_X, M, WND_W - INPUTS_X - (2*BTN_W + 8) - M, H, hwnd, (HMENU)ID_EDIT_VIDEO, nullptr, nullptr);

        g_hBtnBrowse = CreateWindowW(L"BUTTON", L"Browse...", WS_CHILD | WS_VISIBLE | WS_TABSTOP,
            WND_W - (2*BTN_W + 8 + M), M, BTN_W, H, hwnd, (HMENU)ID_BTN_BROWSE, nullptr, nullptr);

        // Sign In with Google button (top-right corner)
        g_hBtnGoogle = CreateWindowW(L"BUTTON", L"Sign In", WS_CHILD | WS_VISIBLE | WS_TABSTOP,
            WND_W - (BTN_W + M), M, BTN_W, H, hwnd, (HMENU)ID_BTN_GOOGLE, nullptr, nullptr);
        // Sign Out button (same position, initially hidden)
        g_hBtnSignOut = CreateWindowW(L"BUTTON", L"Sign Out", WS_CHILD | WS_TABSTOP,
            WND_W - (BTN_W + M), M, BTN_W, H, hwnd, (HMENU)ID_BTN_SIGNOUT, nullptr, nullptr);

        const int validY = M + H + 8;
        g_hLblValid = CreateWindowW(L"STATIC", L"", WS_CHILD | WS_VISIBLE,
            INPUTS_X, validY, 200, H, hwnd, (HMENU)ID_LBL_VALID, nullptr, nullptr);
        // Email label on the right side of the same row
        const int EMAIL_W = 220;
        g_hLblEmail = CreateWindowW(L"STATIC", L"", WS_CHILD | WS_VISIBLE | SS_RIGHT,
            WND_W - (BTN_W + M) - 8 - EMAIL_W, validY, EMAIL_W, H, hwnd, (HMENU)ID_LBL_EMAIL, nullptr, nullptr);

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
        // Orientation
        g_hInfoLOr = CreateWindowW(L"STATIC", L"Orientasi", WS_CHILD | WS_VISIBLE,
            M, infoRowY0 + 4*H, INFO_LW, H, hwnd, (HMENU)ID_INFO_L_ORI, nullptr, nullptr);
        g_hInfoVOr = CreateWindowW(L"STATIC", L"", WS_CHILD | WS_VISIBLE,
            infoValX, infoRowY0 + 4*H, infoValW, H, hwnd, (HMENU)ID_INFO_V_ORI, nullptr, nullptr);

        // Row B: Stream Key (below video info section)
        const int row2Y = infoRowY0 + 5*H + 8; // after 5 rows of info
        CreateWindowW(L"STATIC", L"Stream Key", WS_CHILD | WS_VISIBLE,
            M, row2Y+4, LBLW, H, hwnd, nullptr, nullptr, nullptr);

        g_hEditKey = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL,
            INPUTS_X, row2Y, WND_W - INPUTS_X - (2*BTN_W + 8) - M, H, hwnd, (HMENU)ID_EDIT_KEY, nullptr, nullptr);

        // Place Start to the left of Stop (Stop is on the right)
        g_hBtnStart = CreateWindowW(L"BUTTON", L"Start Stream", WS_CHILD | WS_VISIBLE | WS_TABSTOP,
            WND_W - (2*BTN_W + 8 + M), row2Y, BTN_W, H, hwnd, (HMENU)ID_BTN_START, nullptr, nullptr);
        EnableWindow(g_hBtnStart, FALSE);

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
                         g_hInfoLOr, g_hInfoVOr,
                         g_hEditKey, g_hBtnStart, g_hBtnStop, g_hLblArgHdr, g_hEditArgs, g_hBtnCopyArgs,
                         g_hLblStatus, g_hEditLog, g_hBtnClearLog, g_hBtnGoogle, g_hBtnSignOut, g_hLblEmail };
        for (HWND c : ctrls) if (c) SendMessageW(c, WM_SETFONT, (WPARAM)g_hFont, TRUE);

        if (!VerifyFfmpegOrDie(hwnd)) {
            PostQuitMessage(0);
            return -1;
        }

        // Compute total content height and initialize scrollbar
        g_contentHeight = clearY + H + M;
        RecalcScrollBar(hwnd);

        g_hMainWnd = hwnd;
        // Capture base title
        {
            int len = GetWindowTextLengthW(hwnd);
            if (len > 0) { std::vector<wchar_t> t(len+1); GetWindowTextW(hwnd, t.data(), len+1); g_baseTitle.assign(t.data()); }
        }
        // Try restore session via refresh token in background
        {
            HANDLE h = CreateThread(nullptr, 0, FirebaseRefreshThread, hwnd, 0, nullptr);
            if (h) CloseHandle(h);
        }
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
        } else if (id == ID_BTN_GOOGLE && code == BN_CLICKED) {
            if (!g_isSignedIn) {
                EnableWindow((HWND)lParam, FALSE);
                HANDLE h = CreateThread(nullptr, 0, GoogleSignInThread, hwnd, 0, nullptr);
                if (h) CloseHandle(h);
                EnableWindow((HWND)lParam, TRUE);
            }
        } else if (id == ID_BTN_SIGNOUT && code == BN_CLICKED) {
            DoSignOut(hwnd);
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
        else if (wParam == ID_TIMER_AUTH) {
            // Trigger background refresh; the thread will reschedule
            HANDLE h = CreateThread(nullptr, 0, FirebaseRefreshThread, hwnd, 0, nullptr);
            if (h) CloseHandle(h);
            KillTimer(hwnd, ID_TIMER_AUTH);
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
        KillTimer(hwnd, ID_TIMER_AUTH);
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
    // Load secrets from environment variables
    gFirebaseApiKey = GetEnvW(L"YT247_FIREBASE_API_KEY");
    gGoogleClientId = GetEnvW(L"YT247_GOOGLE_CLIENT_ID");
    gGoogleClientSecret = GetEnvW(L"YT247_GOOGLE_CLIENT_SECRET");
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
