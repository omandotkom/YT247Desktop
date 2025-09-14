$ErrorActionPreference = 'Stop'
$p = 'src/main.cpp'
if (Test-Path $p) {
  $t = Get-Content $p -Raw
  $t = $t -replace 'static const wchar_t\*\s*kGoogleClientSecret\s*=\s*L"[^"]*";', 'static const wchar_t* kGoogleClientSecret = L"";'
  $t = $t -replace 'static const wchar_t\*\s*kGoogleClientId\s*=\s*L"[^"]*";', 'static const wchar_t* kGoogleClientId = L"example.apps.googleusercontent.com";'
  $t = $t -replace 'static const wchar_t\*\s*kFirebaseApiKey\s*=\s*L"[^"]*";', 'static const wchar_t* kFirebaseApiKey = L"";'
  Set-Content -NoNewline -Path $p -Value $t
}
