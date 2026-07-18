# Smoke test manual de la app en Windows tras instalar el .exe (NSIS).
# No automatiza la UI: comprueba las piezas que solo dependen del SO —
# instalación, WebView2, arranque, y el backend Npcap de capa 2.
#
# Uso:  powershell -ExecutionPolicy Bypass -File smoke-windows.ps1
#
#Requires -Version 5
$ErrorActionPreference = "Stop"
$ok = 0; $warn = 0; $fail = 0
function Pass($m) { Write-Host "  [OK]   $m" -ForegroundColor Green; $script:ok++ }
function Warn($m) { Write-Host "  [WARN] $m" -ForegroundColor Yellow; $script:warn++ }
function Fail($m) { Write-Host "  [FAIL] $m" -ForegroundColor Red; $script:fail++ }

Write-Host "`n== Smoke test iec61850-tauri (Windows) ==`n"

# 1. Binario instalado
$exe = Get-ChildItem "$env:LOCALAPPDATA\Programs", "$env:ProgramFiles" -Recurse `
    -Filter "iec61850-tauri.exe" -ErrorAction SilentlyContinue | Select-Object -First 1
if ($exe) { Pass "binario instalado: $($exe.FullName)" }
else { Fail "no se encontró iec61850-tauri.exe (instala el .exe NSIS primero)" }

# 2. WebView2 (runtime de la UI)
$wv = Get-ItemProperty "HKLM:\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\*" `
    -ErrorAction SilentlyContinue | Where-Object { $_.pv } | Select-Object -First 1
if ($wv) { Pass "WebView2 runtime presente (pv $($wv.pv))" }
else { Warn "WebView2 no detectado; el instalador debería ofrecerlo al arrancar" }

# 3. Npcap (capa 2: GOOSE/SV/PCAP)
if (Test-Path "$env:SystemRoot\System32\Npcap\wpcap.dll") {
    Pass "Npcap instalado (capa 2 disponible)"
} elseif (Test-Path "$env:SystemRoot\System32\wpcap.dll") {
    Pass "wpcap.dll en System32 (WinPcap/Npcap modo compatible)"
} else {
    Warn "Npcap no instalado: MMS/TCP funciona; GOOSE/SV/PCAP no hasta instalarlo (https://npcap.com)"
}

# 4. Arranque efímero (abre y cierra la ventana)
if ($exe) {
    try {
        $p = Start-Process $exe.FullName -PassThru
        Start-Sleep 6
        if (-not $p.HasExited) {
            Pass "la app arranca y se mantiene viva"
            Stop-Process -Id $p.Id -Force
        } else {
            Fail "la app se cerró sola (código $($p.ExitCode))"
        }
    } catch { Fail "no se pudo arrancar: $_" }
}

Write-Host "`n== Resultado: $ok OK, $warn avisos, $fail fallos ==`n"
Write-Host "Prueba manual recomendada tras esto:"
Write-Host "  1. Entorno de pruebas (matraz) -> Iniciar IED en vivo (127.0.0.1:10102)"
Write-Host "  2. Conectar -> explorar arbol -> pestana Control -> arrastrar un DO -> Operar"
Write-Host "  3. Con Npcap: pestana GOOSE/SV -> elegir interfaz -> Publicar demo + Iniciar`n"
if ($fail -gt 0) { exit 1 }
