/*
    NEXUS ANTIVIRUS - reglas YARA incluidas.
    Estas reglas detectan indicadores concretos. No sustituyen a ClamAV ni a un motor
    de firmas completo. Las coincidencias se presentan como sospecha salvo que la
    metadata indique "verdict = malware".
*/

rule NEXUS_EICAR_Test_File
{
    meta:
        name = "EICAR-Test-File"
        severity = "test"
        verdict = "malware"
        description = "Archivo de prueba estandar EICAR para verificar el motor."
    strings:
        $e1 = "X5O!P%@AP[4"
        $e2 = "PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        filesize < 1KB and all of them
}

rule NEXUS_Ransomware_Shadow_Deletion
{
    meta:
        name = "Suspicious.ShadowCopyDeletion"
        severity = "high"
        verdict = "suspicious"
        description = "Comandos usados por ransomware para destruir copias de seguridad."
    strings:
        $a = "vssadmin delete shadows" nocase
        $b = "wmic shadowcopy delete" nocase
        $c = "wbadmin delete catalog" nocase
        $d = "bcdedit /set {default} recoveryenabled no" nocase
    condition:
        filesize < 20MB and any of them
}

rule NEXUS_PowerShell_Download_Execution
{
    meta:
        name = "Suspicious.PowerShellDownloadExecution"
        severity = "high"
        verdict = "suspicious"
        description = "Descarga y ejecucion de contenido remoto mediante PowerShell."
    strings:
        $a = "DownloadString" nocase
        $b = "DownloadData" nocase
        $c = "Invoke-Expression" nocase
        $d = "FromBase64String" nocase
        $e = "-EncodedCommand" nocase
    condition:
        filesize < 10MB and 2 of them
}

rule NEXUS_Credential_Theft_Tooling
{
    meta:
        name = "Suspicious.CredentialTheft"
        severity = "critical"
        verdict = "suspicious"
        description = "Cadenas asociadas a robo de credenciales y volcado de LSASS."
    strings:
        $a = "sekurlsa::logonpasswords" nocase
        $b = "mimikatz" nocase
        $c = "procdump" nocase
        $d = "lsass.exe" nocase
        $e = "MiniDumpWriteDump" nocase
    condition:
        filesize < 50MB and 2 of them
}

rule NEXUS_Reverse_Shell
{
    meta:
        name = "Suspicious.ReverseShell"
        severity = "high"
        verdict = "suspicious"
        description = "Patrones de shell inversa o conexion remota interactiva."
    strings:
        $a = "bash -i >& /dev/tcp/" nocase
        $b = "nc -e /bin/sh" nocase
        $c = "ncat -e" nocase
        $d = "New-Object System.Net.Sockets.TCPClient" nocase
        $e = "fsockopen" nocase
    condition:
        filesize < 10MB and any of them
}

rule NEXUS_Office_Macro_AutoExec
{
    meta:
        name = "Suspicious.OfficeMacro"
        severity = "high"
        verdict = "suspicious"
        description = "Documento con macros y descarga/ejecucion de contenido."
    strings:
        $a = "AutoOpen" nocase
        $b = "Document_Open" nocase
        $c = "Workbook_Open" nocase
        $d = "URLDownloadToFile" nocase
        $e = "CreateObject" nocase
        $f = "Shell(" nocase
    condition:
        filesize < 20MB and 1 of ($a, $b, $c) and any of ($d, $e, $f)
}

rule NEXUS_LOLBin_Remote_Execution
{
    meta:
        name = "Suspicious.LOLBinRemoteExecution"
        severity = "high"
        verdict = "suspicious"
        description = "Uso de binarios del sistema para descargar o ejecutar contenido remoto."
    strings:
        $a = "mshta http" nocase
        $b = "regsvr32 /s /i:http" nocase
        $c = "rundll32 javascript" nocase
        $d = "certutil -urlcache" nocase
        $e = "bitsadmin /transfer" nocase
    condition:
        filesize < 10MB and any of them
}

rule NEXUS_Trojan_RemoteAccess
{
    meta:
        name = "Trojan.RemoteAccess"
        severity = "critical"
        verdict = "malware"
        description = "Indicadores de troyano de acceso remoto (RAT) o puerta trasera."
    strings:
        $a = "RemoteDesktop" nocase
        $b = "ReverseShell" nocase
        $c = "ShellExecute" nocase
        $d = "keylogger" nocase
        $e = "screenshot" nocase
        $f = "webcam" nocase
        $g = "clipboard" nocase
        $h = "FileZilla" nocase
        $i = "njRAT" nocase
        $j = "DarkComet" nocase
        $k = "AsyncRAT" nocase
        $l = "Quasar" nocase
        $m = "Remcos" nocase
    condition:
        filesize < 5MB and 3 of them
}

rule NEXUS_Backdoor_Persistence
{
    meta:
        name = "Backdoor.Persistence"
        severity = "critical"
        verdict = "malware"
        description = "Puerta trasera con persistencia y comunicacion remota."
    strings:
        $a = "cmd.exe /c" nocase
        $b = "powershell -w hidden" nocase
        $c = "WScript.Shell" nocase
        $d = "CreateObject" nocase
        $e = "tcpclient" nocase
        $f = "socket.connect" nocase
        $g = "base64" nocase
        $h = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" nocase
    condition:
        filesize < 10MB and 4 of them
}

rule NEXUS_HackingTool_Metasploit
{
    meta:
        name = "HackingTool.Metasploit"
        severity = "critical"
        verdict = "malware"
        description = "Herramientas o payloads de Metasploit Framework."
    strings:
        $a = "meterpreter" nocase
        $b = "reverse_tcp" nocase
        $c = "reverse_https" nocase
        $d = "msfvenom" nocase
        $e = "msfpayload" nocase
        $f = "LHOST" nocase
        $g = "LPORT" nocase
        $h = "windows/meterpreter" nocase
    condition:
        filesize < 20MB and 2 of them
}

rule NEXUS_HackingTool_CobaltStrike
{
    meta:
        name = "HackingTool.CobaltStrike"
        severity = "critical"
        verdict = "malware"
        description = "Indicadores de beacon de Cobalt Strike."
    strings:
        $a = "cobaltstrike" nocase
        $b = "beacon" nocase
        $c = "sleep_mask" nocase
        $d = "ReflectiveLoader" nocase
        $e = "rundll32" nocase
        $f = "sleeptime" nocase
    condition:
        filesize < 20MB and 3 of them
}

rule NEXUS_Keylogger
{
    meta:
        name = "Spyware.Keylogger"
        severity = "high"
        verdict = "malware"
        description = "Indicadores de keylogger o captura de teclado."
    strings:
        $a = "GetAsyncKeyState" nocase
        $b = "SetWindowsHookEx" nocase
        $c = "GetKeyboardState" nocase
        $d = "keylogger" nocase
        $e = "logkeys" nocase
        $f = "keystroke" nocase
    condition:
        filesize < 10MB and 2 of them
}

rule NEXUS_Trojan_Downloader
{
    meta:
        name = "Trojan.Downloader"
        severity = "high"
        verdict = "malware"
        description = "Troyano descargador de cargas utiles adicionales."
    strings:
        $a = "URLDownloadToFile" nocase
        $b = "WinHttpOpen" nocase
        $c = "InternetOpenUrl" nocase
        $d = "ShellExecute" nocase
        $e = "CreateProcess" nocase
        $f = "%TEMP%" nocase
        $g = "cmd.exe" nocase
    condition:
        filesize < 10MB and 4 of them
}
