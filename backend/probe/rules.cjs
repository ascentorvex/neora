'use strict';
// Static indicators scanned inside the detonation container (source files AND strings inside binaries).
// Severity/titles live in ../verdict.mjs (RULE_META). Rules marked `combo` are weak signals that only count in
// combination (see classify() in ../verdict.mjs), so they have no metadata of their own.
module.exports = [
  // destructive / system-level
  { id: 'mbr_overwrite', re: /PhysicalDrive\d|\\\\\.\\(?:PhysicalDrive|Harddisk)\d/i },
  { id: 'disk_wipe', re: /\bdd\s+if=\/dev\/(?:zero|u?random)\s+of=\/dev\/(?:sd|nvme|hd|vd)|\bmkfs(?:\.\w+)?\s+\/dev\/|\bshred\s+[^\n]{0,30}\/dev\// },
  { id: 'ransom_cmds', re: /vssadmin\s+delete\s+shadows|wmic\s+shadowcopy\s+delete|bcdedit[^\n]{0,60}recoveryenabled\s+no|\bcipher\s+\/w|wbadmin\s+delete/i },
  { id: 'destructive_rm', re: /\brm\s+-[rf]{1,3}\s+(?:--no-preserve-root\s+)?(?:\/\*?|~\/?\*?|\$HOME\/?\*?)(?:\s|$|;|&)/ },
  { id: 'fork_bomb', re: /:\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:/ },
  // remote access / download-and-run
  { id: 'reverse_shell', re: /\/dev\/tcp\/|bash\s+-i\s*>&|\bnc\s+(?:-e|-c)\b|mkfifo\s+\/tmp\// },
  { id: 'py_socket_shell', re: /socket\.socket\([^)]*\)[\s\S]{0,300}(?:dup2|pty\.spawn|subprocess|\/bin\/(?:ba)?sh)/ },
  { id: 'curl_pipe_sh', re: /\b(?:curl|wget)\b[^\n|;]{0,200}\|\s*(?:ba|z)?sh\b/ },
  { id: 'ps_download_exec', re: /\bIEX\s*[($]|\bIEX\s+(?:New-Object|iwr|irm)\b|Invoke-Expression|DownloadString|DownloadFile|Net\.WebClient|Start-BitsTransfer/i },
  { id: 'ps_encoded', re: /powershell[^\n]{0,80}-(?:enc|encodedcommand)\b/i },
  { id: 'win_lolbin', re: /certutil[^\n]{0,40}-urlcache|bitsadmin[^\n]{0,30}\/transfer|mshta\s+https?:|regsvr32[^\n]{0,40}\/i:http|rundll32[^\n]{0,60}javascript:/i },
  { id: 'php_webshell', re: /\beval\s*\(\s*(?:base64_decode|gzinflate|str_rot13)|\b(?:shell_exec|passthru|proc_open|system)\s*\(\s*\$_(?:GET|POST|REQUEST)/ },
  // code hiding
  { id: 'eval_b64', re: /\b(?:eval|Function)\s*\(\s*(?:atob|Buffer\.from)\s*\(/ },
  { id: 'py_exec_b64', re: /\b(?:exec|eval)\s*\(\s*(?:base64\.b64decode|zlib\.decompress|marshal\.loads|codecs\.decode|bytes\.fromhex)/ },
  { id: 'obfuscated', re: /(?:\\x[0-9a-f]{2}){20,}|\b_0x[0-9a-f]{4,6}\b/, textOnly: true },
  { id: 'encoded_blob', re: /['"][A-Za-z0-9+\/]{400,}={0,2}['"]/, textOnly: true },
  // theft / spying
  { id: 'browser_wallet', re: /Login Data|Cookies\.sqlite|logins\.json|\bkey[34]\.db|metamask|exodus|wallet\.dat|\.solana\/id\.json|\.ethereum\/keystore/i },
  { id: 'cred_paths', re: /\.ssh\/(?:id_rsa|authorized_keys)|\.aws\/credentials|\.git-credentials|\.docker\/config\.json|\.kube\/config|\/etc\/shadow/ },
  { id: 'webhook_exfil', re: /discord(?:app)?\.com\/api\/webhooks|api\.telegram\.org\/bot|hooks\.slack\.com\/services|pastebin\.com\/raw|transfer\.sh|ngrok\.io|webhook\.site|requestbin|oast\.(?:fun|pro|live)|interact\.sh|burpcollaborator/i },
  { id: 'keylogger', re: /SetWindowsHookEx|GetAsyncKeyState|GetKeyboardState|pynput\.keyboard|keyboard\.on_press/ },
  { id: 'proc_injection', re: /VirtualAllocEx|WriteProcessMemory|CreateRemoteThread|NtUnmapViewOfSection|SetThreadContext/ },
  { id: 'env_harvest', re: /JSON\.stringify\(\s*process\.env\s*\)|Object\.(?:keys|entries|values)\(\s*process\.env\s*\)|dict\(\s*os\.environ\s*\)/ },
  { id: 'raw_ip_url', re: /https?:\/\/\d{1,3}(?:\.\d{1,3}){3}/ },
  // persistence / defense evasion
  { id: 'win_persistence', re: /schtasks\s+\/create|CurrentVersion\\Run\b|reg\s+add[^\n]{0,60}\\Run\b|\\Start Menu\\Programs\\Startup/i },
  { id: 'unix_persistence', re: /crontab\s+-|\/etc\/cron\.|systemctl\s+enable|>>\s*~?\/?[\w.\/]*authorized_keys|LaunchAgents/ },
  { id: 'defender_off', re: /Set-MpPreference[^\n]{0,60}Disable|DisableRealtimeMonitoring|netsh\s+advfirewall\s+set[^\n]{0,40}off/i },
  { id: 'anti_analysis', re: /VBoxService|VMwareService|vmtoolsd|IsDebuggerPresent|CheckRemoteDebuggerPresent|SbieDll|cuckoo|sandboxie/i },
  { id: 'time_bomb', re: /\b(?:setTimeout|time\.sleep|Thread\.sleep|sleep)\s*\(\s*(?:[3-9]\d{5,}|\d{7,})/, textOnly: true },
  { id: 'miner', re: /stratum\+tcp|xmrig|coinhive|cryptonight|minerd\b/i },
  // low-signal (context only)
  { id: 'py_subprocess', re: /\bsubprocess\.(?:Popen|run|call|check_output)|\bos\.system\s*\(|\bos\.popen\s*\(/, textOnly: true },
  { id: 'child_process', re: /require\(\s*['"](?:node:)?child_process['"]\s*\)/, textOnly: true },
  { id: 'eval_generic', re: /\beval\s*\(/, textOnly: true },
  // ---- binaries, documents, scripts of other platforms (matched against strings extracted from the file) ----
  { id: 'mimikatz', re: /mimikatz|sekurlsa::|kerberos::(?:ptt|golden)|lsadump::/i },
  { id: 'lsass_dump', re: /MiniDumpWriteDump|procdump[^\n]{0,40}lsass|comsvcs\.dll[^\n]{0,30}MiniDump/i },
  { id: 'amsi_bypass', re: /AmsiScanBuffer|amsiInitFailed|AmsiUtils/ },
  { id: 'uac_bypass', re: /fodhelper\.exe|eventvwr\.exe[^\n]{0,60}mscfile|ms-settings\\shell\\open|ComputerDefaults\.exe/i },
  { id: 'ransom_note', re: /your (?:files|data|documents) (?:have been|are|were) (?:encrypted|locked)|decrypt(?:ion)?\s+(?:key|tool)|send\s+[\d.]+\s*(?:btc|bitcoin|xmr)|\bbitcoin\s+address\b|ransomware/i },
  { id: 'tor_c2', re: /\b[a-z2-7]{16,56}\.onion\b/i },
  { id: 'win_dl_api', re: /URLDownloadToFile[AW]?|InternetOpenUrl[AW]?|WinHttpOpenRequest|InternetReadFile|HttpSendRequest[AW]?/, combo: true },
  { id: 'win_exec_api', re: /\bWinExec\b|ShellExecute(?:Ex)?[AW]?|CreateProcess(?:A|W|AsUser[AW])\b/, combo: true },
  { id: 'api_virtualalloc', re: /VirtualAlloc(?:Ex)?\b|NtAllocateVirtualMemory/, combo: true },
  { id: 'api_thread_exec', re: /NtCreateThreadEx|QueueUserAPC|EnumSystemLocales[AW]?|VirtualProtect(?:Ex)?\b/, combo: true },
  { id: 'api_crypto', re: /CryptEncrypt|BCryptEncrypt|CryptAcquireContext[AW]?|CryptGenKey/, combo: true },
  { id: 'api_file_enum', re: /FindNextFile[AW]?/, combo: true },
  { id: 'wscript_shell', re: /CreateObject\s*\(\s*["'](?:WScript\.Shell|MSXML2\.(?:Server)?XMLHTTP|Microsoft\.XMLHTTP|ADODB\.Stream|Shell\.Application)/i },
  { id: 'office_macro', re: /\bAutoOpen\b|\bAuto_Open\b|Document_Open|Workbook_Open|_VBA_PROJECT|VBA\/ThisDocument|Macros\/VBA/ },
  { id: 'pdf_active', re: /\/(?:JavaScript|JS)\s*[(<\/]|\/Launch\b|\/OpenAction\b[\s\S]{0,120}\/(?:JS|JavaScript|Launch)/ },
  { id: 'rtf_exploit', re: /\\objdata|\\objautlink|\\\*\\objclass/ },
  { id: 'dotnet_load', re: /Assembly\]?::?Load\(|Assembly\.Load\(|FromBase64String|\.GetType\(\s*["']System\.Reflection/ },
  { id: 'java_exec', re: /Runtime\.getRuntime\(\)\.exec|ProcessBuilder|ClassLoader\.defineClass/ },
  { id: 'android_abuse', re: /android\.permission\.(?:SEND_SMS|READ_SMS|RECEIVE_SMS|BIND_ACCESSIBILITY_SERVICE|BIND_DEVICE_ADMIN|REQUEST_INSTALL_PACKAGES|SYSTEM_ALERT_WINDOW)/ },
  { id: 'mac_keychain', re: /security\s+find-(?:generic|internet)-password|Library\/Keychains|login\.keychain/ },
  { id: 'mac_osascript', re: /osascript\s+-e|do shell script|tell application "System Events"/ },
  { id: 'linux_preload', re: /\/etc\/ld\.so\.preload|LD_PRELOAD\s*=/ },
  { id: 'setuid_shell', re: /chmod\s+(?:[ugoa]*\+s\b|[2467][0-7]{3}\b)/ },
  { id: 'packer_marker', re: /\bUPX!|\$Info: This file is packed with the UPX|Themida|VMProtect|\.aspack/ },
];
