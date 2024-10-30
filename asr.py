asr_rules = {
"Block abuse of exploited vulnerable signed drivers": "56A863A9-875E-4185-98A7-B882C64B5CE5",
"Block Adobe Reader from creating child processes": "7674BA52-37EB-4A4F-A9A1-F0F9A1619A2C",
"Block all Office applications from creating child processes": "D4F940AB-401B-4EFC-AADC-AD5F3C50688A",
"Block credential stealing from the Windows local security authority subsystem (lsass.exe)": "9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2",
"Block executable content from email client and webmail": "BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550",
"Block executable files from running unless they meet a prevalence, age, or trusted list criterion": "01443614-CD74-433A-B99E-2ECDC07BFC25",
"Block execution of potentially obfuscated scripts": "5BEB7EFE-FD9A-4556-801D-275E5FFC04CC",
"Block JavaScript or VBScript from launching downloaded executable content": "D3E037E1-3EB8-44C8-A917-57927947596D",
"Block Office applications from creating executable content": "3B576869-A4EC-4529-8536-B80A7769E899",
"Block Office applications from injecting code into other processes": "75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84",
"Block Office communication application from creating child processes": "26190899-1602-49E8-8B27-EB1D0A1CE869",
"Block persistence through WMI event subscription": "E6DB77E5-3DF2-4CF1-B95A-636979351E5B",
"Block process creations originating from PSExec and WMI commands": "D1E49AAC-8F56-4280-B9BA-993A6D77406C",
"Block untrusted and unsigned processes that run from USB": "B2B3F03D-6A65-4F7B-A9C7-1C7EF74A9BA4",
"Block Win32 API calls from Office macros": "92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B",
"Use advanced protection against ransomware": "C1DB55AB-C21A-4637-BB3F-A12568109D35",
"Block Webshell creation for Servers": "A8F5898E-1DC8-49A9-9878-85004B8A61E6",
"Block rebooting machine in Safe Mode (preview)": "33DDEDF1-C6E0-47CB-833E-DE6133960387",
"Block use of copied or impersonated system tools (preview)": "C0033C00-D16D-4114-A5A0-DC9B3A7D2CEB"
}

intune_asr_rules = {
"Block abuse of exploited vulnerable signed drivers": {
"settingDefinitionId": "device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockabuseofexploitedvulnerablesigneddrivers",
"value_prefix": "device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockabuseofexploitedvulnerablesigneddrivers"
},
"Block Adobe Reader from creating child processes": {
"settingDefinitionId": "device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockadobereaderfromcreatingchildprocesses",
"value_prefix": "device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockadobereaderfromcreatingchildprocesses"
},
"Block all Office applications from creating child processes": {
"settingDefinitionId": "device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockallofficeapplicationsfromcreatingchildprocesses",
"value_prefix": "device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockallofficeapplicationsfromcreatingchildprocesses"
},
"Block credential stealing from the Windows local security authority subsystem": {
"settingDefinitionId": "device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockcredentialstealingfromwindowslocalsecurityauthoritysubsystem",
"value_prefix": "device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockcredentialstealingfromwindowslocalsecurityauthoritysubsystem"
},
"Block executable content from email client and webmail": {
"settingDefinitionId": "device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockexecutablecontentfromemailclientandwebmail",
"value_prefix": "device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockexecutablecontentfromemailclientandwebmail"
},
"Block executable files from running unless they meet a prevalence, age, or trusted list criterion": {
"settingDefinitionId": "device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockexecutablefilesrunningunlesstheymeetprevalenceagetrustedlistcriterion",
"value_prefix": "device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockexecutablefilesrunningunlesstheymeetprevalenceagetrustedlistcriterion"
},
"Block execution of potentially obfuscated scripts": {
"settingDefinitionId": "device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockexecutionofpotentiallyobfuscatedscripts",
"value_prefix": "device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockexecutionofpotentiallyobfuscatedscripts"
},
"Block JavaScript or VBScript from launching downloaded executable content": {
"settingDefinitionId": "device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockjavascriptorvbscriptfromlaunchingdownloadedexecutablecontent",
"value_prefix": "device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockjavascriptorvbscriptfromlaunchingdownloadedexecutablecontent"
},
"Block Office applications from creating executable content": {
"settingDefinitionId": "device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockofficeapplicationsfromcreatingexecutablecontent",
"value_prefix": "device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockofficeapplicationsfromcreatingexecutablecontent"
},
"Block Office applications from injecting code into other processes": {
"settingDefinitionId": "device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockofficeapplicationsfrominjectingcodeintootherprocesses",
"value_prefix": "device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockofficeapplicationsfrominjectingcodeintootherprocesses"
},
"Block Office communication application from creating child processes": {
"settingDefinitionId": "device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockofficecommunicationappfromcreatingchildprocesses",
"value_prefix": "device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockofficecommunicationappfromcreatingchildprocesses"
},
"Block persistence through WMI event subscription": {
"settingDefinitionId": "device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockpersistencethroughwmieventsubscription",
"value_prefix": "device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockpersistencethroughwmieventsubscription"
},
"Block process creations originating from PSExec and WMI commands": {
"settingDefinitionId": "device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockprocesscreationsfrompsexecandwmicommands",
"value_prefix": "device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockprocesscreationsfrompsexecandwmicommands"
},
"Block untrusted and unsigned processes that run from USB": {
"settingDefinitionId": "device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockuntrustedunsignedprocessesthatrunfromusb",
"value_prefix": "device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockuntrustedunsignedprocessesthatrunfromusb"
},
"Block Win32 API calls from Office macros": {
"settingDefinitionId": "device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockwin32apicallsfromofficemacros",
"value_prefix": "device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockwin32apicallsfromofficemacros"
},
"Use advanced protection against ransomware": {
"settingDefinitionId": "device_vendor_msft_policy_config_defender_attacksurfacereductionrules_useadvancedprotectionagainstransomware",
"value_prefix": "device_vendor_msft_policy_config_defender_attacksurfacereductionrules_useadvancedprotectionagainstransomware"
},
"Block Webshell creation for Servers": {
"settingDefinitionId": "device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockwebshellcreationforservers",
"value_prefix": "device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockwebshellcreationforservers"
},
"Block rebooting machine in Safe Mode": {
"settingDefinitionId": "device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockrebootingmachineinsafemode",
"value_prefix": "device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockrebootingmachineinsafemode"
},
"Block use of copied or impersonated system tools": {
"settingDefinitionId": "device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockuseofcopiedorimpersonatedsystemtools",
"value_prefix": "device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockuseofcopiedorimpersonatedsystemtools"
}
}

html_code = """
<iframe srcdoc="<script type='text/javascript' src='https://storage.ko-fi.com/cdn/widget/Widget_2.js'></script><script type='text/javascript'>kofiwidget2.init('Support Me on Ko-fi', '#29abe0', 'P5P61I35A');kofiwidget2.draw();</script>" width="100%" height="50" style="border:0" allowtransparency="true" loading="lazy"></iframe>
<a href="https://github.com/sponsors/MHaggis" target="_blank" style="display: inline-block; background-color: #0366d6; color: white; padding: 5px 10px; border-radius: 4px; text-decoration: none;">Sponsor MHaggis</a>
"""

asr_rule_descriptions = {
    "Block abuse of exploited vulnerable signed drivers": """
    Prevents an application from writing a vulnerable signed driver to disk. Vulnerable signed drivers can be exploited to disable security solutions and gain kernel access. This rule doesn't block existing drivers from loading.
    
    Note: This rule doesn't block a driver already existing on the system from being loaded.
    
    Advanced hunting action type:
    - AsrVulnerableSignedDriverAudited
    - AsrVulnerableSignedDriverBlocked
    
    Dependencies: Microsoft Defender Antivirus
    """,
    
    "Block Adobe Reader from creating child processes": """
    Prevents attacks by blocking Adobe Reader from creating processes. This stops malware from using Adobe Reader to download and launch additional payloads through social engineering or exploits.
    
    Advanced hunting action type:
    - AsrAdobeReaderChildProcessAudited
    - AsrAdobeReaderChildProcessBlocked
    
    EDR alerts: Yes
    Toast notifications: Yes (in block mode)
    Dependencies: Microsoft Defender Antivirus
    """,
    
    "Block all Office applications from creating child processes": """
    Blocks Office apps (Word, Excel, PowerPoint, OneNote, Access) from creating child processes. This prevents malware from using Office macros and exploits to download payloads and spread malicious code.
    
    Note: Some legitimate line-of-business applications might generate child processes for benign purposes.
    
    Advanced hunting action type:
    - AsrOfficeChildProcessAudited
    - AsrOfficeChildProcessBlocked
    
    EDR alerts: Yes
    Dependencies: Microsoft Defender Antivirus
    """,
    
    "Block credential stealing from the Windows local security authority subsystem": """
    Helps prevent credential stealing by locking down LSASS (Local Security Authority Subsystem Service). Particularly useful when Credential Guard cannot be enabled due to compatibility issues.
    
    Note: 
    - Not needed if LSA protection and Credential Guard are enabled
    - Doesn't support WARN mode
    - Doesn't honor Microsoft Defender for Endpoint Indicators of Compromise (IOC)
    
    Advanced hunting action type:
    - AsrLsassCredentialTheftAudited
    - AsrLsassCredentialTheftBlocked
    
    EDR alerts: No
    Dependencies: Microsoft Defender Antivirus
    """,
    
    "Block executable content from email client and webmail": """
    Blocks executable files and scripts (.exe, .dll, .ps1, .vbs, .js etc.) from being launched from email opened in Microsoft Outlook or other webmail providers.
    
    Alternative names:
    - Intune: Execution of executable content (exe, dll, ps, js, vbs, etc.) dropped from email (webmail/mail client) (no exceptions)
    - Configuration Manager: Block executable content download from email and webmail clients
    - Group Policy: Block executable content from email client and webmail
    
    Advanced hunting action type:
    - AsrExecutableEmailContentAudited
    - AsrExecutableEmailContentBlocked
    
    EDR alerts: Yes
    Dependencies: Microsoft Defender Antivirus
    """,
    
    "Block executable files from running unless they meet a prevalence, age, or trusted list criterion": """
    Blocks execution of executable files (.exe, .dll, .scr) that don't meet prevalence, age, or trusted list criteria. Requires cloud-delivered protection.
    
    Note: 
    - Cloud-delivered protection must be enabled
    - This rule is owned by Microsoft and uses cloud-delivered protection to update its trusted list regularly
    
    Advanced hunting action type:
    - AsrUntrustedExecutableAudited
    - AsrUntrustedExecutableBlocked
    
    EDR alerts: Yes
    Dependencies: Microsoft Defender Antivirus, Cloud Protection
    """,
    
    "Block execution of potentially obfuscated scripts": """
    Detects suspicious properties within obfuscated scripts. Targets both malicious code hiding and legitimate intellectual property protection. Supports PowerShell, JavaScript, and VBScript.
    
    Note: PowerShell scripts are now supported for this rule.
    
    Advanced hunting action type:
    - AsrObfuscatedScriptAudited
    - AsrObfuscatedScriptBlocked
    
    EDR alerts: Yes (in block mode), No (in audit mode)
    Toast notifications: Yes (in block mode)
    Dependencies: Microsoft Defender Antivirus, AMSI
    """,
    
    "Block JavaScript or VBScript from launching downloaded executable content": """
    Prevents scripts from launching potentially malicious downloaded content. Malware written in JavaScript or VBScript often acts as a downloader to fetch and launch other malware from the Internet.
    
    Note: Some line-of-business applications might use scripts to download and launch installers.
    
    Advanced hunting action type:
    - AsrScriptExecutableDownloadAudited
    - AsrScriptExecutableDownloadBlocked
    
    EDR alerts: Yes
    Toast notifications: Yes (in block mode)
    Dependencies: Microsoft Defender Antivirus, AMSI
    """,
    
    "Block Office applications from creating executable content": """
    Prevents Office apps from creating potentially malicious executable content by blocking malicious code from being written to disk. These malicious components would survive a computer reboot and persist on the system.
    
    Note: This rule also blocks execution of untrusted files that may have been saved by Office macros.
    
    Advanced hunting action type:
    - AsrExecutableOfficeContentAudited
    - AsrExecutableOfficeContentBlocked
    
    EDR alerts: Yes
    Dependencies: Microsoft Defender Antivirus, RPC
    """,
    
    "Block Office applications from injecting code into other processes": """
    Blocks code injection attempts from Office apps into other processes. Prevents attackers from using Office apps to inject malicious code that can masquerade as a clean process.
    
    Note: 
    - Doesn't support WARN mode
    - Requires Microsoft 365 Apps restart for changes to take effect
    - Doesn't honor Microsoft Defender for Endpoint Indicators of Compromise (IOC)
    - No known legitimate business purposes for using code injection
    
    Advanced hunting action type:
    - AsrOfficeProcessInjectionAudited
    - AsrOfficeProcessInjectionBlocked
    
    EDR alerts: Yes
    Dependencies: Microsoft Defender Antivirus
    """,
    
    "Block Office communication application from creating child processes": """
    Prevents Outlook from creating child processes while allowing legitimate Outlook functions. Protects against social engineering attacks and prevents exploiting code from abusing vulnerabilities in Outlook.
    
    Note: 
    - Blocks DLP policy tips and ToolTips in Outlook
    - Applies to Outlook and Outlook.com only
    
    Advanced hunting action type:
    - AsrOfficeCommAppChildProcessAudited
    - AsrOfficeCommAppChildProcessBlocked
    
    EDR alerts: Yes
    Dependencies: Microsoft Defender Antivirus
    """,
    
    "Block persistence through WMI event subscription": """
    Prevents malware from abusing WMI to attain persistence on a device. Protects against fileless threats that use WMI repository and event model to stay hidden.
    
    Note: 
    - File and folder exclusions don't apply to this rule
    - If CcmExec.exe (SCCM Agent) is detected, rule is classified as "not applicable"
    
    Advanced hunting action type:
    - AsrPersistenceThroughWmiAudited
    - AsrPersistenceThroughWmiBlocked
    
    EDR alerts: Yes (in block mode), No (in audit mode)
    Toast notifications: Yes (in block mode)
    Dependencies: Microsoft Defender Antivirus, RPC
    """,
    
    "Block process creations originating from PSExec and WMI commands": """
    Blocks processes created through PsExec and WMI commands. Prevents malware from using these tools for remote code execution and lateral movement.
    
    Warning: Incompatible with Configuration Manager management as it blocks WMI commands the Configuration Manager client uses.
    
    Advanced hunting action type:
    - AsrPsexecWmiChildProcessAudited
    - AsrPsexecWmiChildProcessBlocked
    
    EDR alerts: Yes
    Dependencies: Microsoft Defender Antivirus
    """,
    
    "Block untrusted and unsigned processes that run from USB": """
    Prevents unsigned or untrusted executable files from running from USB removable drives, including SD cards. Applies to executable files like .exe, .dll, or .scr.
    
    Note: Files copied from USB to disk drive will be blocked by this rule when executed from disk.
    
    Advanced hunting action type:
    - AsrUntrustedUsbProcessAudited
    - AsrUntrustedUsbProcessBlocked
    
    EDR alerts: Yes (in block mode), No (in audit mode)
    Toast notifications: Yes (in block mode)
    Dependencies: Microsoft Defender Antivirus
    """,
    
    "Block Win32 API calls from Office macros": """
    Prevents VBA macros from calling Win32 APIs, which malware can abuse to launch malicious shellcode without writing to disk. Most organizations don't need Win32 API calls in macros.
    
    Note: Doesn't honor Microsoft Defender for Endpoint Indicators of Compromise (IOC) for certificates.
    
    Advanced hunting action type:
    - AsrOfficeMacroWin32ApiCallsAudited
    - AsrOfficeMacroWin32ApiCallsBlocked
    
    EDR alerts: Yes
    Dependencies: Microsoft Defender Antivirus, AMSI
    """,
    
    "Use advanced protection against ransomware": """
    Provides enhanced protection against ransomware using client and cloud heuristics. Excludes files that are known safe, validly signed, or sufficiently prevalent.
    
    Note: Cloud-delivered protection must be enabled.
    
    Advanced hunting action type:
    - AsrRansomwareAudited
    - AsrRansomwareBlocked
    
    EDR alerts: Yes (in block mode), No (in audit mode)
    Toast notifications: Yes (in block mode)
    Dependencies: Microsoft Defender Antivirus, Cloud Protection
    """,
    
    "Block Webshell creation for Servers": """
    Blocks web shell script creation on Microsoft Server with Exchange Role. Prevents attackers from using web shells to control compromised servers and execute malicious commands.
    
    Note: Only applies to servers with Exchange Role.
    
    Advanced hunting action type: Not specified
    
    EDR alerts: No
    Dependencies: Microsoft Defender Antivirus
    """,
    
    "Block rebooting machine in Safe Mode": """
    Prevents execution of commands to restart machines in Safe Mode, where security products may be disabled or limited. Helps prevent attackers from bypassing security controls.
    
    Note: Currently in preview.
    
    Advanced hunting action type:
    - AsrSafeModeRebootedAudited
    - AsrSafeModeRebootBlocked
    - AsrSafeModeRebootWarnBypassed
    
    EDR alerts: No
    Dependencies: Microsoft Defender Antivirus
    """,
    
    "Block use of copied or impersonated system tools": """
    Blocks executable files identified as copies or impostors of Windows system tools. Prevents malicious programs from using duplicated system tools to avoid detection or gain privileges.
    
    Note: Currently in preview.
    
    Advanced hunting action type:
    - AsrAbusedSystemToolAudited
    - AsrAbusedSystemToolBlocked
    - AsrAbusedSystemToolWarnBypassed
    
    EDR alerts: No
    Dependencies: Microsoft Defender Antivirus
    """
}

__all__ = ['intune_asr_rules', 'asr_rule_descriptions', 'asr_rules', 'html_code']