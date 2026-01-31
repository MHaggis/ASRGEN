"""
ASR Rules Data and Metadata - Single Source of Truth
"""

from dataclasses import dataclass
from typing import Dict, List

@dataclass
class ASRRule:
    """Represents a single ASR rule"""
    name: str
    guid: str
    description: str
    intune_setting_id: str
    intune_value_prefix: str
    category: str  # Office, Process, Credential, Script, Driver, Ransomware, etc.
    editable_in_intune: bool = True
    supports_warn_mode: bool = True
    requires_cloud_protection: bool = False
    incompatible_with: List[str] = None  # List of rule GUIDs that conflict
    
    def __post_init__(self):
        if self.incompatible_with is None:
            self.incompatible_with = []

# All ASR rules - single source of truth
ASR_RULES = {
    "56A863A9-875E-4185-98A7-B882C64B5CE5": ASRRule(
        name="Block abuse of exploited vulnerable signed drivers",
        guid="56A863A9-875E-4185-98A7-B882C64B5CE5",
        category="Driver",
        description="""Prevents an application from writing a vulnerable signed driver to disk. Vulnerable signed drivers can be exploited to disable security solutions and gain kernel access. This rule doesn't block existing drivers from loading.

Note: This rule doesn't block a driver already existing on the system from being loaded.

Advanced hunting action type:
- AsrVulnerableSignedDriverAudited
- AsrVulnerableSignedDriverBlocked

Dependencies: Microsoft Defender Antivirus""",
        intune_setting_id="device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockabuseofexploitedvulnerablesigneddrivers",
        intune_value_prefix="device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockabuseofexploitedvulnerablesigneddrivers",
    ),
    "7674BA52-37EB-4A4F-A9A1-F0F9A1619A2C": ASRRule(
        name="Block Adobe Reader from creating child processes",
        guid="7674BA52-37EB-4A4F-A9A1-F0F9A1619A2C",
        category="Application",
        description="""Prevents attacks by blocking Adobe Reader from creating processes. This stops malware from using Adobe Reader to download and launch additional payloads through social engineering or exploits.

Advanced hunting action type:
- AsrAdobeReaderChildProcessAudited
- AsrAdobeReaderChildProcessBlocked

EDR alerts: Yes
Toast notifications: Yes (in block mode)
Dependencies: Microsoft Defender Antivirus""",
        intune_setting_id="device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockadobereaderfromcreatingchildprocesses",
        intune_value_prefix="device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockadobereaderfromcreatingchildprocesses",
    ),
    "D4F940AB-401B-4EFC-AADC-AD5F3C50688A": ASRRule(
        name="Block all Office applications from creating child processes",
        guid="D4F940AB-401B-4EFC-AADC-AD5F3C50688A",
        category="Office",
        description="""Blocks Office apps (Word, Excel, PowerPoint, OneNote, Access) from creating child processes. This prevents malware from using Office macros and exploits to download payloads and spread malicious code.

Note: Some legitimate line-of-business applications might generate child processes for benign purposes.

Advanced hunting action type:
- AsrOfficeChildProcessAudited
- AsrOfficeChildProcessBlocked

EDR alerts: Yes
Dependencies: Microsoft Defender Antivirus""",
        intune_setting_id="device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockallofficeapplicationsfromcreatingchildprocesses",
        intune_value_prefix="device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockallofficeapplicationsfromcreatingchildprocesses",
    ),
    "9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2": ASRRule(
        name="Block credential stealing from the Windows local security authority subsystem",
        guid="9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2",
        category="Credential",
        description="""Helps prevent credential stealing by locking down LSASS (Local Security Authority Subsystem Service). Particularly useful when Credential Guard cannot be enabled due to compatibility issues.

Note: 
- Not needed if LSA protection and Credential Guard are enabled
- Doesn't support WARN mode
- Doesn't honor Microsoft Defender for Endpoint Indicators of Compromise (IOC)

Advanced hunting action type:
- AsrLsassCredentialTheftAudited
- AsrLsassCredentialTheftBlocked

EDR alerts: No
Dependencies: Microsoft Defender Antivirus""",
        intune_setting_id="device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockcredentialstealingfromwindowslocalsecurityauthoritysubsystem",
        intune_value_prefix="device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockcredentialstealingfromwindowslocalsecurityauthoritysubsystem",
        supports_warn_mode=False,
    ),
    "BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550": ASRRule(
        name="Block executable content from email client and webmail",
        guid="BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550",
        category="Email",
        description="""Blocks executable files and scripts (.exe, .dll, .ps1, .vbs, .js etc.) from being launched from email opened in Microsoft Outlook or other webmail providers.

Alternative names:
- Intune: Execution of executable content (exe, dll, ps, js, vbs, etc.) dropped from email (webmail/mail client) (no exceptions)
- Configuration Manager: Block executable content download from email and webmail clients
- Group Policy: Block executable content from email client and webmail

Advanced hunting action type:
- AsrExecutableEmailContentAudited
- AsrExecutableEmailContentBlocked

EDR alerts: Yes
Dependencies: Microsoft Defender Antivirus""",
        intune_setting_id="device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockexecutablecontentfromemailclientandwebmail",
        intune_value_prefix="device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockexecutablecontentfromemailclientandwebmail",
    ),
    "01443614-CD74-433A-B99E-2ECDC07BFC25": ASRRule(
        name="Block executable files from running unless they meet a prevalence, age, or trusted list criterion",
        guid="01443614-CD74-433A-B99E-2ECDC07BFC25",
        category="Execution",
        description="""Blocks execution of executable files (.exe, .dll, .scr) that don't meet prevalence, age, or trusted list criteria. Requires cloud-delivered protection.

Note: 
- Cloud-delivered protection must be enabled
- This rule is owned by Microsoft and uses cloud-delivered protection to update its trusted list regularly

Advanced hunting action type:
- AsrUntrustedExecutableAudited
- AsrUntrustedExecutableBlocked

EDR alerts: Yes
Dependencies: Microsoft Defender Antivirus, Cloud Protection""",
        intune_setting_id="device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockexecutablefilesrunningunlesstheymeetprevalenceagetrustedlistcriterion",
        intune_value_prefix="device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockexecutablefilesrunningunlesstheymeetprevalenceagetrustedlistcriterion",
        requires_cloud_protection=True,
    ),
    "5BEB7EFE-FD9A-4556-801D-275E5FFC04CC": ASRRule(
        name="Block execution of potentially obfuscated scripts",
        guid="5BEB7EFE-FD9A-4556-801D-275E5FFC04CC",
        category="Script",
        description="""Detects suspicious properties within obfuscated scripts. Targets both malicious code hiding and legitimate intellectual property protection. Supports PowerShell, JavaScript, and VBScript.

Note: PowerShell scripts are now supported for this rule.

Advanced hunting action type:
- AsrObfuscatedScriptAudited
- AsrObfuscatedScriptBlocked

EDR alerts: Yes (in block mode), No (in audit mode)
Toast notifications: Yes (in block mode)
Dependencies: Microsoft Defender Antivirus, AMSI""",
        intune_setting_id="device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockexecutionofpotentiallyobfuscatedscripts",
        intune_value_prefix="device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockexecutionofpotentiallyobfuscatedscripts",
    ),
    "D3E037E1-3EB8-44C8-A917-57927947596D": ASRRule(
        name="Block JavaScript or VBScript from launching downloaded executable content",
        guid="D3E037E1-3EB8-44C8-A917-57927947596D",
        category="Script",
        description="""Prevents scripts from launching potentially malicious downloaded content. Malware written in JavaScript or VBScript often acts as a downloader to fetch and launch other malware from the Internet.

Note: Some line-of-business applications might use scripts to download and launch installers.

Advanced hunting action type:
- AsrScriptExecutableDownloadAudited
- AsrScriptExecutableDownloadBlocked

EDR alerts: Yes
Toast notifications: Yes (in block mode)
Dependencies: Microsoft Defender Antivirus, AMSI""",
        intune_setting_id="device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockjavascriptorvbscriptfromlaunchingdownloadedexecutablecontent",
        intune_value_prefix="device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockjavascriptorvbscriptfromlaunchingdownloadedexecutablecontent",
    ),
    "3B576869-A4EC-4529-8536-B80A7769E899": ASRRule(
        name="Block Office applications from creating executable content",
        guid="3B576869-A4EC-4529-8536-B80A7769E899",
        category="Office",
        description="""Prevents Office apps from creating potentially malicious executable content by blocking malicious code from being written to disk. These malicious components would survive a computer reboot and persist on the system.

Note: This rule also blocks execution of untrusted files that may have been saved by Office macros.

Advanced hunting action type:
- AsrExecutableOfficeContentAudited
- AsrExecutableOfficeContentBlocked

EDR alerts: Yes
Dependencies: Microsoft Defender Antivirus, RPC""",
        intune_setting_id="device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockofficeapplicationsfromcreatingexecutablecontent",
        intune_value_prefix="device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockofficeapplicationsfromcreatingexecutablecontent",
    ),
    "75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84": ASRRule(
        name="Block Office applications from injecting code into other processes",
        guid="75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84",
        category="Office",
        description="""Blocks code injection attempts from Office apps into other processes. Prevents attackers from using Office apps to inject malicious code that can masquerade as a clean process.

Note: 
- Doesn't support WARN mode
- Requires Microsoft 365 Apps restart for changes to take effect
- Doesn't honor Microsoft Defender for Endpoint Indicators of Compromise (IOC)
- No known legitimate business purposes for using code injection

Advanced hunting action type:
- AsrOfficeProcessInjectionAudited
- AsrOfficeProcessInjectionBlocked

EDR alerts: Yes
Dependencies: Microsoft Defender Antivirus""",
        intune_setting_id="device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockofficeapplicationsfrominjectingcodeintootherprocesses",
        intune_value_prefix="device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockofficeapplicationsfrominjectingcodeintootherprocesses",
        supports_warn_mode=False,
    ),
    "26190899-1602-49E8-8B27-EB1D0A1CE869": ASRRule(
        name="Block Office communication application from creating child processes",
        guid="26190899-1602-49E8-8B27-EB1D0A1CE869",
        category="Office",
        description="""Prevents Outlook from creating child processes while allowing legitimate Outlook functions. Protects against social engineering attacks and prevents exploiting code from abusing vulnerabilities in Outlook.

Note: 
- Blocks DLP policy tips and ToolTips in Outlook
- Applies to Outlook and Outlook.com only

Advanced hunting action type:
- AsrOfficeCommAppChildProcessAudited
- AsrOfficeCommAppChildProcessBlocked

EDR alerts: Yes
Dependencies: Microsoft Defender Antivirus""",
        intune_setting_id="device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockofficecommunicationappfromcreatingchildprocesses",
        intune_value_prefix="device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockofficecommunicationappfromcreatingchildprocesses",
    ),
    "E6DB77E5-3DF2-4CF1-B95A-636979351E5B": ASRRule(
        name="Block persistence through WMI event subscription",
        guid="E6DB77E5-3DF2-4CF1-B95A-636979351E5B",
        category="Persistence",
        description="""Prevents malware from abusing WMI to attain persistence on a device. Protects against fileless threats that use WMI repository and event model to stay hidden.

Note: 
- File and folder exclusions don't apply to this rule
- If CcmExec.exe (SCCM Agent) is detected, rule is classified as "not applicable"

Advanced hunting action type:
- AsrPersistenceThroughWmiAudited
- AsrPersistenceThroughWmiBlocked

EDR alerts: Yes (in block mode), No (in audit mode)
Toast notifications: Yes (in block mode)
Dependencies: Microsoft Defender Antivirus, RPC""",
        intune_setting_id="device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockpersistencethroughwmieventsubscription",
        intune_value_prefix="device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockpersistencethroughwmieventsubscription",
        incompatible_with=["D1E49AAC-8F56-4280-B9BA-993A6D77406C"],  # Conflicts with PSExec/WMI blocker if SCCM is involved
    ),
    "D1E49AAC-8F56-4280-B9BA-993A6D77406C": ASRRule(
        name="Block process creations originating from PSExec and WMI commands",
        guid="D1E49AAC-8F56-4280-B9BA-993A6D77406C",
        category="Process",
        description="""Blocks processes created through PsExec and WMI commands. Prevents malware from using these tools for remote code execution and lateral movement.

Warning: Incompatible with Configuration Manager management as it blocks WMI commands the Configuration Manager client uses.

Advanced hunting action type:
- AsrPsexecWmiChildProcessAudited
- AsrPsexecWmiChildProcessBlocked

EDR alerts: Yes
Dependencies: Microsoft Defender Antivirus""",
        intune_setting_id="device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockprocesscreationsfrompsexecandwmicommands",
        intune_value_prefix="device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockprocesscreationsfrompsexecandwmicommands",
        incompatible_with=["E6DB77E5-3DF2-4CF1-B95A-636979351E5B"],  # Conflicts with WMI persistence blocker if SCCM is involved
    ),
    "B2B3F03D-6A65-4F7B-A9C7-1C7EF74A9BA4": ASRRule(
        name="Block untrusted and unsigned processes that run from USB",
        guid="B2B3F03D-6A65-4F7B-A9C7-1C7EF74A9BA4",
        category="Execution",
        description="""Prevents unsigned or untrusted executable files from running from USB removable drives, including SD cards. Applies to executable files like .exe, .dll, or .scr.

Note: Files copied from USB to disk drive will be blocked by this rule when executed from disk.

Advanced hunting action type:
- AsrUntrustedUsbProcessAudited
- AsrUntrustedUsbProcessBlocked

EDR alerts: Yes (in block mode), No (in audit mode)
Toast notifications: Yes (in block mode)
Dependencies: Microsoft Defender Antivirus""",
        intune_setting_id="device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockuntrustedunsignedprocessesthatrunfromusb",
        intune_value_prefix="device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockuntrustedunsignedprocessesthatrunfromusb",
    ),
    "92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B": ASRRule(
        name="Block Win32 API calls from Office macros",
        guid="92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B",
        category="Office",
        description="""Prevents VBA macros from calling Win32 APIs, which malware can abuse to launch malicious shellcode without writing to disk. Most organizations don't need Win32 API calls in macros.

Note: Doesn't honor Microsoft Defender for Endpoint Indicators of Compromise (IOC) for certificates.

Advanced hunting action type:
- AsrOfficeMacroWin32ApiCallsAudited
- AsrOfficeMacroWin32ApiCallsBlocked

EDR alerts: Yes
Dependencies: Microsoft Defender Antivirus, AMSI""",
        intune_setting_id="device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockwin32apicallsfromofficemacros",
        intune_value_prefix="device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockwin32apicallsfromofficemacros",
    ),
    "C1DB55AB-C21A-4637-BB3F-A12568109D35": ASRRule(
        name="Use advanced protection against ransomware",
        guid="C1DB55AB-C21A-4637-BB3F-A12568109D35",
        category="Ransomware",
        description="""Provides enhanced protection against ransomware using client and cloud heuristics. Excludes files that are known safe, validly signed, or sufficiently prevalent.

Note: Cloud-delivered protection must be enabled.

Advanced hunting action type:
- AsrRansomwareAudited
- AsrRansomwareBlocked

EDR alerts: Yes (in block mode), No (in audit mode)
Toast notifications: Yes (in block mode)
Dependencies: Microsoft Defender Antivirus, Cloud Protection""",
        intune_setting_id="device_vendor_msft_policy_config_defender_attacksurfacereductionrules_useadvancedprotectionagainstransomware",
        intune_value_prefix="device_vendor_msft_policy_config_defender_attacksurfacereductionrules_useadvancedprotectionagainstransomware",
        requires_cloud_protection=True,
    ),
    "A8F5898E-1DC8-49A9-9878-85004B8A61E6": ASRRule(
        name="Block Webshell creation for Servers",
        guid="A8F5898E-1DC8-49A9-9878-85004B8A61E6",
        category="Server",
        description="""Blocks web shell script creation on Microsoft Server with Exchange Role. Prevents attackers from using web shells to control compromised servers and execute malicious commands.

Note: Only applies to servers with Exchange Role.

Advanced hunting action type: Not specified

EDR alerts: No
Dependencies: Microsoft Defender Antivirus""",
        intune_setting_id="device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockwebshellcreationforservers",
        intune_value_prefix="device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockwebshellcreationforservers",
    ),
    "33DDEDF1-C6E0-47CB-833E-DE6133960387": ASRRule(
        name="Block rebooting machine in Safe Mode",
        guid="33DDEDF1-C6E0-47CB-833E-DE6133960387",
        category="Process",
        description="""Prevents execution of commands to restart machines in Safe Mode, where security products may be disabled or limited. Helps prevent attackers from bypassing security controls.

Advanced hunting action type:
- AsrSafeModeRebootedAudited
- AsrSafeModeRebootBlocked
- AsrSafeModeRebootWarnBypassed

EDR alerts: No
Dependencies: Microsoft Defender Antivirus""",
        intune_setting_id="device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockrebootingmachineinsafemode",
        intune_value_prefix="device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockrebootingmachineinsafemode",
    ),
    "C0033C00-D16D-4114-A5A0-DC9B3A7D2CEB": ASRRule(
        name="Block use of copied or impersonated system tools",
        guid="C0033C00-D16D-4114-A5A0-DC9B3A7D2CEB",
        category="Process",
        description="""Blocks executable files identified as copies or impostors of Windows system tools. Prevents malicious programs from using duplicated system tools to avoid detection or gain privileges.

Advanced hunting action type:
- AsrAbusedSystemToolAudited
- AsrAbusedSystemToolBlocked
- AsrAbusedSystemToolWarnBypassed

EDR alerts: No
Dependencies: Microsoft Defender Antivirus""",
        intune_setting_id="device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockuseofcopiedorimpersonatedsystemtools",
        intune_value_prefix="device_vendor_msft_policy_config_defender_attacksurfacereductionrules_blockuseofcopiedorimpersonatedsystemtools",
    ),
}

# Presets for quick configuration
PRESETS = {
    "Audit Only": {
        "description": "All rules in audit mode for monitoring without impact",
        "mode": "Audit",
        "rules": list(ASR_RULES.keys()),
    },
    "Defender Baseline": {
        "description": "Microsoft's recommended baseline for most organizations",
        "mode": "Block",
        "rules": [
            "D4F940AB-401B-4EFC-AADC-AD5F3C50688A",  # Block all Office child processes
            "BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550",  # Block email executable content
            "5BEB7EFE-FD9A-4556-801D-275E5FFC04CC",  # Block obfuscated scripts
            "D3E037E1-3EB8-44C8-A917-57927947596D",  # Block script downloads
            "92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B",  # Block Win32 API from macros
            "C1DB55AB-C21A-4637-BB3F-A12568109D35",  # Ransomware protection
        ],
    },
    "Enterprise Hardened": {
        "description": "Comprehensive protection with increased compatibility management",
        "mode": "Block",
        "rules": [k for k, v in ASR_RULES.items() if v.guid != "D1E49AAC-8F56-4280-B9BA-993A6D77406C"],  # All except PSExec/WMI (SCCM conflict)
    },
}

# Helper functions
def get_rule_by_guid(guid: str) -> ASRRule:
    """Get an ASR rule by GUID"""
    return ASR_RULES.get(guid)

def get_rules_by_category(category: str) -> Dict[str, ASRRule]:
    """Get all rules in a category"""
    return {guid: rule for guid, rule in ASR_RULES.items() if rule.category == category}

def get_categories() -> List[str]:
    """Get all unique categories"""
    return sorted(list(set(rule.category for rule in ASR_RULES.values())))

def check_conflicts(selected_guids: List[str]) -> List[Dict]:
    """Check for conflicts in selected rules
    
    Args:
        selected_guids: List of ASR rule GUIDs to check
        
    Returns:
        List of conflicts found (each with rule1, rule2, message)
    """
    conflicts = []
    for guid in selected_guids:
        rule = get_rule_by_guid(guid)
        if rule and rule.incompatible_with:
            for incompatible_guid in rule.incompatible_with:
                if incompatible_guid in selected_guids:
                    conflicts.append({
                        "rule1": rule.name,
                        "rule2": get_rule_by_guid(incompatible_guid).name,
                        "message": f"'{rule.name}' conflicts with '{get_rule_by_guid(incompatible_guid).name}'"
                    })
    return conflicts
