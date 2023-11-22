import streamlit as st
from streamlit.components.v1 import html
from streamlit_js_eval import streamlit_js_eval
from time import sleep


st.set_page_config(page_title="ASR Essentials", layout="wide")

st.title("Attack Surface Reduction (ASR) Essentials")

if "svg_height" not in st.session_state:
    st.session_state["svg_height"] = 200

if "previous_mermaid" not in st.session_state:
    st.session_state["previous_mermaid"] = ""

if "previous_font_size" not in st.session_state:
    st.session_state["previous_font_size"] = 18

def mermaid(code: str, font_size: int = 18) -> None:
    html(
        f"""
        <pre class="mermaid">
            {code}
        </pre>
        <script type="module">
            import mermaid from 'https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.esm.min.mjs';
            mermaid.initialize({{ startOnLoad: true, theme: "default", themeVariables: {{ fontSize: "{font_size}px" }} }});
        </script>
        """,
        height=st.session_state["svg_height"] + 50,
    )

# Your mermaid code
code = """
graph LR
    A["Endpoint Activity (File Execution, Script Run, etc.)"] --> B["ASR Rule Evaluation"]
    B --> C{"ASR Rule Triggered?"}
    C -->|Yes| D["Enforce ASR Action (Block/Warn/Audit)"]
    C -->|No| E["Activity Allowed"]
    D --> F{"Action Type"}
    F -->|Block| G["Activity Blocked"]
    F -->|Warn| H["User Warning & Decision"]
    F -->|Audit| I["Activity Logged for Review"]
    subgraph "Adversarial Actions"
    J["Exploit Vulnerabilities"] -.-> B
    K["Bypass ASR Rules"] -.-> B
    L["Mimic Legitimate Behavior"] -.-> B
    end
    subgraph "Defender's Monitoring and Response"
    M["Monitor ASR Alerts and Logs"] -.-> F
    N["Review and Analyze ASR Incidents"] -.-> F
    O["Update and Refine ASR Rules"] -.-> B
    end
"""

mermaid(code, 18)

if (
    code != st.session_state["previous_mermaid"]
    or 18 != st.session_state["previous_font_size"]
):
    st.session_state["previous_mermaid"] = code
    st.session_state["previous_font_size"] = 18
    sleep(1)
    streamlit_js_eval(
        js_expressions='parent.document.getElementsByTagName("iframe")[0].contentDocument.getElementsByClassName("mermaid")[0].getElementsByTagName("svg")[0].getBBox().height',
        key="svg_height",
    )



toc = """
1. **[Introduction](#what-is-attack-surface-reduction)**
   - [What is Attack Surface Reduction?](#what-is-attack-surface-reduction)

2. **[Using ASR on the Command Line](#using-asr-on-the-command-line)**
   - [Command Line Parameters for ASR](#command-line-parameters-for-asr)
     - [Set-MpPreference Cmdlet](#set-mppreference-cmdlet)

3. **[Listing ASR Rules](#listing-asr-rules)**
   - [View All ASR Rules](#view-all-asr-rules)
   - [View a Specific ASR Rule](#view-a-specific-asr-rule)
   - [Understanding Rule Actions](#understanding-rule-actions)
   - [Explanation of Rule Actions](#explanation-of-rule-actions)

4. **[Understanding ASR Event Codes](#understanding-asr-event-codes)**
   - [Common ASR Event Codes](#common-asr-event-codes)

5. **[Registry Modifications by ASR](#registry-modifications-by-asr)**
   - [Registry Keys for ASR](#registry-keys-for-asr)
   - [Common Registry Entries](#common-registry-entries)

6. **[Using PowerShell to Review ASR Event Logs](#using-powershell-to-review-asr-event-logs)**
   - [Basic Command to Access ASR Event Logs](#basic-command-to-access-asr-event-logs)
   - [Filtering Event Logs](#filtering-event-logs)
   - [Viewing the Last N Events](#viewing-the-last-n-events)
   - [Exporting Event Logs](#exporting-event-logs)

7. **[How to Use Exclusions in ASR](#how-to-use-exclusions-in-asr)**
   - [Creating Exclusions](#creating-exclusions)
   - [Types of Exclusions](#types-of-exclusions)
   - [Considerations for Using Exclusions](#considerations-for-using-exclusions)
   - [Reviewing and Managing Exclusions](#reviewing-and-managing-exclusions)
   - [Examples of Exclusion Paths](#examples-of-exclusion-paths)
     - [Using Wildcards in Paths](#using-wildcards-in-paths)
     - [Using Environment Variables in Paths](#using-environment-variables-in-paths)
     - [Combining Wildcards and Environment Variables](#combining-wildcards-and-environment-variables)
     - [Things to Remember](#things-to-remember)

8. **[Conclusion and Additional Resources](#conclusion-and-additional-resources)**
"""
st.markdown(toc, unsafe_allow_html=True)

st.header("What is Attack Surface Reduction?")
st.write("""
Attack Surface Reduction (ASR) is a set of controls that help prevent actions that malware often uses to infect machines. 
It's a feature in Microsoft Defender for Endpoint designed to help organizations reduce the risk from malware 
that uses office files and scripts to infect machines.
""")

st.header("Using ASR on the Command Line")
st.write("""
To manage ASR rules via the command line, you use the `Set-MpPreference` cmdlet in PowerShell. 
This cmdlet allows you to enable or disable specific ASR rules, set their actions, and configure exclusions.
""")

st.header("Command Line Parameters for ASR")
st.subheader("Set-MpPreference Cmdlet")
st.code("""
# To enable an ASR rule:
Set-MpPreference -AttackSurfaceReductionRules_Ids <RuleID> -AttackSurfaceReductionRules_Actions Enabled

# To disable an ASR rule:
Set-MpPreference -AttackSurfaceReductionRules_Ids <RuleID> -AttackSurfaceReductionRules_Actions Disabled

# To set a rule to Warn mode:
Set-MpPreference -AttackSurfaceReductionRules_Ids <RuleID> -AttackSurfaceReductionRules_Actions Warn

# To set a rule to Audit mode:
Set-MpPreference -AttackSurfaceReductionRules_Ids <RuleID> -AttackSurfaceReductionRules_Actions AuditMode

# Enable all Rules in AuditMode
(Get-MpPreference).AttackSurfaceReductionRules_Ids | Foreach {Add-MpPreference -AttackSurfaceReductionRules_Ids $_ -AttackSurfaceReductionRules_Actions AuditMode}
""", language="powershell")

st.header("Listing ASR Rules")
st.write("""
To view the current status of ASR rules, you can use the `Get-MpPreference` cmdlet in PowerShell. This cmdlet allows you to see the status of all ASR rules or a specific rule.
""")

st.subheader("View All ASR Rules")
st.code("""
# To view the status of all ASR rules:
$asrSettings = Get-MpPreference | Select-Object AttackSurfaceReductionRules_Ids, AttackSurfaceReductionRules_Actions

for ($i=0; $i -lt $asrSettings.AttackSurfaceReductionRules_Ids.Count; $i++) {
    Write-Host ("Rule ID: " + $asrSettings.AttackSurfaceReductionRules_Ids[$i] + " - Action: " + $asrSettings.AttackSurfaceReductionRules_Actions[$i])
}
""", language="powershell")

st.info("""
Example output:\n
Rule ID: 01443614-cd74-433a-b99e-2ecdc07bfc25 - Action: 2\n
Rule ID: 26190899-1602-49e8-8b27-eb1d0a1ce869 - Action: 2\n
Rule ID: 3B576869-A4EC-4529-8536-B80A7769E899 - Action: 2\n
""")


st.subheader("View a Specific ASR Rule")
st.write("""
To view the status of a specific ASR rule, you need to know the rule's ID. Once you have the ID, you can filter the output of `Get-MpPreference`.
""")
st.code("""
# To view a specific ASR rule (replace <RuleID> with the actual ID of the rule):
$ruleId = "<RuleID>"
$asrSettings = Get-MpPreference | Select-Object  AttackSurfaceReductionRules_Ids, AttackSurfaceReductionRules_Actions
$index = $asrSettings.AttackSurfaceReductionRules_Ids.IndexOf($ruleId)
if ($index -ne -1) {
    $ruleAction = $asrSettings.AttackSurfaceReductionRules_Actions[$index]
    Write-Host "Rule ID: $ruleId - Action: $ruleAction"
} else {
    Write-Host "Rule ID: $ruleId not found"
}
""", language="powershell")

st.subheader("Understanding Rule Actions")
st.write("""
In the output of `Get-MpPreference`, the status of ASR rules is indicated by their actions:
- `0` denotes a rule is Disabled.
- `1` means the rule is set to Block mode.
- `2` indicates the rule is in Audit mode.
- `6` represents the Warn mode.
""")

st.subheader("Explanation of Rule Actions")
st.write("""
- **Block**: When a rule is set to 'Block', it actively prevents the execution of actions that are deemed risky or potentially malicious. This is a proactive stance to stop threats before they can execute.
- **Warn**: 'Warn' mode allows the potentially risky actions to execute but will warn the user or administrator. This mode is useful for understanding the impact of a rule without fully enforcing it.
- **Disable**: Disabling a rule means it won't take any action or log any events. Use this when you're certain that the rule's protection is not needed or if it's causing false positives.
- **Audit**: In 'Audit' mode, the rule logs events when it detects actions that would have been blocked or warned about if the rule was active. This mode is useful for evaluating the impact of a rule before fully enforcing it.
""")

st.header("Understanding ASR Event Codes")
st.write("""
ASR rules generate specific event codes that are logged in the Windows Event Log. These codes are crucial for monitoring and understanding the actions taken by ASR rules.
""")

st.subheader("Common ASR Event Codes")
st.write("""
- **Event ID 1121**: Microsoft Defender Exploit Guard has blocked an operation that is not allowed by your IT administrator.
- **Event ID 1122**: Microsoft Defender Exploit Guard audited an operation that is not allowed by your IT administrator.
- **Event ID 1125**: Audit mode: Microsoft Defender Exploit Guard would have blocked a potentially dangerous network connection.
- **Event ID 1126**: Block mode: Microsoft Defender Exploit Guard has blocked a potentially dangerous network connection.
- **Event ID 1129**: A user has allowed a blocked Microsoft Defender Exploit Guard operation.
- **Event ID 1131**: Microsoft Defender ASR has blocked an operation that your administrator doesn't allow.
- **Event ID 1132**: Microsoft Defender ASR has audited an operation.
- **Event ID 1133**: Microsoft Defender ASR has blocked an operation that your administrator doesn't allow.
- **Event ID 1134**: Microsoft Defender ASR has audited an operation.
- **Event ID 5007**: Configuration has changed. If this is an unexpected event you should review the settings as this may be the result of malware.
""")

st.code("""
# Simple PowerShell command to export ASR event logs to a CSV file:
Get-WinEvent -LogName "Microsoft-Windows-Windows Defender/Operational" | Where-Object {1121, 1122, 1125, 1126, 1129, 1131, 1132, 1133, 1134, 5007 -contains $_.Id} | Select-Object TimeCreated, Id, LevelDisplayName, Message | Export-Csv -NoTypeInformation -Path "ASR_EventLogs.csv"
""", language="powershell")

st.header("Registry Modifications by ASR")
st.write("""
Attack Surface Reduction (ASR) rules, when enabled or configured, make specific modifications to the Windows Registry. These modifications are key to how ASR rules are enforced and logged. Understanding these registry changes can help in troubleshooting and ensuring that the rules are correctly applied.
""")

st.subheader("Registry Keys for ASR")
st.write("""
ASR rules are primarily stored in the following registry key:
- `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR`
""")

st.subheader("Common Registry Entries")
st.write("""
Within the ASR key, common entries include:
- `Rules`: Lists the GUIDs of all ASR rules and their corresponding actions.
- `Exclusions`: Contains any exclusions to the ASR rules, based on file paths or other criteria.
""")

st.write("""
Note: Modifying these registry entries directly is not recommended unless you are an advanced user and understand the implications. Instead, it's safer to use PowerShell cmdlets or Group Policy for configuring ASR rules.
""")

st.header("Using PowerShell to Review ASR Event Logs")
st.write("""
ASR rules generate event logs that are essential for monitoring and reviewing the actions taken by these rules. PowerShell can be used to query these event logs to extract useful information.
""")

st.subheader("Basic Command to Access ASR Event Logs")
st.code("""
# To access the ASR event logs:
Get-WinEvent -LogName "Microsoft-Windows-Windows Defender/Operational" 
""", language="powershell")

st.subheader("Filtering Event Logs")
st.write("""
To filter the event logs for specific ASR rules or actions, you can refine the PowerShell command.
""")
st.code("""
# To filter event logs for a specific ASR rule ID:
$ruleId = '<RuleID>'
Get-WinEvent -LogName "Microsoft-Windows-Windows Defender/Operational" | Where-Object { $_.Id -eq 1121 -and $_.Properties[0].Value -eq $ruleId }
""", language="powershell")

st.subheader("Viewing the Last N Events")
st.code("""
# To view the last 5 events, for example:
Get-WinEvent -LogName "Microsoft-Windows-Windows Defender/Operational" | Where-Object { $_.Id -eq 1121 } | Select-Object -First 5
""", language="powershell")

st.subheader("Exporting Event Logs")
st.code("""
# To export event logs to a CSV file:
Get-WinEvent -LogName "Microsoft-Windows-Windows Defender/Operational" | Where-Object { $_.Id -eq 1121 } | Export-Csv -Path "ASR_Logs.csv"
""", language="powershell")

st.write("""
These commands provide a basis for reviewing and analyzing ASR rule logs, which is crucial for assessing the effectiveness of your ASR configurations.
""")

st.header("How to Use Exclusions in ASR")

st.write("""
Exclusions in Attack Surface Reduction (ASR) allow you to define specific files, folders, or processes that the ASR rules should ignore. This is particularly useful in scenarios where you know certain applications or files are safe and you want to prevent them from being falsely flagged or blocked by ASR rules. However, it's important to use exclusions judiciously as they can potentially create security gaps.
""")

st.markdown("""
1. **General Exclusions**: These exclusions apply to all ASR rules. Use the `-AttackSurfaceReductionOnlyExclusions` parameter to set these exclusions.
2. **Rule-Specific Exclusions**: These exclusions apply to a specific ASR rule. Use the `-AttackSurfaceReductionRules_RuleSpecificExclusions_Id` and `-AttackSurfaceReductionRules_RuleSpecificExclusions` parameters to set these exclusions.
""")

st.code("""
# General Exclusions
Set-MpPreference -AttackSurfaceReductionOnlyExclusions "C:\\path\\to\\exclude"

# Rule-Specific Exclusions
Set-MpPreference -AttackSurfaceReductionRules_RuleSpecificExclusions_Id "<RuleID>" -AttackSurfaceReductionRules_RuleSpecificExclusions "C:\\path\\to\\exclude"
""", language="powershell")

st.subheader("Reviewing and Managing Exclusions")

st.write("""
You can review and manage your existing exclusions using the `Get-MpPreference` cmdlet in PowerShell.
""")

st.code("""
# Reviewing General Exclusions
Get-MpPreference | Select-Object AttackSurfaceReductionOnlyExclusions
""", language="powershell")

st.subheader("Types of Exclusions")

st.write("""
You can exclude files and folders based on:
- **File Paths**: Specify the full path of the file or folder.
- **Environment Variables**: Use variables like `%ProgramFiles%` to specify paths.
- **Wildcards**: Use `*` and `?` to represent multiple or single characters, respectively.
""")

st.subheader("Considerations for Using Exclusions")

st.write("""
- Exclusions should be used sparingly and carefully.
- Always validate the necessity of an exclusion before adding it.
- Use audit mode to test the impact of a rule before fully enforcing it.
- Remember, exclusions might weaken your security posture if not managed correctly.
""")

st.caption("[Learn more about ASR rule exclusions](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/configure-attack-surface-reduction?view=o365-worldwide#exclude-files-and-folders-from-asr-rules)")

st.subheader("Reviewing and Managing Exclusions")

st.write("""
You can review and manage your existing exclusions using the `Get-MpPreference` cmdlet in PowerShell. This will list all current exclusions set on your system.
""")

st.code("""
Get-MpPreference | Select-Object AttackSurfaceReductionOnlyExclusions
""", language="powershell")

st.write("""
This command returns a list of all paths that are currently excluded from ASR rules.
""")

st.code("""
Get-MpPreference | Select-Object AttackSurfaceReductionRules_RuleSpecificExclusions
""", language="powershell")

st.write("""
This command returns a list of all paths that are currently excluded from specific ASR rules.
""")

st.header("Examples of Exclusion Paths")

st.write("""
Understanding how to correctly format exclusion paths is key to ensuring that ASR rules function as intended. Here are some examples to illustrate how to use wildcards, environment variables, and other variations in defining exclusion paths.
""")

st.subheader("Using Wildcards in Paths")

st.write("""
Wildcards like `*` and `?` can be used to create flexible exclusion paths. Here are some examples:
""")

st.markdown("""
- `C:\\Program Files\\MyApp\\*` : Excludes all files in the 'MyApp' folder.
- `C:\\Data\\*\\config.xml` : Excludes 'config.xml' in any subfolder under the 'Data' folder.
- `C:\\Users\\*\\Documents\\*.docx` : Excludes all '.docx' files in the 'Documents' folder of any user.
- `C:\\Temp\\test?.log` : Excludes files like 'test1.log', 'test2.log', etc., in the 'Temp' folder.
""")

st.subheader("Using Environment Variables in Paths")

st.write("""
Environment variables can be used to represent system paths. Examples include:
""")

st.markdown("""
- `%ProgramFiles%\\MyApp\\app.exe` : Excludes 'app.exe' in the 'MyApp' folder within the Program Files directory.
- `%APPDATA%\\*` : Excludes all files and folders in the Application Data folder for the current user.
- `%SystemRoot%\\Temp\\*` : Excludes all files in the Temp folder located in the system root directory.
""")

st.subheader("Combining Wildcards and Environment Variables")

st.write("""
You can combine wildcards and environment variables for more complex exclusions. For example:
""")

st.markdown("""
- `%ProgramData%\\*\\temp\\*.tmp` : Excludes all '.tmp' files in any 'temp' folder under the Program Data directory.
""")

st.subheader("Things to Remember")

st.write("""
- Be cautious when using wildcards as they can potentially exclude more than intended.
- Verify the correct functioning of exclusions in audit mode before applying them.
- Regularly review your exclusion lists to ensure they are up-to-date.
""")

st.caption("[Detailed guidelines on using wildcards and environment variables](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/configure-extension-file-exclusions-microsoft-defender-antivirus?view=o365-worldwide)")

st.header("Conclusion and Additional Resources")
st.write("""
ASR is a powerful tool in the arsenal of Windows Defender, helping to keep systems safe from a variety of attacks.
For more detailed information and guidance, refer to the official Microsoft documentation.
""")
st.markdown("[Microsoft's Official ASR Documentation](https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-atp/attack-surface-reduction)")
st.markdown("[MICROSOFT DEFENDER ANTIVIRUS ATTACK SURFACE REDUCTION RULES BYPASSES](https://thalpius.com/2020/11/02/microsoft-defender-antivirus-attack-surface-reduction-rules-bypasses/)")
st.markdown("[Windows Defender Exploit Guard ASR Rules for Office](https://www.darkoperator.com/blog/2017/11/11/windows-defender-exploit-guard-asr-rules-for-office)")
st.markdown("[Windows Defender Exploit Guard ASR Obfuscated Script Rule](https://www.darkoperator.com/blog/2017/11/8/windows-defender-exploit-guard-asr-obfuscated-script-rule)")
st.markdown("[infosecn1nja GIST](https://gist.github.com/infosecn1nja/24a733c5b3f0e5a8b6f0ca2cf75967e3)")