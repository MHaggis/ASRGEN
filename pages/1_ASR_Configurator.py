import streamlit as st
from streamlit.components.v1 import html
from asr import asr_rules, html_code

st.set_page_config(page_title="ASR Configurator", layout="wide")

st.title("Attack Surface Configurator")
st.markdown("This tool will help you configure the Attack Surface Reduction rules in Microsoft Defender for Endpoint.")
user_inputs = {}
mode = None
enable_all = st.checkbox("Enable All Rules")
if enable_all:
    global_mode = st.selectbox("Select mode for all rules:", ["Enabled", "Audit", "Warn"])

    # PowerShell equivalent action string
    ps_action = {"Enabled": "Enabled", "Audit": "AuditMode", "Warn": "Warn"}[global_mode]

    st.code("""
    $asrRuleIds = @{
        "56A863A9-875E-4185-98A7-B882C64B5CE5" = "Block abuse of exploited vulnerable signed drivers";
        "7674BA52-37EB-4A4F-A9A1-F0F9A1619A2C" = "Block Adobe Reader from creating child processes";
        "D4F940AB-401B-4EFC-AADC-AD5F3C50688A" = "Block all Office applications from creating child processes";
        "9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2" = "Block credential stealing from the Windows local security authority subsystem (lsass.exe)";
        "BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550" = "Block executable content from email client and webmail";
        "01443614-CD74-433A-B99E-2ECDC07BFC25" = "Block executable files from running unless they meet a prevalence, age, or trusted list criterion";
        "5BEB7EFE-FD9A-4556-801D-275E5FFC04CC" = "Block execution of potentially obfuscated scripts";
        "D3E037E1-3EB8-44C8-A917-57927947596D" = "Block JavaScript or VBScript from launching downloaded executable content";
        "3B576869-A4EC-4529-8536-B80A7769E899" = "Block Office applications from creating executable content";
        "75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84" = "Block Office applications from injecting code into other processes";
        "26190899-1602-49E8-8B27-EB1D0A1CE869" = "Block Office communication application from creating child processes";
        "E6DB77E5-3DF2-4CF1-B95A-636979351E5B" = "Block persistence through WMI event subscription";
        "D1E49AAC-8F56-4280-B9BA-993A6D77406C" = "Block process creations originating from PSExec and WMI commands";
        "B2B3F03D-6A65-4F7B-A9C7-1C7EF74A9BA4" = "Block untrusted and unsigned processes that run from USB";
        "92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B" = "Block Win32 API calls from Office macros";
        "C1DB55AB-C21A-4637-BB3F-A12568109D35" = "Use advanced protection against ransomware";
        "A8F5898E-1DC8-49A9-9878-85004B8A61E6" = "Block Webshell creation for Servers";
        "33DDEDF1-C6E0-47CB-833E-DE6133960387" = "Block rebooting machine in Safe Mode (preview)";
        "C0033C00-D16D-4114-A5A0-DC9B3A7D2CEB" = "Block use of copied or impersonated system tools (preview)";
    }
    foreach ($id in $asrRuleIds.Keys) {
        Add-MpPreference -AttackSurfaceReductionRules_Ids $id -AttackSurfaceReductionRules_Actions """ + ps_action + """
    }

    Write-Host "All specified ASR rules have been set to """ + ps_action + """."
    """, language="powershell")

for rule_name, rule_id in asr_rules.items():
    with st.expander(f"{rule_name} ({rule_id})"):
        col1, col2, col3, col4 = st.columns(4)

        with col1:
            enable = st.checkbox("Enable", key=f"enable_{rule_id}")

        with col2:
            disable = st.checkbox("Disable", key=f"disable_{rule_id}")

        with col3:
            mode = st.radio("Mode:", ["Block", "Audit", "Warn"], key=f"mode_{rule_id}")

        with col4:
            exclusion = st.text_input("Exclusions (Optional)", key=f"exclusion_{rule_id}")

        user_inputs[rule_id] = {'enable': enable, 'disable': disable, 'mode': mode, 'exclusion': exclusion}

        mode_colors = {
            "Audit": "orange",
            "Block": "red",
            "Warn": "blue"  
        }

        if enable:
            action_color = mode_colors.get(mode, "black") 
            action_text = f"<span style='color: {action_color};'>This will enable '{rule_name}' in {mode} Mode.</span>"
        elif disable:
            action_text = f"<span style='color: grey;'>This will disable '{rule_name}'.</span>"
        else:
            action_text = "Select an option to see the action."

        st.markdown(action_text, unsafe_allow_html=True)

if st.button("Generate Command"):
    commands = []
    mode_grouping = {"Block": [], "Audit": [], "Warn": [], "Disabled": []}
    exclusion_commands = []

    for rule_id, inputs in user_inputs.items():
        if inputs['enable'] and not inputs['disable']:
            mode_grouping[inputs['mode']].append(rule_id)
            if inputs['exclusion']:
                exclusion_command = f"Set-MpPreference -AttackSurfaceReductionOnlyExclusions -Exclusions {inputs['exclusion']}"
                exclusion_commands.append(exclusion_command)
                st.caption(f"Note: The exclusion will be applied to all rules. If you would like per-rule exclusions, use set-mppreference -AttackSurfaceReductionRules_Ids {rule_id} -AttackSurfaceReductionOnlyExclusions -Exclusions {inputs['exclusion']}")
        elif inputs['disable']:
            mode_grouping["Disabled"].append(rule_id)

    for mode, ids in mode_grouping.items():
        if ids:
            action_cmd = {"Block": "Enabled", "Audit": "AuditMode", "Warn": "Warn", "Disabled": "Disabled"}.get(mode)
            command = f"Set-MpPreference -AttackSurfaceReductionRules_Ids {','.join(ids)} -AttackSurfaceReductionRules_Actions {action_cmd}"
            commands.append(command)

    final_commands = commands + exclusion_commands

    if final_commands:
        st.text_area("PowerShell Commands:", "\n".join(final_commands), height=100)
        st.caption("To view the enabled rules, use the following command in PowerShell: Get-MpPreference | Select-Object AttackSurfaceReductionRules_Ids")
        st.caption("[Learn more about configuring file and folder exclusions](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/configure-extension-file-exclusions-microsoft-defender-antivirus?view=o365-worldwide)")

    else:
        st.error("Please select at least one rule and specify the action.")
        
st.sidebar.image("assets/logo.png", width=300)

st.sidebar.markdown(html_code, unsafe_allow_html=True)
