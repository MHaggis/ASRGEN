import streamlit as st

st.set_page_config(page_title="ASR Configurator", layout="wide")

asr_rules = {
    "Block abuse of exploited vulnerable signed drivers": "56a863a9-875e-4185-98a7-b882c64b5ce5",
    "Block Adobe Reader from creating child processes": "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c",
    "Block all Office applications from creating child processes": "D4F940AB-401B-4EFC-AADC-AD5F3C50688A",
    "Block credential stealing from the Windows local security authority subsystem (lsass.exe)": "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2",
    "Block executable content from email client and webmail": "BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550",
    "Block executable files from running unless they meet a prevalence, age, or trusted list criterion": "01443614-cd74-433a-b99e-2ecdc07bfc25",
    "Block execution of potentially obfuscated scripts": "5BEB7EFE-FD9A-4556-801D-275E5FFC04CC",
    "Block JavaScript or VBScript from launching downloaded executable content": "D3E037E1-3EB8-44C8-A917-57927947596D",
    "Block Office applications from creating executable content": "3B576869-A4EC-4529-8536-B80A7769E899",
    "Block Office applications from injecting code into other processes": "75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84",
    "Block Office communication application from creating child processes": "26190899-1602-49e8-8b27-eb1d0a1ce869",
    "Block persistence through WMI event subscription": "e6db77e5-3df2-4cf1-b95a-636979351e5b",
    "Block process creations originating from PSExec and WMI commands": "d1e49aac-8f56-4280-b9ba-993a6d77406c",
    "Block untrusted and unsigned processes that run from USB": "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4",
    "Block Win32 API calls from Office macros": "92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B",
    "Use advanced protection against ransomware": "c1db55ab-c21a-4637-bb3f-a12568109d35"
}

st.title("Attack Surface Configurator")
st.markdown("This tool will help you configure the Attack Surface Reduction rules in Microsoft Defender for Endpoint.")
user_inputs = {}
mode = None
enable_all = st.checkbox("Enable All Rules")
if enable_all:
    global_mode = st.selectbox("Select mode for all rules:", ["Block", "Audit", "Warn"])

for rule_name, rule_id in asr_rules.items():
    with st.expander(f"{rule_name} ({rule_id})"):
        col1, col2, col3, col4 = st.columns(4)

        with col1:
            enable = st.checkbox("Enable", key=f"enable_{rule_id}", value=enable_all)

        with col2:
            disable = st.checkbox("Disable", key=f"disable_{rule_id}")

        with col3:
            if enable_all:
                st.radio("Mode:", ["Block", "Audit", "Warn"], key=f"mode_{rule_id}", index=["Block", "Audit", "Warn"].index(global_mode))
            else:
                mode = st.radio("Mode:", ["Block", "Audit", "Warn"], key=f"mode_{rule_id}")

        with col4:
            exclusion = st.text_input("Exclusions (Optional)", key=f"exclusion_{rule_id}")

        user_inputs[rule_id] = {'enable': enable, 'disable': disable, 'mode': global_mode if enable_all else mode, 'exclusion': exclusion}

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
                exclusion_command = f"Set-MpPreference -AddAttackSurfaceReductionRuleExclusions -AttackSurfaceReductionRules_Ids {rule_id} -Exclusions {inputs['exclusion']}"
                exclusion_commands.append(exclusion_command)
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