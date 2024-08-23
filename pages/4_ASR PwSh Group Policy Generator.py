import streamlit as st
from asr import asr_rules, html_code

st.set_page_config(page_title="ASR PwSh", layout="wide")

# Initialize user inputs
user_inputs = {}

# App title and introduction
st.title("ASR PwSh Group Policy Object Generator")
st.markdown("This tool will help you create a new Group Policy Object (GPO) in the Group Policy Management Console (GPMC). Once the GPO is created, it can be further deployed as per your organization's requirements.")


# Add a checkbox and a select box at the top of the app
enable_all = st.checkbox("Enable All Rules")
if enable_all:
    enable_all_state = st.selectbox("Select state for all rules:", ["0 (Disabled)", "1 (Block)", "2 (Audit)"], key="enable_all_state")
    # If the checkbox is checked, set the state of all rules to the selected value
    for rule_id in asr_rules.values():
        user_inputs[rule_id] = int(enable_all_state[0])  # Get the first character (0, 1, or 2) as the state

# Iterating over each ASR rule to create an expander with options
for rule_name, rule_id in asr_rules.items():
    with st.expander(f"{rule_name} ({rule_id})"):
        # Check if the rule has already been set
        if rule_id not in user_inputs:
            state = st.radio("Select state for this rule:", ["0 (Disabled)", "1 (Block)", "2 (Audit)"], key=rule_id)
            user_inputs[rule_id] = int(state[0])  # Get the first character (0, 1, or 2) as the state

gpo_name = st.text_input("Enter the GPO Name", value="MyNewASRGPO", key="gpo_name_input")
# Initialize the PowerShell script
ps_script = ""

if st.button("Generate PowerShell Script"):  # Button to generate PowerShell script
    # Start of the PowerShell script
    ps_script = f"""# Create a new GPO
    $gpoName = "{gpo_name}"
    $gpo = New-GPO -Name $gpoName -Comment "GPO to configure ASR rules"

    # Define the registry path for ASR settings
    $asrRegPath = "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Windows Defender Exploit Guard\\ASR\\Rules"

    # ASR rule settings
    $asrRules = @{{\n"""

    # Adding each rule to the script
    for rule_id, state in user_inputs.items():
        # Include the rule only if the state is not "0 (Disabled)"
        if state != 0:
            # Get the rule name corresponding to the rule ID
            rule_name = [name for name, id in asr_rules.items() if id == rule_id][0]
            ps_script += f'    "{rule_id}" = {state};  # {rule_name}\n'

    # Closing the ASR rules PowerShell array
    ps_script += """}

    # Apply the ASR rule settings
    foreach ($rule in $asrRules.GetEnumerator()) {
        $regKey = "$asrRegPath\$($rule.Name)"
        Set-GPRegistryValue -Name $gpoName -Key $asrRegPath -ValueName $rule.Name -Type Dword -Value $rule.Value
    }

    # Link the GPO to an OU (optional)
    # Replace 'OU=MyOU,DC=example,DC=com' with the actual path to your OU
    # New-GPLink -Name $gpoName -Target "OU=Workstations,DC=sevenkingdoms,DC=local"
    """

st.code(ps_script, language='powershell')

st.warning("Please note that I have not tested this in production, but only a lab. Be sure to thoroughly test before implementing in production.", icon="⚠️")

st.sidebar.image("assets/logo.png", width=300)
st.sidebar.markdown(html_code, unsafe_allow_html=True)
