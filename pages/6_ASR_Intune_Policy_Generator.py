import streamlit as st
import json
from datetime import datetime
from asr import intune_asr_rules, asr_rule_descriptions
import requests
import logging
import msal
import uuid
import pandas as pd

logging.basicConfig(level=logging.INFO)

st.set_page_config(page_title="ASR Intune Policy Generator", layout="wide")

st.title("🛡️ ASR Intune Policy Generator")
st.markdown("### Generate and Deploy Attack Surface Reduction!")


if "messages" not in st.session_state:
    st.session_state.messages = []


def add_message(message, type="info"):
    st.session_state.messages.append({"message": message, "type": type})

for msg in st.session_state.messages:
    if msg["type"] == "success":
        st.success(msg["message"])
    elif msg["type"] == "error":
        st.error(msg["message"])
    else:
        st.info(msg["message"])

with st.spinner("🔄 Loading configuration..."):

    pass

with st.expander("Azure AD App Registration Details", expanded=True):
    client_id = st.text_input("Client ID", value='your-client-id-here')
    client_secret = st.text_input("Client Secret", value='your-client-secret-here', type="password")
    tenant_id = st.text_input("Tenant ID", value='your-tenant-id-here')
    st.info("""
    **Required Permissions:**
    - `DeviceManagementConfiguration.ReadWrite.All`
    - `DeviceManagementManagedDevices.ReadWrite.All`
    """)

graph_api_endpoint = 'https://graph.microsoft.com/beta'

def get_access_token():
    authority = f'https://login.microsoftonline.com/{tenant_id}'
    app = msal.ConfidentialClientApplication(
        client_id,
        authority=authority,
        client_credential=client_secret
    )
    result = app.acquire_token_for_client(scopes=["https://graph.microsoft.com/.default"])
    if "access_token" in result:
        logging.info("Access token obtained successfully.")
        return result['access_token']
    else:
        error_message = f"Could not acquire token: {json.dumps(result, indent=2)}"
        st.error(error_message)
        logging.error(error_message)
        return None

def deploy_policy(policy_json):
    token = get_access_token()
    if not token:
        st.error("Failed to obtain access token.")
        logging.error("Failed to obtain access token.")
        return False, "Failed to obtain access token"
    
    headers = {
        'Authorization': f'Bearer {token}',
        'Content-Type': 'application/json'
    }
    
    create_url = f"{graph_api_endpoint}/deviceManagement/configurationPolicies"
    try:
        logging.info(f"Sending policy creation request to {create_url}")
        response = requests.post(create_url, headers=headers, json=policy_json)
        response.raise_for_status()
        policy_id = response.json().get('id')
        logging.info(f"Policy created with ID: {policy_id}")
        return True, policy_id
    except requests.exceptions.RequestException as e:
        if e.response is not None:
            error_message = e.response.json()
            logging.error(f"Failed to create policy: {error_message}")
            st.error(f"Failed to create policy: {error_message}")
        else:
            logging.error(f"Failed to create policy: {str(e)}")
            st.error(f"Failed to create policy: {str(e)}")
        return False, str(e)

def delete_policy(policy_id):
    """Delete an ASR policy from Intune"""
    try:
        token = get_access_token()
        if not token:
            st.error("Failed to get access token")
            return False
            
        url = f"https://graph.microsoft.com/beta/deviceManagement/configurationPolicies/{policy_id}"
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        }
        
        response = requests.delete(url, headers=headers)
        if response.status_code == 204:
            return True
        else:
            st.error(f"Failed to delete policy: {response.status_code}")
            return False
            
    except Exception as e:
        st.error(f"Error deleting policy: {str(e)}")
        return False

def list_policies():
    """List all ASR policies and their contents from Intune"""
    try:
        token = get_access_token()
        if not token:
            st.error("Failed to get access token")
            return

        url = "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies"
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        }

        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            policies = response.json().get('value', [])
            
            asr_policies = [p for p in policies if "Attack Surface Reduction" in p.get('name', '')]
            
            if not asr_policies:
                st.info("No ASR policies found")
                return
                
            for policy in asr_policies:
                with st.expander(f"📋 {policy['name']} ({policy['id']})"):
                    st.write("**Description:**", policy.get('description', 'No description'))
                    st.write("**Current Rules Configuration:**")
                    settings_url = f"{url}/{policy['id']}/settings"
                    settings_response = requests.get(settings_url, headers=headers)
                    
                    if settings_response.status_code == 200:
                        settings = settings_response.json().get('value', [])
                        
                        for setting in settings:
                            if 'settingInstance' in setting:
                                instance = setting['settingInstance']
                                if 'groupSettingCollectionValue' in instance:
                                    for group in instance['groupSettingCollectionValue']:
                                        for child in group.get('children', []):
                                            rule_id = child.get('settingDefinitionId', '')
                                            rule_value = child.get('choiceSettingValue', {}).get('value', '')
                                            
                                            rule_name = next((name for name, info in intune_asr_rules.items() 
                                                            if info['settingDefinitionId'] == rule_id), rule_id)
                                            mode = rule_value.split('_')[-1] if '_' in rule_value else rule_value
                                            
                                            st.write(f"- {rule_name}: **{mode}**")
                    else:
                        st.error(f"Failed to fetch policy settings: {settings_response.status_code}")
                        
        else:
            st.error(f"Failed to list policies: {response.status_code}")
            
    except Exception as e:
        st.error(f"Error listing policies: {str(e)}")

user_inputs = {}

st.write("## 📦 Configuration")
col1, col2 = st.columns([3, 1])

with col1:
    enable_all = st.selectbox("Enable All As", ["", "Audit", "Block", "Warn", "Off"], 
                             key="enable_all")
    
with col2:
    st.info("Quick set all rules to the same mode")

for rule_name, rule_info in intune_asr_rules.items():
    with st.expander(f"📌 {rule_name}", expanded=False):
        st.info(asr_rule_descriptions[rule_name], icon="ℹ️")
        
        mode = st.selectbox("Select Mode", ["Audit", "Block", "Warn", "Off"], 
                            key=f"mode_{rule_info['settingDefinitionId']}",
                            index=["Audit", "Block", "Warn", "Off"].index(enable_all) if enable_all else 0)
        st.write(f"**Current Mode:** {mode}")
    
    user_inputs[rule_info['settingDefinitionId']] = {"mode": mode.lower()}

policy_name = st.text_input("Policy Name", value="Attack Surface Reduction Rules", 
                           help="Enter a custom name for your policy",
                           key="policy_name_input")

policy_description = st.text_area(
    "Policy Description",
    value="ASR Rules Category",
    help="Enter a description for your policy",
    key="policy_description_input"
)

tab1, tab2 = st.tabs(["Deploy via Intune", "Manual Import"])

with tab1:
    st.markdown("### 🚀 Deploy via Intune")
    if st.button("Generate Intune Policy", key="generate_policy_api"):
        with st.spinner("Generating policy..."):
            policy = {
                "description": policy_description,
                "name": policy_name,
                "platforms": "windows10",
                "technologies": "mdm",
                "roleScopeTagIds": ["0"],
                "settings": [
                    {
                        "id": "0",
                        "settingInstance": {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationGroupSettingCollectionInstance",
                            "settingDefinitionId": "device_vendor_msft_policy_config_defender_attacksurfacereductionrules",
                            "groupSettingCollectionValue": [
                                {
                                    "children": [
                                        {
                                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                                            "settingDefinitionId": rule_info['settingDefinitionId'],
                                            "choiceSettingValue": {
                                                "value": f"{rule_info['value_prefix']}_{user_inputs[rule_info['settingDefinitionId']]['mode']}"
                                            }
                                        } for rule_name, rule_info in intune_asr_rules.items()
                                    ]
                                }
                            ]
                        }
                    }
                ]
            }
            st.success("✅ Policy generated successfully!")
            st.json(policy)
            st.session_state.generated_policy = policy
    
    if st.button("🚀 Deploy Policy", key="deploy_policy_api"):
        if not client_id or not client_secret or not tenant_id:
            st.error("⚠️ Please fill in all Azure AD credentials before deploying")
        elif 'generated_policy' not in st.session_state:
            st.warning("Please generate a policy first.")
        else:
            with st.spinner("Deploying policy..."):
                success, result = deploy_policy(st.session_state.generated_policy)
                if success:
                    st.success(f"Policy deployed successfully! Policy ID: {result}")
                    st.markdown("[View the configuration in Intune](https://intune.microsoft.com/#view/Microsoft_Intune_DeviceSettings/DevicesMenu/~/configuration)")
                else:
                    st.error(f"Failed to deploy policy: {result}")
    
with tab2:
    st.markdown("### ℹ️ How to Import Manually")
    st.markdown("""
    1. Choose 'Enable All' to set all rules at once
    2. Or expand each rule to set individually  
    3. Click 'Generate Intune Policy' when done
    4. Download the JSON file
    5. Import the file into your Intune portal
    """)
    
    if st.button("Generate Intune Policy", key="generate_policy_manual"):
        with st.spinner("Generating policy..."):
            policy = {
                "description": "ASR Rules Category",
                "name": "Attack Surface Reduction Rules",
                "platforms": "windows10",
                "technologies": "mdm",
                "roleScopeTagIds": ["0"],
                "settings": [
                    {
                        "id": "0",
                        "settingInstance": {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationGroupSettingCollectionInstance",
                            "settingDefinitionId": "device_vendor_msft_policy_config_defender_attacksurfacereductionrules",
                            "groupSettingCollectionValue": [
                                {
                                    "children": [
                                        {
                                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                                            "settingDefinitionId": rule_info['settingDefinitionId'],
                                            "choiceSettingValue": {
                                                "value": f"{rule_info['value_prefix']}_{user_inputs[rule_info['settingDefinitionId']]['mode']}"
                                            }
                                        } for rule_name, rule_info in intune_asr_rules.items()
                                    ]
                                }
                            ]
                        }
                    }
                ]
            }
            st.success("✅ Policy generated successfully!")
            st.json(policy)
            st.session_state.generated_policy = policy
            st.download_button(
                label="📥 Download Policy JSON",
                data=json.dumps(policy, indent=2),
                file_name="asr_policy.json",
                mime="application/json"
            )

st.sidebar.image("assets/logo.png", width=300)
st.sidebar.markdown("## About")
st.sidebar.info("This helps you generate Attack Surface Reduction (ASR) rules for Microsoft Intune. Configure your rules and download the policy JSON file or Deploy the policy to Intune directly.")

col1, col2 = st.columns([2, 1])

with col1:
    st.write("## 🔧 Review Policies Deployed")

if st.button("📋 List Intune Policies"):
    with st.spinner("Retrieving policies..."):
        list_policies()

st.write("## 📊 Current Configuration Preview")
preview_data = {}
for rule_name, rule_info in intune_asr_rules.items():
    preview_data[rule_name] = user_inputs[rule_info['settingDefinitionId']]['mode']
st.dataframe(pd.DataFrame.from_dict(preview_data, orient='index', columns=['Mode']))

def validate_credentials():
    if not client_id or not client_secret or not tenant_id:
        st.error("⚠️ Please fill in all Azure AD credentials before deploying")
        return False
    return True

if st.sidebar.button("🔄 Reset All Settings"):
    for key in st.session_state.keys():
        del st.session_state[key]
    st.rerun()

st.sidebar.markdown("""
### 📚 Resources
- [ASR Rules Documentation](https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-atp/attack-surface-reduction)
- [Intune Configuration Guide](https://docs.microsoft.com/en-us/mem/intune/protect/endpoint-security-asr-profile-settings)
""")
