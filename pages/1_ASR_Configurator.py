import streamlit as st
from streamlit.components.v1 import html
from datetime import datetime
from src import (
    ASR_RULES,
    PRESETS,
    get_categories,
    get_rules_by_category,
    check_conflicts,
    PSGenerator,
    simplify_config_for_display,
    ConfigManager
)
from asr import html_code

st.set_page_config(page_title="ASR Configurator", layout="wide")

st.title("⚙️ Attack Surface Reduction Configurator")
st.markdown("Configure ASR rules with an improved, searchable interface. Save configurations for reuse.")

# Initialize session state
if "config" not in st.session_state:
    st.session_state.config = {}
if "search_query" not in st.session_state:
    st.session_state.search_query = ""
if "selected_category" not in st.session_state:
    st.session_state.selected_category = "All"


def render_rule_editor(rule_id: str, rule, config: dict):
    """Render a single rule editor"""
    is_selected = rule_id in config
    
    with st.expander(
        f"{'✅' if is_selected else '⬜'} {rule.name}",
        expanded=False
    ):
        col1, col2, col3, col4 = st.columns([1, 1, 1, 2])
        
        with col1:
            include = st.checkbox(
                "Enable",
                value=is_selected,
                key=f"enable_{rule_id}"
            )
        
        if include:
            with col2:
                mode = st.selectbox(
                    "Mode:",
                    ["Block", "Audit", "Warn"],
                    index=0,
                    key=f"mode_{rule_id}"
                )
        else:
            mode = "Block"
        
        with col3:
            if include:
                with st.popover("🛑 Add Exclusion"):
                    exclusion_input = st.text_area(
                        "Paths to exclude (one per line):",
                        value="\n".join(config.get(rule_id, {}).get("exclusions", [])),
                        key=f"exclusion_{rule_id}",
                        height=100
                    )
                    exclusions = [p.strip() for p in exclusion_input.split("\n") if p.strip()]
            else:
                exclusions = []
        
        with col4:
            if include:
                status_color = {"Block": "🔴", "Audit": "🟠", "Warn": "🟡"}.get(mode, "⬜")
                st.success(f"{status_color} **{mode} Mode**")
            else:
                st.caption("Not configured")
        
        # Show rule description
        st.divider()
        st.caption(rule.description)
        
        # Update config
        if include:
            config[rule_id] = {"mode": mode, "exclusions": exclusions}
        elif rule_id in config:
            del config[rule_id]

# Sidebar
with st.sidebar:
    st.image("assets/logo.png", width=300)
    st.markdown(html_code, unsafe_allow_html=True)
    
    st.divider()
    st.subheader("🎯 Quick Presets")
    
    preset_choice = st.selectbox("Load a preset:", ["None"] + list(PRESETS.keys()))
    
    if preset_choice != "None":
        preset = PRESETS[preset_choice]
        st.info(f"**{preset_choice}**\n\n{preset['description']}")
        
        if st.button(f"Load {preset_choice}"):
            st.session_state.config = {
                rule_id: {"mode": preset["mode"], "exclusions": []}
                for rule_id in preset["rules"]
            }
            st.success("✅ Preset loaded! Configure exclusions below if needed.")
            st.rerun()
    
    st.divider()
    st.subheader("💾 Configuration Management")
    
    # Save current config
    if st.button("💾 Save Current Configuration"):
        st.session_state.show_save_dialog = True
    
    if st.session_state.get("show_save_dialog", False):
        with st.form("save_config_form"):
            config_name = st.text_input("Configuration Name", value="My ASR Config")
            config_desc = st.text_area("Description (optional)", height=80)
            
            if st.form_submit_button("Save"):
                if config_name and st.session_state.config:
                    filepath = ConfigManager.save_config(
                        st.session_state.config,
                        config_name,
                        config_desc
                    )
                    st.success(f"✅ Saved: {config_name}")
                    st.session_state.show_save_dialog = False
                    st.rerun()
                else:
                    st.error("Please name the config and select at least one rule.")
    
    # Load saved configs
    st.subheader("📂 Saved Configurations")
    saved_configs = ConfigManager.list_configs()
    
    if saved_configs:
        selected_config = st.selectbox(
            "Load configuration:",
            [None] + [cfg["name"] for cfg in saved_configs],
            format_func=lambda x: x if x else "Select..."
        )
        
        if selected_config:
            config_data = next((cfg for cfg in saved_configs if cfg["name"] == selected_config), None)
            if config_data:
                col1, col2 = st.columns(2)
                with col1:
                    if st.button("📥 Load"):
                        loaded_config = ConfigManager.load_config(config_data["path"])
                        if loaded_config:
                            st.session_state.config = loaded_config
                            st.success(f"✅ Loaded: {selected_config}")
                            st.rerun()
                with col2:
                    if st.button("🗑️ Delete"):
                        if ConfigManager.delete_config(config_data["path"]):
                            st.success(f"Deleted: {selected_config}")
                            st.rerun()
    else:
        st.caption("No saved configurations yet.")

# Main content
st.divider()

# Search and filter controls
col1, col2, col3 = st.columns([2, 1, 1])

with col1:
    search_query = st.text_input("🔍 Search rules by name or description:", key="search_input")

with col2:
    categories = ["All"] + get_categories()
    selected_category = st.selectbox("📁 Filter by category:", categories)

with col3:
    st.write("")  # Spacer
    if st.button("Clear All Selections"):
        st.session_state.config = {}
        st.rerun()

st.divider()

# Filter rules based on search and category
filtered_rules = {}

for rule_id, rule in ASR_RULES.items():
    # Category filter
    if selected_category != "All" and rule.category != selected_category:
        continue
    
    # Search filter
    if search_query:
        query_lower = search_query.lower()
        if not (query_lower in rule.name.lower() or query_lower in rule.description.lower()):
            continue
    
    filtered_rules[rule_id] = rule

# Show filtering status
if search_query or selected_category != "All":
    st.caption(f"📊 Showing {len(filtered_rules)} of {len(ASR_RULES)} rules")

# Check for conflicts
current_rule_ids = list(st.session_state.config.keys())
conflicts = check_conflicts(current_rule_ids)

if conflicts:
    with st.warning("⚠️ **Rule Conflicts Detected**"):
        for conflict in conflicts:
            st.write(f"• {conflict['message']}")

# Display rules
if filtered_rules:
    # Tabs for different categories if no filter is applied
    if selected_category == "All" and not search_query:
        category_list = get_categories()
        tabs = st.tabs(category_list)
        
        for tab, category in zip(tabs, category_list):
            with tab:
                category_rules = get_rules_by_category(category)
                
                for rule_id, rule in category_rules.items():
                    render_rule_editor(rule_id, rule, st.session_state.config)
    else:
        # Single view for filtered rules
        for rule_id, rule in filtered_rules.items():
            render_rule_editor(rule_id, rule, st.session_state.config)
else:
    st.info("No rules match your search criteria.")

st.divider()

# Configuration preview and generation
st.subheader("📋 Preview & Generate")

if st.session_state.config:
    # Show summary
    summary = simplify_config_for_display(st.session_state.config)
    
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("🔒 Block", len(summary["block"]))
    with col2:
        st.metric("👀 Audit", len(summary["audit"]))
    with col3:
        st.metric("⚠️ Warn", len(summary["warn"]))
    with col4:
        st.metric("❌ Disabled", len(summary["disabled"]))
    
    # Display selected rules
    if summary["block"]:
        with st.expander("🔒 Rules in Block Mode"):
            for rule_name in summary["block"]:
                st.write(f"• {rule_name}")
    
    if summary["audit"]:
        with st.expander("👀 Rules in Audit Mode"):
            for rule_name in summary["audit"]:
                st.write(f"• {rule_name}")
    
    if summary["warn"]:
        with st.expander("⚠️ Rules in Warn Mode"):
            for rule_name in summary["warn"]:
                st.write(f"• {rule_name}")
    
    if summary["disabled"]:
        with st.expander("❌ Disabled Rules"):
            for rule_name in summary["disabled"]:
                st.write(f"• {rule_name}")
    
    if summary["exclusions"]:
        with st.expander("🛑 Exclusions"):
            for rule_name, exclusions in summary["exclusions"].items():
                st.write(f"**{rule_name}:**")
                for exc in exclusions:
                    st.code(exc, language="text")
    
    # Generate PowerShell
    st.subheader("🚀 Generate PowerShell Script")
    
    tab1, tab2, tab3 = st.tabs(["Full Script", "Commands Only", "JSON Export"])
    
    with tab1:
        ps_script = PSGenerator.generate_full_script(st.session_state.config)
        st.code(ps_script, language="powershell")
        st.download_button(
            label="📥 Download PowerShell Script",
            data=ps_script,
            file_name=f"ASR_Config_{datetime.now().strftime('%Y%m%d_%H%M%S')}.ps1",
            mime="text/plain"
        )
    
    with tab2:
        main_commands, exclusion_commands = PSGenerator.generate_batch_commands(st.session_state.config)
        all_commands = main_commands + exclusion_commands
        commands_text = "\n".join(all_commands)
        st.code(commands_text, language="powershell")
    
    with tab3:
        json_export = ConfigManager.export_config_as_json(st.session_state.config)
        st.code(json_export, language="json")
        st.download_button(
            label="📥 Download Configuration (JSON)",
            data=json_export,
            file_name=f"ASR_Config_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
            mime="application/json"
        )
    
    # Verification command
    st.info(f"**Verification Command:**\n```\n{PSGenerator.generate_view_command()}\n```")

else:
    st.info("👈 Select rules above to generate PowerShell commands.")
