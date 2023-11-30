import streamlit as st
import registrypol
from asr import html_code

st.set_page_config(page_title="ASR Policy Reader", layout="wide")

def main():
    st.title("GPO .pol File Reader")
    st.markdown("This tool allows you to read and display the contents of a GPO .pol file. \
    It uses the registry.pol file from a GPO backup. After you upload a .pol file, \
    the tool will parse the file and display the key, value, type, size, and data for each entry.")
    file = st.file_uploader("Upload a GPO .pol file", type=['pol'])
    if file is not None:
        # Load the Registry.pol file
        policy = registrypol.load(file)

        # Display the parsed data
        for value in policy.values:
            st.write(f"Key: {value.key}")
            st.write(f"Value: {value.value}")
            st.write(f"Type: {value.type}")
            st.write(f"Size: {value.size}")
            st.write(f"Data: {value.data}")
            st.write("---")

if __name__ == "__main__":
    main()
    
st.sidebar.image("assets/logo.png", width=300)
st.sidebar.markdown(html_code, unsafe_allow_html=True)