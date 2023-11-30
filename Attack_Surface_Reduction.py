import streamlit as st
from streamlit.components.v1 import html
from asr import html_code


# Set page title
st.set_page_config(page_title="ASRGEN", layout="wide")


# Page header
st.markdown("<h1 style='text-align: left;'>Attack Surface Reduction Generator</h1>", unsafe_allow_html=True)

col1, col2, col3 = st.columns([2,1,1])

with col1:
    st.write("""
    <b>Welcome to the Attack Surface Reduction (ASR) Generator.</b> 🎉 This project is a comprehensive suite of tools and resources designed to aid in understanding and configuring ASR rules in Microsoft Defender. 🛡️

    The ASR Generator is built with the aim of simplifying the process of managing ASR rules, making it more accessible and efficient for users of all levels. 🚀 It provides a user-friendly interface that allows you to easily navigate through the various components and features. 💻

    The project consists of the following key components:

    1️⃣ <a href="ASR_Configurator" target="_self">ASR Configurator</a> 🛠️: A tool for configuring ASR rules and generating the corresponding PowerShell commands. 📝

    2️⃣ <a href="ASR_Essentials" target="_self">ASR Essentials</a> 📚: A guide to the basics of ASR, including how to use ASR on the command line, how to list ASR rules, and how to understand ASR event codes. 🤓

    3️⃣ <a href="ASR_Atomic_Testing" target="_self">ASR Atomic Testing</a> 🧪: A collection of scripts for testing the effectiveness of ASR rules. 🔬
    
    4️⃣ <a href="ASR_PwSh_Group_Policy_Generator" target="_self">ASR PwSh Group Policy Generator</a> 🛠️: A tool for generating Group Policy Objects (GPO) with PowerShell. 📝
    
    5️⃣ <a href="ASR_Read_Pol_File" target="_self">ASR .pol File Reader</a> 📖: A tool for reading and displaying the contents of GPO .pol files. 📝

    The ASR Generator is an ongoing project, and we are constantly working to improve its features and capabilities. We welcome feedback and suggestions from our users to help us make this tool even better 🙌. 💡

    """, unsafe_allow_html=True)

with col2:
    st.markdown("""
    <iframe width="560" height="315" src="https://www.youtube.com/embed/BUZBGbzm1cE?si=ye9LOktWEDZRYIUL" title="YouTube video player" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share" allowfullscreen></iframe>
    """, unsafe_allow_html=True)


st.sidebar.image("assets/logo.png", width=300)

st.sidebar.markdown(html_code, unsafe_allow_html=True)

