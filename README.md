# ASRGEN

> _now BETA_

Access ASRGEN here on https://asrgen.streamlit.app/

### Project Overview

This repository contains code and resources related to Attack Surface Reduction (ASR) rules in Windows Defender. The primary goal of this project is to provide a comprehensive understanding of ASR rules, their configuration, and their impact on system security.

### Disclaimer

The content in this repository is intended for research and educational purposes only. It should be used responsibly and ethically. Any scripts or code that simulate potentially harmful actions are provided for the purpose of understanding and mitigating security threats with ASR. They should only be run in a controlled, secure environment for testing or educational purposes.

### Getting Started

1. Clone the repository to your local machine.
2. Ensure you have the necessary dependencies installed. This project primarily uses Python and PowerShell.
3. Navigate through the codebase and familiarize yourself with the structure and content.

### Code Structure

The project consists of the following key components:

- 1️⃣ ASR Configurator 🛠️: A tool for configuring ASR rules and generating the corresponding PowerShell commands. 📝

- 2️⃣ ASR Essentials 📚: A guide to the basics of ASR, including how to use ASR on the command line, how to list ASR rules, and how to understand ASR event codes. 🤓

- 3️⃣ ASR Atomic Testing 🧪: A collection of scripts for testing the effectiveness of ASR rules. 🔬

- 4️⃣ ASR PwSh Group Policy Generator 🛠️: A tool for generating Group Policy Objects (GPO) with PowerShell. 📝

- 5️⃣ ASR .pol File Reader 📖: A tool for reading and displaying the contents of GPO .pol files. 📝

- 6️⃣ ASR Intune Policy Generator 🔄: A web-based tool for creating and deploying ASR rules directly to Microsoft Intune. Features include:
  - Interactive rule configuration
  - Direct deployment to Intune
  - JSON policy export
  - Current configuration preview
  - Policy listing and management

### Features

- PowerShell-based ASR rule management
- Group Policy Object generation
- .pol file analysis
- Intune integration for cloud-based deployment
- Interactive web interface
- Atomic testing capabilities
- Comprehensive documentation

### Required Permissions for Intune Integration

To use the Intune Policy Generator, your Azure AD app registration needs:
- `DeviceManagementConfiguration.ReadWrite.All`
- `DeviceManagementManagedDevices.ReadWrite.All`

### Contributing

We welcome contributions to this project. If you have a suggestion, bug report, or want to add to the codebase, please open an issue or submit a pull request.

### License

This project is licensed under the terms of the Apache license.