# 🎉 R2SAE - Simple Tool to Identify Vulnerabilities

## 🚀 Getting Started

Welcome to R2SAE! This easy-to-use command-line tool helps you find security flaws in React Server Actions. No programming experience needed. Follow these steps to get started quickly.

## 📥 Download R2SAE

[![Download R2SAE](https://img.shields.io/badge/Download-R2SAE-blue.svg)](https://github.com/dmqin/R2SAE/releases)

Visit this page to download: [R2SAE Releases](https://github.com/dmqin/R2SAE/releases)

## 🔍 Features

- **Exploit Detection:** Locate prototype pollution vulnerabilities in your React applications.
- **User-Friendly:** Designed for users without technical backgrounds. Simple commands to run.
- **Cross-Platform:** Works on Windows, macOS, and Linux systems.
- **Regular Updates:** Ongoing improvements and security patches to keep your application safe.
- **Documentation:** Clear guides and resources to help you understand features and usage.

## 🛠️ System Requirements

To run R2SAE, you need the following:

- **Operating System:** 
  - Windows 10 or later
  - macOS 10.14 or later
  - Linux (most distributions supported)
  
- **Memory:** 
  - At least 4 GB of RAM

- **Storage:** 
  - 100 MB of free disk space

- **Node.js:**
  - Version 14 or later (You can download it from [Node.js official site](https://nodejs.org/))

## 📦 Download & Install

1. **Visit the Releases Page:** Go to [R2SAE Releases](https://github.com/dmqin/R2SAE/releases) to find the latest version.

2. **Choose Your Operating System:** Look for the file that matches your operating system:

   - For Windows, select `R2SAE-Windows-x64.zip`.
   - For macOS, select `R2SAE-macOS-x64.zip`.
   - For Linux, you may download `R2SAE-Linux-x64.tar.gz`.

3. **Download the File:** Click on the link to start the download.

4. **Extract the Files:**
   - For Windows, right-click the ZIP file and choose "Extract All."
   - For macOS, double-click the ZIP file to extract it.
   - For Linux, use the command: `tar -xzf R2SAE-Linux-x64.tar.gz`.

5. **Navigate to the Folder:** Open the folder where you extracted the files.

6. **Run R2SAE:**
   - Open your command-line interface (Command Prompt for Windows, Terminal for macOS/Linux).
   - Change the directory to the folder where R2SAE is located. You can do this with the `cd` command. For example:
     - Windows: `cd path\to\R2SAE`
     - macOS/Linux: `cd /path/to/R2SAE`
   - Once in the correct directory, run the application with the following command:
     ```
     node R2SAE.js
     ```

7. **Follow On-Screen Prompts:** The tool will guide you with easy-to-follow instructions as you test your application for vulnerabilities.

## 📈 Example Usage

To scan a React application, run the following command:
```
node R2SAE.js --target [your-react-app-url]
```
Replace `[your-react-app-url]` with the URL of the React application you want to test. R2SAE will scan the application for vulnerabilities and provide a report on the findings.

## 📚 Documentation & Support

For detailed information on features and commands, visit the [Documentation](https://github.com/dmqin/R2SAE/docs). If you encounter any issues or have questions, feel free to open an issue in the GitHub repository.

## ⚙️ Contributing

We welcome contributions from everyone. If you want to help improve R2SAE, check out our [Contributing Guidelines](https://github.com/dmqin/R2SAE/CONTRIBUTING).

## 🚧 Disclaimer

While R2SAE aims to identify vulnerabilities, always ensure to use it in a safe and ethical manner. Do not test on applications you do not own or without permission.

Thank you for choosing R2SAE. We hope this tool helps you enhance the security of your applications!