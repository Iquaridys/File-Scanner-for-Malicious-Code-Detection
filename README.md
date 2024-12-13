PHP/JS File Scanner for Malicious Code Detection

This is a simple project created for learning and experimentation. The goal of this project is to build a PHP script that scans various file types (PHP, JavaScript, TXT, JSON, and CSS) for potentially malicious code, suspicious functions, and exfiltration patterns.
Features

    Scans PHP, JS, TXT, JSON, and CSS files for harmful functions and patterns.
    Detects suspicious PHP functions like eval, exec, base64_decode, and more.
    Identifies common JavaScript exfiltration methods such as XMLHttpRequest, fetch, and eval.
    Recognizes base64 encoding, hexadecimal patterns, and malicious URLs.
    Generates an HTML report listing detected issues and suspicious code.

Installation

    Clone or download this repository to your local machine.

    Ensure you have PHP installed on your system.

    Modify the directory path in the PHP script to point to the directory you want to scan.

    Run the script using the command:

    php scan.php

    After the scan, an HTML report (scan_report.html) will be generated with the results.

Usage

    This tool can be useful for identifying potential vulnerabilities or suspicious code in your project files.
    The report highlights files with detected issues, and you can review the details directly in the generated HTML file.

Contributing

This project is for learning and testing purposes, so feel free to fork or contribute with improvements. If you find bugs or have ideas for new features, feel free to create an issue or pull request.
License

This project is open-source and available under the MIT License.

Let me know if you'd like to add or modify anything!
