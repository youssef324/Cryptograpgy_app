# Cryptography App 🔐  
*A Python GUI toolkit featuring 6 classic encryption algorithms with double-layer security and dark mode.*  

![Python](https://img.shields.io/badge/Python-3.8%2B-blue)  
![License](https://img.shields.io/badge/License-MIT-green)  

## Features ✨  
- Caesar, Vigenère, Playfair, Rail Fence, Row-Column, Mono-alphabetic ciphers  
- Double encryption (combine any two ciphers)  
- Dark/light mode, random key generator, summary panel  
System Requirements
Python 3.8+

pip package manager

Installation
1. Clone the Repository
bash
git clone https://github.com/youssef324/Cryptograpgy_app.git
cd Cryptograpgy_app
2. Install Dependencies
bash
pip install -r requirements.txt
The requirements.txt should contain:

tk
ttkthemes
pyperclip
File Structure
Cryptograpgy_app/
├── cipher_app.py          # Main application file
├── ciphers/              # Cipher implementations
│   ├── caesar.py
│   ├── vigenere.py
│   ├── playfair.py
│   ├── railfence.py
│   ├── rowcolumn.py
│   └── monoalphabetic.py
├── assets/               # Graphical assets
│   ├── icon.ico
│   └── logo.png
├── tests/                # Unit tests
│   ├── test_caesar.py
│   └── ...
└── README.md
Running the Application
bash
python cipher_app.py
Backup and Recovery
1. Creating a Backup
bash
# Create a zip archive of the project
zip -r cryptography_app_backup.zip Cryptograpgy_app/
2. Restoring from Backup
bash
unzip cryptography_app_backup.zip
cd Cryptograpgy_app
pip install -r requirements.txt
python cipher_app.py
Database Recovery (if applicable)
If the app uses a database:

bash
# Backup SQLite database
cp app.db app_backup.db

# Restore database
cp app_backup.db app.db
Troubleshooting
Common Issues
Missing Dependencies:

bash
pip install --upgrade -r requirements.txt
GUI Not Loading:

Verify Python Tkinter is installed:

bash
python -m tkinter
On Linux, install Tkinter:

bash
sudo apt-get install python3-tk
Application Crashes:

Check error logs

Run in debug mode:

bash
python -m pdb cipher_app.py
Maintenance
To keep the application updated:

bash
git pull origin main
pip install --upgrade -r requirements.txt
Deployment Options
1. As Executable (PyInstaller)
bash
pip install pyinstaller
pyinstaller --onefile --windowed cipher_app.py
2. Docker Container
dockerfile
FROM python:3.8
COPY . /app
WORKDIR /app
RUN pip install -r requirements.txt
CMD ["python", "cipher_app.py"]
Build and run:

bash
docker build -t cryptography-app .
docker run -it cryptography-app
Support
For additional help:
Contact maintainer at youssef324

