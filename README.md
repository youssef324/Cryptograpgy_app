# Cryptographic Toolkit 🔐

## 📜 Complete Technical Documentation
**Version**: 1.0  
**License**: MIT  
**Python**: 3.8+  

## 🧩 Core Features
### Encryption Algorithms
1. **Caesar Cipher** - Shift-based substitution
   - Key: Integer (1-25)
   - Example: Key=3, "HELLO" → "KHOOR"

2. **Vigenère Cipher** - Polyalphabetic substitution
   - Key: Alphabetic string
   - Example: Key="KEY", "ATTACK" → "KXKXKX"

3. **Playfair Cipher** - Digraph substitution
   - Key: 5x5 matrix keyword
   - Example: Key="MONARCHY", "HELLO" → "CFSUPM"

4. **Rail Fence Cipher** - Transposition
   - Key: Number of rails (2-10)
   - Example: Key=3, "WEAREDISCOVERED" → "WECRUOERDSOEERDV"

5. **Row-Column Transposition**
   - Key: Keyword for column ordering
   - Example: Key="ZEBRAS", "WEAREDISCOVERED" → "EVLNACDTESEAROFODE"

6. **Mono-alphabetic Substitution**
   - Key: 26-letter permutation
   - Example: Key="ZYXWVUTSRQPONMLKJIHGFEDCBA", "ABC" → "ZYX"

### Advanced Features
- Double encryption/decryption (chain any two algorithms)
- Dark/light mode theming
- Random key generation
- Operation history logging
#File Structure
Cryptograpgy_app/
├── cryptographic_toolkit.py  # Main application (600+ LOC)
├── requirements.txt          # Dependency list
└── README.md                # This document
## 🛠️ Technical Specifications
### Dependencies


💻 Installation & Execution
Windows/Linux/macOS

bash:
# Clone repository
git clone https://github.com/youssef324/Cryptograpgy_app.git
cd Cryptograpgy_app

# Install dependencies
pip install -r requirements.txt

# Launch application
python cryptographic_toolkit.py

#build Executable
pip install pyinstaller
pyinstaller --onefile --windowed cryptographic_toolkit.py

📄 License
MIT License - Free for academic and commercial use with attribution.

🔍 Support
For bug reports or feature requests, open an issue at:
https://github.com/youssef324/Cryptograpgy_app/issues



tk>=8.6
ttkthemes>=3.2.2
pyperclip>=1.8.2
