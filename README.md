# 🛡️ Cryptographic Toolkit

A Python GUI app for experimenting with classic cryptographic algorithms, built with Tkinter and ttkthemes.

---

## ✨ Features

- **Caesar Cipher**: Encrypt/decrypt with a shift value.
- **Vigenère Cipher**: Encrypt/decrypt with a keyword.
- **Playfair Cipher**: Encrypt/decrypt with a 5x5 keyword square.
- **Rail Fence Cipher**: Encrypt/decrypt with a number of rails.
- **Row-Column Transposition**: Encrypt/decrypt with a keyword.
- **Mono-alphabetic Substitution**: Encrypt/decrypt with a 26-letter substitution alphabet.
- **Double Cipher**: Combine any two algorithms for double encryption/decryption.
- **Key Generation**: One-click random key generation for all ciphers.
- **Clipboard Support**: Copy keys and results easily.
- **Summary Panel**: View a log of all operations performed.
- **Dark/Light Theme**: Toggle between dark and light modes.

---

## 🚀 Quick Start

1. **Clone the repository:**
   ```bash
   git clone https://github.com/youssef324/cryptographic-toolkit.git
   cd cryptographic-toolkit
   ```

2. **Install dependencies:**
   ```bash
   pip install ttkthemes pyperclip
   ```
   *(Tkinter is included with standard Python installations.)*

3. **Run the app:**
   ```bash
   python Cryptograpgy_app/cryptogrpahy_app.py
   ```

---

## 🖥️ How to Use

- **Choose a cipher** from the tabs.
- **Enter your text** and **key**.
- Click **Encrypt** or **Decrypt**.
- Use **Generate** to create a random valid key.
- For **Double Cipher**, select two algorithms and generate keys for both.
- **View operation history** in the summary panel.
- **Toggle dark/light mode** from the menu.

---

## 🔍 Code Highlights

### File: `Cryptograpgy_app/cryptogrpahy_app.py`

- **Class:** `CipherApp`
- **GUI:** Built with `Tkinter` and `ttkthemes` for a modern look.
- **Key Features:**
  - Each cipher has its own frame, input/output widgets, and key management.
  - **Key generation** for each cipher is handled by methods like `generate_caesar_key`, `generate_vigenere_key`, etc.
  - **Double Cipher:**  
    - Select two algorithms from dropdowns (`self.first_algo`, `self.second_algo`).
    - Generate keys for both with `generate_double_keys`.
    - Encrypt/Decrypt in sequence with `double_encrypt` and `double_decrypt`.
    - All logic is in the `apply_cipher` method, which dispatches to the correct cipher based on user selection.
  - **Input validation:**  
    - Playfair and Row-Column ciphers force uppercase and remove whitespace.
    - Keys are validated for correct format (e.g., 26 letters for mono-alphabetic).
  - **Summary Panel:**  
    - Every operation is logged with input, output, key, and algorithm.

#### Example: Double Cipher Key Generation
```python
def generate_double_keys(self):
    # Generate appropriate keys based on selected algorithms
    first_algo = self.first_algo.get()
    second_algo = self.second_algo.get()
    # ...key generation logic for each algorithm...
```

#### Example: Playfair Input Validation
```python
def playfair_encrypt(self):
    plaintext = self.playfair_input.get("1.0", tk.END).strip().replace(" ", "").upper()
    key = self.playfair_key.get().strip().replace(" ", "").upper()
    if not key.isalpha():
        messagebox.showerror("Error", "Key must contain only letters and no spaces")
        return
    # ...encryption logic...
```

---

## 📝 Notes

- **Playfair and Row-Column ciphers:** Input and key are always uppercase, whitespace is removed.
- **Key validation:** The app prevents invalid keys (e.g., non-letters for Playfair, wrong length for Mono-alphabetic).
- **Double Cipher:** Applies two ciphers in sequence for added security.
- **Clipboard:** Use the "Copy" button next to each key to copy it instantly.

---


## 👤 Author

Made with ❤️ by [ypussef324](https://github.com/ypussef324)

---

## ⚖️ License

MIT License

---

## 🙏 Credits

- [ttkthemes](https://github.com/RedFantom/ttkthemes)
- [pyperclip](https://github.com/asweigart/pyperclip)

---