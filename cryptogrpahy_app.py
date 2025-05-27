import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
from tkinter import font as tkfont
import random
import string
import pyperclip
from ttkthemes import ThemedTk

class CipherApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Cryptographic Toolkit")
        self.root.geometry("1000x700")

        # Set theme
        self.dark_mode = False  # Start with light mode
        self.set_theme()
        self.setup_styles()

        # Create main container
        self.main_frame = ttk.Frame(self.root)
        self.main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Create notebook for cipher selection
        self.notebook = ttk.Notebook(self.main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True)

        # Create cipher frames
        self.create_caesar_frame()
        self.create_vigenere_frame()
        self.create_playfair_frame()
        self.create_railfence_frame()
        self.create_rowcolumn_frame()
        self.create_monoalphabetic_frame()
        self.create_double_cipher_frame()
        self.create_sdes_frame()  # Create S-DES frame

        # Create summary panel
        self.summary_visible = False
        self.create_summary_panel()

        # Create menu
        self.create_menu()

    def set_theme(self):
        if self.dark_mode:
            self.root.set_theme("black")
            self.text_bg = "#232946"      # Deep blue background for text
            self.text_fg = "#eebbc3"      # Soft pink text
            self.button_bg = "#393e46"    # Darker blue for buttons
            self.button_fg = "#eebbc3"    # Soft pink text on buttons
            self.frame_bg = "#121629"     # Very dark blue for frames
            self.label_fg = "#eebbc3"     # Soft pink for labels
        else:
            self.root.set_theme("arc")
            self.text_bg = "#f4f6fb"      # Very light blue background for text
            self.text_fg = "#232946"      # Deep blue text
            self.button_bg = "#6557ff"    # Vibrant purple for buttons
            self.button_fg = "#ffffff"    # White text on buttons
            self.frame_bg = "#ffffff"     # White for frames
            self.label_fg = "#6557ff"     # Vibrant purple for labels

    def setup_styles(self):
        style = ttk.Style(self.root)
        style.theme_use("arc")
        style.configure("TFrame", background=self.frame_bg)
        style.configure("TLabel", background=self.frame_bg, foreground=self.label_fg, font=("Segoe UI", 12, "bold"))
        style.configure(
            "Accent.TButton",
            background=self.button_bg,
            foreground=self.button_fg,
            font=("Segoe UI", 11, "bold"),
            borderwidth=0,
            focusthickness=3,
            focuscolor=self.button_bg,
            padding=10
        )
        style.map(
            "Accent.TButton",
            background=[("active", "#232946"), ("pressed", "#393e46")],
            foreground=[("active", "#eebbc3"), ("pressed", "#eebbc3")]
        )
        style.layout("Accent.TButton", [
            ('Button.border', {'sticky': 'nswe', 'children': [
                ('Button.focus', {'sticky': 'nswe', 'children': [
                    ('Button.padding', {'sticky': 'nswe', 'children': [
                        ('Button.label', {'sticky': 'nswe'})
                    ]})
                ]})
            ]})
        ])
    
    # Update create_action_buttons to use the new style
    def create_action_buttons(self, parent, encrypt_callback, decrypt_callback):
        frame = ttk.Frame(parent)
        encrypt_btn = ttk.Button(frame, text="Encrypt", command=encrypt_callback, style="Pink.TButton")
        encrypt_btn.pack(side=tk.LEFT, padx=5, pady=5)

        decrypt_btn = ttk.Button(frame, text="Decrypt", command=decrypt_callback, style="Pink.TButton")
        decrypt_btn.pack(side=tk.LEFT, padx=5, pady=5)

        clear_btn = ttk.Button(frame, text="Clear", command=lambda: self.clear_text_widgets(parent), style="Pink.TButton")
        clear_btn.pack(side=tk.LEFT, padx=5, pady=5)

        return frame

    # Update create_key_frame to use the new style for buttons
    def create_key_frame(self, parent, key_var, key_name="Key", generate_callback=None):
        frame = ttk.Frame(parent)
        ttk.Label(frame, text=f"{key_name}:").pack(side=tk.LEFT, padx=5)
        key_entry = ttk.Entry(frame, textvariable=key_var, width=30)
        key_entry.pack(side=tk.LEFT, padx=5, expand=True, fill=tk.X)

        if generate_callback:
            generate_btn = ttk.Button(frame, text="Generate", command=generate_callback, style="Pink.TButton")
            generate_btn.pack(side=tk.LEFT, padx=5)

        copy_btn = ttk.Button(frame, text="Copy", command=lambda: self.copy_to_clipboard(key_var.get()), style="Pink.TButton")
        copy_btn.pack(side=tk.LEFT, padx=5)

        return frame

    # In create_double_cipher_frame, update button styles as well:
    def create_double_cipher_frame(self):
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="Double Cipher")

        # Algorithm selection
        algo_frame = ttk.Frame(frame)
        ttk.Label(algo_frame, text="First Algorithm:").pack(side=tk.LEFT, padx=5)
        self.first_algo = ttk.Combobox(algo_frame, values=[
            "Caesar Cipher", "Vigenère Cipher", "Playfair Cipher", 
            "Rail Fence Cipher", "Row-Column Transposition", "Mono-alphabetic Substitution",
            "S-DES"  # Add S-DES to the list
        ], state="readonly")
        self.first_algo.pack(side=tk.LEFT, padx=5, expand=True, fill=tk.X)
        
        ttk.Label(algo_frame, text="Second Algorithm:").pack(side=tk.LEFT, padx=5)
        self.second_algo = ttk.Combobox(algo_frame, values=[
            "Caesar Cipher", "Vigenère Cipher", "Playfair Cipher", 
            "Rail Fence Cipher", "Row-Column Transposition", "Mono-alphabetic Substitution",
            "S-DES"  # Add S-DES to the list
        ], state="readonly")
        self.second_algo.pack(side=tk.LEFT, padx=5, expand=True, fill=tk.X)
        algo_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Input/Output
        io_frame, self.double_cipher_input, self.double_cipher_output = self.create_input_output_frame(frame)
        io_frame.pack(fill=tk.BOTH, expand=True)
        
        # Key frames
        key_frame = ttk.Frame(frame)
        
        self.first_key = tk.StringVar()
        first_key_frame = self.create_key_frame(key_frame, self.first_key, "First Key")
        first_key_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.second_key = tk.StringVar()
        second_key_frame = self.create_key_frame(key_frame, self.second_key, "Second Key")
        second_key_frame.pack(fill=tk.X, padx=5, pady=5)
        
        key_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Buttons
        btn_frame = ttk.Frame(frame)
        encrypt_btn = ttk.Button(btn_frame, text="Double Encrypt", command=self.double_encrypt, style="Pink.TButton")
        encrypt_btn.pack(side=tk.LEFT, padx=5, pady=5)
        
        decrypt_btn = ttk.Button(btn_frame, text="Double Decrypt", command=self.double_decrypt, style="Pink.TButton")
        decrypt_btn.pack(side=tk.LEFT, padx=5, pady=5)
        
        clear_btn = ttk.Button(btn_frame, text="Clear", command=lambda: self.clear_text_widgets(frame), style="Pink.TButton")
        clear_btn.pack(side=tk.LEFT, padx=5, pady=5)
        
        generate_keys_btn = ttk.Button(btn_frame, text="Generate Keys", command=self.generate_double_keys, style="Pink.TButton")
        generate_keys_btn.pack(side=tk.LEFT, padx=5, pady=5)
        
        btn_frame.pack(fill=tk.X, padx=5, pady=5)

    # --- S-DES Cipher Implementation ---
    def create_sdes_frame(self):
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="S-DES")

        # Input/Output
        io_frame, self.sdes_input, self.sdes_output = self.create_input_output_frame(frame)
        io_frame.pack(fill=tk.BOTH, expand=True)

        # Key
        self.sdes_key = tk.StringVar(value="1010000010")
        key_frame = self.create_key_frame(frame, self.sdes_key, "10-bit Key")
        key_frame.pack(fill=tk.X, padx=5, pady=5)

        # Buttons
        btn_frame = self.create_action_buttons(frame, self.sdes_encrypt, self.sdes_decrypt)
        btn_frame.pack(fill=tk.X, padx=5, pady=5)
    
    def generate_sdes_key(self):
        # Generate a random 10-bit binary key
        key = ''.join(random.choice('01') for _ in range(10))
        self.sdes_key.set(key)
    
    def sdes_encrypt(self):
        plaintext = self.sdes_input.get("1.0", tk.END).strip()
        key = self.sdes_key.get().strip()
        if not self.validate_sdes_key(key):
            messagebox.showerror("Error", "Key must be a 10-bit binary string (e.g., 1010000010)")
            return
        if not self.validate_sdes_text(plaintext):
            messagebox.showerror("Error", "Plaintext must be 8-bit binary string(s), separated by spaces")
            return
        ciphertext = ' '.join([self.sdes_encrypt_block(block, key) for block in plaintext.split()])
        self.sdes_output.delete('1.0', tk.END)
        self.sdes_output.insert(tk.END, ciphertext)
        self.add_to_summary("Encryption", "S-DES", plaintext, ciphertext, key)

    def sdes_decrypt(self):
        ciphertext = self.sdes_input.get("1.0", tk.END).strip()
        key = self.sdes_key.get().strip()
        if not self.validate_sdes_key(key):
            messagebox.showerror("Error", "Key must be a 10-bit binary string (e.g., 1010000010)")
            return
        if not self.validate_sdes_text(ciphertext):
            messagebox.showerror("Error", "Ciphertext must be 8-bit binary string(s), separated by spaces")
            return
        plaintext = ' '.join([self.sdes_decrypt_block(block, key) for block in ciphertext.split()])
        self.sdes_output.delete('1.0', tk.END)
        self.sdes_output.insert(tk.END, plaintext)
        self.add_to_summary("Decryption", "S-DES", ciphertext, plaintext, key)

    def validate_sdes_key(self, key):
        return len(key) == 10 and all(c in '01' for c in key)

    def validate_sdes_text(self, text):
        return all(len(block) == 8 and all(c in '01' for c in block) for block in text.split())

    # --- S-DES Core Functions ---
    def sdes_encrypt_block(self, block, key):
        K1, K2 = self.sdes_generate_keys(key)
        return self.sdes_fk(block, K1, K2)

    def sdes_decrypt_block(self, block, key):
        K1, K2 = self.sdes_generate_keys(key)
        return self.sdes_fk(block, K2, K1)

    def sdes_generate_keys(self, key):
        # Permutation functions
        def permute(bits, order):
            return ''.join(bits[i] for i in order)
        # Left shift
        def left_shift(bits, n):
            return bits[n:] + bits[:n]
        # P10 and P8
        P10 = [2, 4, 1, 6, 3, 9, 0, 8, 7, 5]
        P8 = [5, 2, 6, 3, 7, 4, 9, 8]
        # Key generation
        key_p10 = permute(key, P10)
        left, right = key_p10[:5], key_p10[5:]
        left1, right1 = left_shift(left, 1), left_shift(right, 1)
        K1 = permute(left1 + right1, P8)
        left2, right2 = left_shift(left1, 2), left_shift(right1, 2)
        K2 = permute(left2 + right2, P8)
        return K1, K2

    def sdes_fk(self, bits, K1, K2):
        # Initial and inverse permutations
        IP = [1, 5, 2, 0, 3, 7, 4, 6]
        IP_inv = [3, 0, 2, 4, 6, 1, 7, 5]
        # Expansion/permutation, S-boxes, P4
        EP = [3, 0, 1, 2, 1, 2, 3, 0]
        S0 = [
            [1, 0, 3, 2],
            [3, 2, 1, 0],
            [0, 2, 1, 3],
            [3, 1, 3, 2]
        ]
        S1 = [
            [0, 1, 2, 3],
            [2, 0, 1, 3],
            [3, 0, 1, 0],
            [2, 1, 0, 3]
        ]
        P4 = [1, 3, 2, 0]

        def permute(bits, order):
            return ''.join(bits[i] for i in order)

        def xor(bits1, bits2):
            return ''.join('0' if b1 == b2 else '1' for b1, b2 in zip(bits1, bits2))

        def sbox(bits, box):
            row = int(bits[0] + bits[3], 2)
            col = int(bits[1] + bits[2], 2)
            val = box[row][col]
            return f"{val:02b}"

        def f_k(bits, key):
            left, right = bits[:4], bits[4:]
            right_exp = permute(right, EP)
            temp = xor(right_exp, key)
            s0 = sbox(temp[:4], S0)
            s1 = sbox(temp[4:], S1)
            p4 = permute(s0 + s1, P4)
            return xor(left, p4) + right

        # Initial permutation
        bits = permute(bits, IP)
        # First round
        bits = f_k(bits, K1)
        # Swap
        bits = bits[4:] + bits[:4]
        # Second round
        bits = f_k(bits, K2)
        # Inverse initial permutation
        bits = permute(bits, IP_inv)
        return bits
    
    def create_menu(self):
        menubar = tk.Menu(self.root)
        
        # Theme menu
        theme_menu = tk.Menu(menubar, tearoff=0)
        theme_menu.add_command(label="Toggle Dark/Light Mode", command=self.toggle_theme)
        menubar.add_cascade(label="Theme", menu=theme_menu)
        
        # View menu
        view_menu = tk.Menu(menubar, tearoff=0)
        view_menu.add_command(label="Toggle Summary Panel", command=self.toggle_summary)
        menubar.add_cascade(label="View", menu=view_menu)
        
        self.root.config(menu=menubar)
    
    def toggle_theme(self):
        self.dark_mode = not self.dark_mode
        self.set_theme()
        self.update_text_widgets()
    
    def toggle_summary(self):
        self.summary_visible = not self.summary_visible
        if self.summary_visible:
            self.summary_panel.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        else:
            self.summary_panel.pack_forget()
    
    def update_text_widgets(self):
        # Update all text widgets with new colors
        widgets = [
            self.caesar_input, self.caesar_output,
            self.vigenere_input, self.vigenere_output,
            self.playfair_input, self.playfair_output,
            self.railfence_input, self.railfence_output,
            self.rowcolumn_input, self.rowcolumn_output,
            self.monoalphabetic_input, self.monoalphabetic_output,
            self.double_cipher_input, self.double_cipher_output,
            self.summary_text
        ]
        
        for widget in widgets:
            if hasattr(widget, 'configure'):
                widget.configure(
                    background=self.text_bg,
                    foreground=self.text_fg,
                    insertbackground=self.text_fg
                )
    
    def create_summary_panel(self):
        self.summary_panel = ttk.Frame(self.main_frame)
        ttk.Label(self.summary_panel, text="Operation Summary", font=('Helvetica', 12, 'bold')).pack(pady=5)
        
        self.summary_text = scrolledtext.ScrolledText(
            self.summary_panel,
            wrap=tk.WORD,
            width=80,
            height=10,
            bg=self.text_bg,
            fg=self.text_fg,
            insertbackground=self.text_fg
        )
        self.summary_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        if self.summary_visible:
            self.summary_panel.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
    
    def add_to_summary(self, operation, algorithm, input_text, output_text, key):
        summary_entry = f"""
=== {operation} with {algorithm} ===
Key: {key}
Input: {input_text}
Output: {output_text}
"""
        self.summary_text.insert(tk.END, summary_entry)
        self.summary_text.see(tk.END)
    
    def create_input_output_frame(self, parent):
        frame = ttk.Frame(parent)
        
        # Input section
        input_frame = ttk.Frame(frame)
        ttk.Label(input_frame, text="Input Text:").pack(anchor=tk.W)
        input_text = scrolledtext.ScrolledText(
            input_frame,
            wrap=tk.WORD,
            width=40,
            height=8,
            bg=self.text_bg,
            fg=self.text_fg,
            insertbackground=self.text_fg
        )
        input_text.pack(fill=tk.BOTH, expand=True)
        
        # Output section
        output_frame = ttk.Frame(frame)
        ttk.Label(output_frame, text="Output Text:").pack(anchor=tk.W)
        output_text = scrolledtext.ScrolledText(
            output_frame,
            wrap=tk.WORD,
            width=40,
            height=8,
            bg=self.text_bg,
            fg=self.text_fg,
            insertbackground=self.text_fg
        )
        output_text.pack(fill=tk.BOTH, expand=True)
        
        # Layout
        input_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        output_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        return frame, input_text, output_text
    
    def clear_text_widgets(self, parent):
        for widget in parent.winfo_children():
            if isinstance(widget, tk.Text) or isinstance(widget, scrolledtext.ScrolledText):
                widget.delete('1.0', tk.END)
    
    def copy_to_clipboard(self, text):
        pyperclip.copy(text)
        messagebox.showinfo("Copied", "Text copied to clipboard!")
    
    # Caesar Cipher Frame
    def create_caesar_frame(self):
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="Caesar Cipher")
        
        # Input/Output
        io_frame, self.caesar_input, self.caesar_output = self.create_input_output_frame(frame)
        io_frame.pack(fill=tk.BOTH, expand=True)
        
        # Key
        self.caesar_key = tk.StringVar(value="3")
        key_frame = self.create_key_frame(frame, self.caesar_key, "Shift Value", self.generate_caesar_key)
        key_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Buttons
        btn_frame = self.create_action_buttons(frame, self.caesar_encrypt, self.caesar_decrypt)
        btn_frame.pack(fill=tk.X, padx=5, pady=5)
    
    def generate_caesar_key(self):
        self.caesar_key.set(str(random.randint(1, 25)))
    
    def caesar_encrypt(self):
        plaintext = self.caesar_input.get("1.0", tk.END).strip()
        try:
            shift = int(self.caesar_key.get())
        except ValueError:
            messagebox.showerror("Error", "Shift must be an integer")
            return
        
        ciphertext = self.caesar_cipher(plaintext, shift)
        self.caesar_output.delete('1.0', tk.END)
        self.caesar_output.insert(tk.END, ciphertext)
        self.add_to_summary("Encryption", "Caesar Cipher", plaintext, ciphertext, shift)
    
    def caesar_decrypt(self):
        ciphertext = self.caesar_input.get("1.0", tk.END).strip()
        try:
            shift = int(self.caesar_key.get())
        except ValueError:
            messagebox.showerror("Error", "Shift must be an integer")
            return
        
        plaintext = self.caesar_cipher(ciphertext, -shift)
        self.caesar_output.delete('1.0', tk.END)
        self.caesar_output.insert(tk.END, plaintext)
        self.add_to_summary("Decryption", "Caesar Cipher", ciphertext, plaintext, shift)
    
    def caesar_cipher(self, text, shift):
        result = []
        for char in text:
            if char.isupper():
                result.append(chr((ord(char) + shift - 65) % 26 + 65))
            elif char.islower():
                result.append(chr((ord(char) + shift - 97) % 26 + 97))
            else:
                result.append(char)
        return ''.join(result)
    
    # Vigenère Cipher Frame
    def create_vigenere_frame(self):
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="Vigenère Cipher")
        
        # Input/Output
        io_frame, self.vigenere_input, self.vigenere_output = self.create_input_output_frame(frame)
        io_frame.pack(fill=tk.BOTH, expand=True)
        
        # Key
        self.vigenere_key = tk.StringVar(value="KEY")
        key_frame = self.create_key_frame(frame, self.vigenere_key, "Keyword", self.generate_vigenere_key)
        key_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Buttons
        btn_frame = self.create_action_buttons(frame, self.vigenere_encrypt, self.vigenere_decrypt)
        btn_frame.pack(fill=tk.X, padx=5, pady=5)
    
    def generate_vigenere_key(self):
        length = random.randint(5, 10)
        key = ''.join(random.choice(string.ascii_uppercase) for _ in range(length))
        self.vigenere_key.set(key)
    
    def vigenere_encrypt(self):
        plaintext = self.vigenere_input.get("1.0", tk.END).strip().upper()
        key = self.vigenere_key.get().upper()
        
        if not key.isalpha():
            messagebox.showerror("Error", "Key must contain only letters")
            return
        
        ciphertext = self.vigenere_cipher(plaintext, key, encrypt=True)
        self.vigenere_output.delete('1.0', tk.END)
        self.vigenere_output.insert(tk.END, ciphertext)
        self.add_to_summary("Encryption", "Vigenère Cipher", plaintext, ciphertext, key)
    
    def vigenere_decrypt(self):
        ciphertext = self.vigenere_input.get("1.0", tk.END).strip().upper()
        key = self.vigenere_key.get().upper()
        
        if not key.isalpha():
            messagebox.showerror("Error", "Key must contain only letters")
            return
        
        plaintext = self.vigenere_cipher(ciphertext, key, encrypt=False)
        self.vigenere_output.delete('1.0', tk.END)
        self.vigenere_output.insert(tk.END, plaintext)
        self.add_to_summary("Decryption", "Vigenère Cipher", ciphertext, plaintext, key)
    
    def vigenere_cipher(self, text, key, encrypt=True):
        result = []
        key_len = len(key)
        key_index = 0
        
        for char in text:
            if char.isalpha():
                shift = ord(key[key_index % key_len].upper()) - 65
                if not encrypt:
                    shift = -shift
                
                if char.isupper():
                    result.append(chr((ord(char) + shift - 65) % 26 + 65))
                else:
                    result.append(chr((ord(char) + shift - 97) % 26 + 97))
                
                key_index += 1
            else:
                result.append(char)
        
        return ''.join(result)
    
    # Playfair Cipher Frame
    def create_playfair_frame(self):
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="Playfair Cipher")
        
        # Input/Output
        io_frame, self.playfair_input, self.playfair_output = self.create_input_output_frame(frame)
        io_frame.pack(fill=tk.BOTH, expand=True)
        
        # Key
        self.playfair_key = tk.StringVar(value="PLAYFAIR")
        key_frame = self.create_key_frame(frame, self.playfair_key, "Keyword", self.generate_playfair_key)
        key_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Buttons
        btn_frame = self.create_action_buttons(frame, self.playfair_encrypt, self.playfair_decrypt)
        btn_frame.pack(fill=tk.X, padx=5, pady=5)
    
    def generate_playfair_key(self):
        length = random.randint(5, 10)
        key = ''.join(random.choice(string.ascii_uppercase.replace('J', '')) for _ in range(length))
        self.playfair_key.set(key)
    
    def playfair_encrypt(self):
        plaintext = self.playfair_input.get("1.0", tk.END).strip().replace(" ", "").upper()
        key = self.playfair_key.get().strip().replace(" ", "").upper()

        if not key.isalpha():
            messagebox.showerror("Error", "Key must contain only letters and no spaces")
            return

        ciphertext = self.playfair_cipher(plaintext, key, encrypt=True)
        self.playfair_output.delete('1.0', tk.END)
        self.playfair_output.insert(tk.END, ciphertext)
        self.add_to_summary("Encryption", "Playfair Cipher", plaintext, ciphertext, key)

    def playfair_decrypt(self):
        ciphertext = self.playfair_input.get("1.0", tk.END).strip().replace(" ", "").upper()
        key = self.playfair_key.get().strip().replace(" ", "").upper()

        if not key.isalpha():
            messagebox.showerror("Error", "Key must contain only letters and no spaces")
            return

        plaintext = self.playfair_cipher(ciphertext, key, encrypt=False)
        self.playfair_output.delete('1.0', tk.END)
        self.playfair_output.insert(tk.END, plaintext)
        self.add_to_summary("Decryption", "Playfair Cipher", ciphertext, plaintext, key)
    
    def playfair_cipher(self, text, key, encrypt=True):
        # Create the 5x5 key square
        key_square = self.create_playfair_square(key)
        
        # Prepare the text (handle I/J and add X between double letters)
        prepared_text = self.prepare_playfair_text(text)
        
        # Process each digraph
        result = []
        for i in range(0, len(prepared_text), 2):
            digraph = prepared_text[i:i+2]
            if len(digraph) == 1:  # Shouldn't happen with proper preparation
                digraph += 'X'
            
            row1, col1 = self.find_in_square(key_square, digraph[0])
            row2, col2 = self.find_in_square(key_square, digraph[1])
            
            if row1 == row2:  # Same row
                if encrypt:
                    new_col1 = (col1 + 1) % 5
                    new_col2 = (col2 + 1) % 5
                else:
                    new_col1 = (col1 - 1) % 5
                    new_col2 = (col2 - 1) % 5
                result.append(key_square[row1][new_col1] + key_square[row2][new_col2])
            elif col1 == col2:  # Same column
                if encrypt:
                    new_row1 = (row1 + 1) % 5
                    new_row2 = (row2 + 1) % 5
                else:
                    new_row1 = (row1 - 1) % 5
                    new_row2 = (row2 - 1) % 5
                result.append(key_square[new_row1][col1] + key_square[new_row2][col2])
            else:  # Rectangle rule
                result.append(key_square[row1][col2] + key_square[row2][col1])
        
        return ''.join(result)
    
    def create_playfair_square(self, key):
        # Remove duplicate letters from key and replace J with I
        key = key.replace('J', 'I')
        seen = set()
        key_unique = []
        for char in key:
            if char not in seen:
                seen.add(char)
                key_unique.append(char)
        
        # Add remaining letters (except J)
        remaining_letters = [c for c in string.ascii_uppercase if c != 'J' and c not in seen]
        key_square_letters = key_unique + remaining_letters
        
        # Create 5x5 square
        key_square = []
        for i in range(5):
            row = key_square_letters[i*5 : (i+1)*5]
            key_square.append(row)
        
        return key_square
    
    def prepare_playfair_text(self, text):
        # Remove non-alphabetic characters and replace J with I
        text = ''.join(c for c in text.upper() if c.isalpha()).replace('J', 'I')
        prepared = []
        i = 0
        while i < len(text):
            a = text[i]
            b = text[i+1] if i+1 < len(text) else 'X'
            if a == b:
                prepared.append(a + 'X')
                i += 1
            else:
                prepared.append(a + b)
                i += 2
        # If the last pair is a single letter, pad with X
        if len(prepared[-1]) == 1:
            prepared[-1] += 'X'
        return ''.join(prepared)
    
    def find_in_square(self, key_square, char):
        for row in range(5):
            for col in range(5):
                if key_square[row][col] == char:
                    return row, col
        return -1, -1  # Shouldn't happen with proper input
    
    # Rail Fence Cipher Frame
    def create_railfence_frame(self):
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="Rail Fence Cipher")
        
        # Input/Output
        io_frame, self.railfence_input, self.railfence_output = self.create_input_output_frame(frame)
        io_frame.pack(fill=tk.BOTH, expand=True)
        
        # Key
        self.railfence_key = tk.StringVar(value="3")
        key_frame = self.create_key_frame(frame, self.railfence_key, "Number of Rails", self.generate_railfence_key)
        key_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Buttons
        btn_frame = self.create_action_buttons(frame, self.railfence_encrypt, self.railfence_decrypt)
        btn_frame.pack(fill=tk.X, padx=5, pady=5)
    
    def generate_railfence_key(self):
        self.railfence_key.set(str(random.randint(2, 10)))
    
    def railfence_encrypt(self):
        plaintext = self.railfence_input.get("1.0", tk.END).strip()
        try:
            rails = int(self.railfence_key.get())
        except ValueError:
            messagebox.showerror("Error", "Number of rails must be an integer")
            return
        
        ciphertext = self.railfence_cipher(plaintext, rails, encrypt=True)
        self.railfence_output.delete('1.0', tk.END)
        self.railfence_output.insert(tk.END, ciphertext)
        self.add_to_summary("Encryption", "Rail Fence Cipher", plaintext, ciphertext, rails)
    
    def railfence_decrypt(self):
        ciphertext = self.railfence_input.get("1.0", tk.END).strip()
        try:
            rails = int(self.railfence_key.get())
        except ValueError:
            messagebox.showerror("Error", "Number of rails must be an integer")
            return
        
        plaintext = self.railfence_cipher(ciphertext, rails, encrypt=False)
        self.railfence_output.delete('1.0', tk.END)
        self.railfence_output.insert(tk.END, plaintext)
        self.add_to_summary("Decryption", "Rail Fence Cipher", ciphertext, plaintext, rails)
    
    def railfence_cipher(self, text, rails, encrypt=True):
        if encrypt:
            fence = [[] for _ in range(rails)]
            rail = 0
            direction = 1
            
            for char in text:
                fence[rail].append(char)
                rail += direction
                if rail == rails - 1 or rail == 0:
                    direction *= -1
            
            return ''.join([''.join(row) for row in fence])
        else:
            # Create the fence pattern to determine character positions
            pattern = []
            rail = 0
            direction = 1
            
            for _ in range(len(text)):
                pattern.append(rail)
                rail += direction
                if rail == rails - 1 or rail == 0:
                    direction *= -1
            
            # Create the fence with the characters in the right places
            fence = [[] for _ in range(rails)]
            for i, char in enumerate(text):
                fence[pattern[i]].append(char)
            
            # Now read the fence in the original pattern order
            result = []
            rail = 0
            direction = 1
            rail_chars = [0] * rails
            
            for _ in range(len(text)):
                if rail_chars[rail] < len(fence[rail]):
                    result.append(fence[rail][rail_chars[rail]])
                    rail_chars[rail] += 1
                rail += direction
                if rail == rails - 1 or rail == 0:
                    direction *= -1
            
            return ''.join(result)
    
    # Row-Column Transposition Frame
    def create_rowcolumn_frame(self):
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="Row-Column Transposition")
        
        # Input/Output
        io_frame, self.rowcolumn_input, self.rowcolumn_output = self.create_input_output_frame(frame)
        io_frame.pack(fill=tk.BOTH, expand=True)
        
        # Key
        self.rowcolumn_key = tk.StringVar(value="KEY")
        key_frame = self.create_key_frame(frame, self.rowcolumn_key, "Keyword", self.generate_rowcolumn_key)
        key_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Buttons
        btn_frame = self.create_action_buttons(frame, self.rowcolumn_encrypt, self.rowcolumn_decrypt)
        btn_frame.pack(fill=tk.X, padx=5, pady=5)
    
    def generate_rowcolumn_key(self):
        length = random.randint(5, 10)
        key = ''.join(random.choice(string.ascii_uppercase) for _ in range(length))
        self.rowcolumn_key.set(key)
    
    def rowcolumn_encrypt(self):
        plaintext = self.rowcolumn_input.get("1.0", tk.END).strip().replace(" ", "").upper()
        key = self.rowcolumn_key.get().strip().replace(" ", "").upper()

        if not key.isalpha():
            messagebox.showerror("Error", "Key must contain only letters and no spaces")
            return

        ciphertext = self.rowcolumn_cipher(plaintext, key, encrypt=True)
        self.rowcolumn_output.delete('1.0', tk.END)
        self.rowcolumn_output.insert(tk.END, ciphertext)
        self.add_to_summary("Encryption", "Row-Column Transposition", plaintext, ciphertext, key)

    def rowcolumn_decrypt(self):
        ciphertext = self.rowcolumn_input.get("1.0", tk.END).strip().replace(" ", "").upper()
        key = self.rowcolumn_key.get().strip().replace(" ", "").upper()

        if not key.isalpha():
            messagebox.showerror("Error", "Key must contain only letters and no spaces")
            return

        plaintext = self.rowcolumn_cipher(ciphertext, key, encrypt=False)
        self.rowcolumn_output.delete('1.0', tk.END)
        self.rowcolumn_output.insert(tk.END, plaintext)
        self.add_to_summary("Decryption", "Row-Column Transposition", ciphertext, plaintext, key)
    
    def rowcolumn_cipher(self, text, key, encrypt=True):
        # Determine the column order based on the key
        key_order = sorted(range(len(key)), key=lambda k: key[k])
        
        if encrypt:
            # Pad the text to make it fit evenly in the grid
            cols = len(key)
            rows = (len(text) + cols - 1) // cols
            padded_text = text.ljust(rows * cols, 'X')
            
            # Create the grid
            grid = [list(padded_text[i*cols:(i+1)*cols]) for i in range(rows)]
            
            # Read columns in key order
            ciphertext = []
            for col in key_order:
                for row in range(rows):
                    ciphertext.append(grid[row][col])
            
            return ''.join(ciphertext)
        else:
            # Determine the original column order
            cols = len(key)
            rows = (len(text) + cols - 1) // cols
            
            # Create empty grid
            grid = [[None for _ in range(cols)] for _ in range(rows)]
            
            # Fill the grid column by column in key order
            text_index = 0
            for col in key_order:
                for row in range(rows):
                    if text_index < len(text):
                        grid[row][col] = text[text_index]
                        text_index += 1
                    else:
                        grid[row][col] = 'X'  # Padding
            
            # Read the grid row by row
            plaintext = []
            for row in range(rows):
                for col in range(cols):
                    plaintext.append(grid[row][col])
            
            return ''.join(plaintext).rstrip('X')
    
    # Mono-alphabetic Substitution Frame
    def create_monoalphabetic_frame(self):
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="Mono-alphabetic Substitution")
        
        # Input/Output
        io_frame, self.monoalphabetic_input, self.monoalphabetic_output = self.create_input_output_frame(frame)
        io_frame.pack(fill=tk.BOTH, expand=True)
        
        # Key
        self.monoalphabetic_key = tk.StringVar(value="ZYXWVUTSRQPONMLKJIHGFEDCBA")
        key_frame = self.create_key_frame(frame, self.monoalphabetic_key, "Substitution Alphabet", 
                                         self.generate_monoalphabetic_key)
        key_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Buttons
        btn_frame = self.create_action_buttons(frame, self.monoalphabetic_encrypt, self.monoalphabetic_decrypt)
        btn_frame.pack(fill=tk.X, padx=5, pady=5)
    
    def generate_monoalphabetic_key(self):
        letters = list(string.ascii_uppercase)
        random.shuffle(letters)
        self.monoalphabetic_key.set(''.join(letters))
    
    def monoalphabetic_encrypt(self):
        plaintext = self.monoalphabetic_input.get("1.0", tk.END).strip().upper()
        key = self.monoalphabetic_key.get().upper()
        
        if len(key) != 26 or not key.isalpha():
            messagebox.showerror("Error", "Key must be a 26-letter permutation of the alphabet")
            return
        
        ciphertext = self.monoalphabetic_cipher(plaintext, key, encrypt=True)
        self.monoalphabetic_output.delete('1.0', tk.END)
        self.monoalphabetic_output.insert(tk.END, ciphertext)
        self.add_to_summary("Encryption", "Mono-alphabetic Substitution", plaintext, ciphertext, key)
    
    def monoalphabetic_decrypt(self):
        ciphertext = self.monoalphabetic_input.get("1.0", tk.END).strip().upper()
        key = self.monoalphabetic_key.get().upper()
        
        if len(key) != 26 or not key.isalpha():
            messagebox.showerror("Error", "Key must be a 26-letter permutation of the alphabet")
            return
        
        plaintext = self.monoalphabetic_cipher(ciphertext, key, encrypt=False)
        self.monoalphabetic_output.delete('1.0', tk.END)
        self.monoalphabetic_output.insert(tk.END, plaintext)
        self.add_to_summary("Decryption", "Mono-alphabetic Substitution", ciphertext, plaintext, key)
    
    def monoalphabetic_cipher(self, text, key, encrypt=True):
        result = []
        for char in text:
            if char.isupper():
                if encrypt:
                    # Encrypt: plaintext letter to key letter
                    index = ord(char) - ord('A')
                    result.append(key[index])
                else:
                    # Decrypt: key letter to plaintext letter
                    index = key.index(char)
                    result.append(chr(ord('A') + index))
            elif char.islower():
                if encrypt:
                    # Encrypt: plaintext letter to key letter (lowercase)
                    index = ord(char) - ord('a')
                    result.append(key[index].lower())
                else:
                    # Decrypt: key letter to plaintext letter (lowercase)
                    index = key.upper().index(char.upper())
                    result.append(chr(ord('a') + index))
            else:
                result.append(char)
        return ''.join(result)
    
    # Double Cipher Frame
    def create_double_cipher_frame(self):
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="Double Cipher")
        
        # Algorithm selection
        algo_frame = ttk.Frame(frame)
        ttk.Label(algo_frame, text="First Algorithm:").pack(side=tk.LEFT, padx=5)
        self.first_algo = ttk.Combobox(algo_frame, values=[
            "Caesar Cipher", "Vigenère Cipher", "Playfair Cipher", 
            "Rail Fence Cipher", "Row-Column Transposition", "Mono-alphabetic Substitution",
            "S-DES"  # Add S-DES to the list
        ], state="readonly")
        self.first_algo.pack(side=tk.LEFT, padx=5, expand=True, fill=tk.X)
        
        ttk.Label(algo_frame, text="Second Algorithm:").pack(side=tk.LEFT, padx=5)
        self.second_algo = ttk.Combobox(algo_frame, values=[
            "Caesar Cipher", "Vigenère Cipher", "Playfair Cipher", 
            "Rail Fence Cipher", "Row-Column Transposition", "Mono-alphabetic Substitution",
            "S-DES"  # Add S-DES to the list
        ], state="readonly")
        self.second_algo.pack(side=tk.LEFT, padx=5, expand=True, fill=tk.X)
        algo_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Input/Output
        io_frame, self.double_cipher_input, self.double_cipher_output = self.create_input_output_frame(frame)
        io_frame.pack(fill=tk.BOTH, expand=True)
        
        # Key frames
        key_frame = ttk.Frame(frame)
        
        self.first_key = tk.StringVar()
        first_key_frame = self.create_key_frame(key_frame, self.first_key, "First Key")
        first_key_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.second_key = tk.StringVar()
        second_key_frame = self.create_key_frame(key_frame, self.second_key, "Second Key")
        second_key_frame.pack(fill=tk.X, padx=5, pady=5)
        
        key_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Buttons
        btn_frame = ttk.Frame(frame)
        encrypt_btn = ttk.Button(btn_frame, text="Double Encrypt", command=self.double_encrypt, style="Pink.TButton")
        encrypt_btn.pack(side=tk.LEFT, padx=5, pady=5)
        
        decrypt_btn = ttk.Button(btn_frame, text="Double Decrypt", command=self.double_decrypt, style="Pink.TButton")
        decrypt_btn.pack(side=tk.LEFT, padx=5, pady=5)
        
        clear_btn = ttk.Button(btn_frame, text="Clear", command=lambda: self.clear_text_widgets(frame), style="Pink.TButton")
        clear_btn.pack(side=tk.LEFT, padx=5, pady=5)
        
        generate_keys_btn = ttk.Button(btn_frame, text="Generate Keys", command=self.generate_double_keys, style="Pink.TButton")
        generate_keys_btn.pack(side=tk.LEFT, padx=5, pady=5)
        
        btn_frame.pack(fill=tk.X, padx=5, pady=5)
    
    def generate_double_keys(self):
        # Generate appropriate keys based on selected algorithms
        first_algo = self.first_algo.get()
        second_algo = self.second_algo.get()

        # Generate key for first algorithm
        if first_algo == "Caesar Cipher":
            self.first_key.set(str(random.randint(1, 25)))
        elif first_algo == "Vigenère Cipher":
            length = random.randint(5, 10)
            key = ''.join(random.choice(string.ascii_uppercase) for _ in range(length))
            self.first_key.set(key)
        elif first_algo == "Playfair Cipher":
            length = random.randint(5, 10)
            key = ''.join(random.choice(string.ascii_uppercase.replace('J', '')) for _ in range(length))
            self.first_key.set(key)
        elif first_algo == "Rail Fence Cipher":
            self.first_key.set(str(random.randint(2, 10)))
        elif first_algo == "Row-Column Transposition":
            length = random.randint(5, 10)
            key = ''.join(random.choice(string.ascii_uppercase) for _ in range(length))
            self.first_key.set(key)
        elif first_algo == "Mono-alphabetic Substitution":
            letters = list(string.ascii_uppercase)
            random.shuffle(letters)
            self.first_key.set(''.join(letters))
        elif first_algo == "S-DES":
            key = ''.join(random.choice('01') for _ in range(10))
            self.first_key.set(key)

        # Generate key for second algorithm
        if second_algo == "Caesar Cipher":
            self.second_key.set(str(random.randint(1, 25)))
        elif second_algo == "Vigenère Cipher":
            length = random.randint(5, 10)
            key = ''.join(random.choice(string.ascii_uppercase) for _ in range(length))
            self.second_key.set(key)
        elif second_algo == "Playfair Cipher":
            length = random.randint(5, 10)
            key = ''.join(random.choice(string.ascii_uppercase.replace('J', '')) for _ in range(length))
            self.second_key.set(key)
        elif second_algo == "Rail Fence Cipher":
            self.second_key.set(str(random.randint(2, 10)))
        elif second_algo == "Row-Column Transposition":
            length = random.randint(5, 10)
            key = ''.join(random.choice(string.ascii_uppercase) for _ in range(length))
            self.second_key.set(key)
        elif second_algo == "Mono-alphabetic Substitution":
            letters = list(string.ascii_uppercase)
            random.shuffle(letters)
            self.second_key.set(''.join(letters))
        elif second_algo == "S-DES":
            key = ''.join(random.choice('01') for _ in range(10))
            self.second_key.set(key)
    
    def double_encrypt(self):
        plaintext = self.double_cipher_input.get("1.0", tk.END).strip()
        first_algo = self.first_algo.get()
        second_algo = self.second_algo.get()
        
        if not first_algo or not second_algo:
            messagebox.showerror("Error", "Please select both algorithms")
            return
        
        # First encryption
        intermediate = self.apply_cipher(plaintext, first_algo, self.first_key.get(), encrypt=True)
        
        # Second encryption
        ciphertext = self.apply_cipher(intermediate, second_algo, self.second_key.get(), encrypt=True)
        
        self.double_cipher_output.delete('1.0', tk.END)
        self.double_cipher_output.insert(tk.END, ciphertext)
        
        summary = f"""
=== Double Encryption ===
First Algorithm: {first_algo} (Key: {self.first_key.get()})
Second Algorithm: {second_algo} (Key: {self.second_key.get()})
Input: {plaintext}
Intermediate: {intermediate}
Output: {ciphertext}
"""
        self.summary_text.insert(tk.END, summary)
        self.summary_text.see(tk.END)
    
    def double_decrypt(self):
        ciphertext = self.double_cipher_input.get("1.0", tk.END).strip()
        first_algo = self.first_algo.get()
        second_algo = self.second_algo.get()
        
        if not first_algo or not second_algo:
            messagebox.showerror("Error", "Please select both algorithms")
            return
        
        # First decryption (second algorithm)
        intermediate = self.apply_cipher(ciphertext, second_algo, self.second_key.get(), encrypt=False)
        
        # Second decryption (first algorithm)
        plaintext = self.apply_cipher(intermediate, first_algo, self.first_key.get(), encrypt=False)
        
        self.double_cipher_output.delete('1.0', tk.END)
        self.double_cipher_output.insert(tk.END, plaintext)
        
        summary = f"""
=== Double Decryption ===
First Algorithm: {first_algo} (Key: {self.first_key.get()})
Second Algorithm: {second_algo} (Key: {self.second_key.get()})
Input: {ciphertext}
Intermediate: {intermediate}
Output: {plaintext}
"""
        self.summary_text.insert(tk.END, summary)
        self.summary_text.see(tk.END)
    
    def apply_cipher(self, text, algorithm, key, encrypt=True):
        if algorithm == "Caesar Cipher":
            try:
                shift = int(key) if encrypt else -int(key)
                return self.caesar_cipher(text, shift)
            except ValueError:
                messagebox.showerror("Error", "Caesar cipher key must be an integer")
                return text
        elif algorithm == "Vigenère Cipher":
            if not key.isalpha():
                messagebox.showerror("Error", "Vigenère cipher key must contain only letters")
                return text
            return self.vigenere_cipher(text, key, encrypt)
        elif algorithm == "Playfair Cipher":
            if not key.isalpha():
                messagebox.showerror("Error", "Playfair cipher key must contain only letters")
                return text
            return self.playfair_cipher(text, key, encrypt)
        elif algorithm == "Rail Fence Cipher":
            try:
                rails = int(key)
                return self.railfence_cipher(text, rails, encrypt)
            except ValueError:
                messagebox.showerror("Error", "Rail fence cipher key must be an integer")
                return text
        elif algorithm == "Row-Column Transposition":
            if not key.isalpha():
                messagebox.showerror("Error", "Row-column cipher key must contain only letters")
                return text
            return self.rowcolumn_cipher(text, key, encrypt)
        elif algorithm == "Mono-alphabetic Substitution":
            if len(key) != 26 or not key.isalpha():
                messagebox.showerror("Error", "Mono-alphabetic cipher key must be a 26-letter permutation")
                return text
            return self.monoalphabetic_cipher(text, key, encrypt)
        elif algorithm == "S-DES":
            if not self.validate_sdes_key(key):
                messagebox.showerror("Error", "S-DES key must be a 10-bit binary string")
                return text
            if encrypt:
                return self.sdes_encrypt_block(text, key)
            else:
                return self.sdes_decrypt_block(text, key)
        return text

def main():
    root = ThemedTk(theme="black")  # Start with dark theme
    app = CipherApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()