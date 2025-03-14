import tkinter as tk
from tkinter import ttk
import json
import os
import random
import string
from zxcvbn import zxcvbn

class EnhancedPasswordCheckerAndGenerator:
    def __init__(self, root):
        self.root = root
        self.root.title("Password Checker")
        self.root.geometry("700x700")
        self.root.minsize(600, 600)

        # Theme colors
        self.primary_color = "#1976d2"
        self.secondary_color = "#2196f3"
        self.accent_color = "#ff9800"
        self.background_color = "#f5f7fa"
        self.text_color = "#263238"
        self.light_text = "#546e7a"

        self.strength_colors = {
            0: "#e53935",  # Very Weak
            1: "#ff7043",  # Weak
            2: "#ffb300",  # Medium
            3: "#7cb342",  # Strong
            4: "#43a047"   # Very Strong
        }

        # Load common passwords
        self.common_passwords = self.load_common_passwords()

        # UI setup
        self.setup_ui()

    def load_common_passwords(self):
        """Load a large list of common passwords"""
        default_common_passwords = {"123456", "password", "123456789", "qwerty", "abc123",
                                    "password1", "111111", "12345678", "iloveyou", "admin"}

        # Load from a file if available
        common_pwd_file = "common_passwords.json"
        if os.path.exists(common_pwd_file):
            try:
                with open(common_pwd_file, 'r') as file:
                    return set(json.load(file))
            except Exception as e:
                print(f"Failed loading common passwords: {e}")

        # Fall back to default
        return default_common_passwords

    def setup_ui(self):
        # Title
        title = tk.Label(self.root, text="Password Checker", font=("Segoe UI", 22, "bold"),
                         fg=self.primary_color, bg=self.background_color)
        title.pack(pady=20)

        # Notebook (tabs)
        self.tab_control = ttk.Notebook(self.root)

        # Password Checker tab
        self.checker_tab = tk.Frame(self.tab_control, bg=self.background_color)
        self.tab_control.add(self.checker_tab, text="Password Checker")
        self.setup_checker_tab()

        # Password Generator tab
        self.generator_tab = tk.Frame(self.tab_control, bg=self.background_color)
        self.tab_control.add(self.generator_tab, text="Password Generator")
        self.setup_generator_tab()

        self.tab_control.pack(expand=True, fill=tk.BOTH)

    def setup_checker_tab(self):
        frame = self.checker_tab

        # Password Entry
        label = tk.Label(frame, text="Enter Your Password:", font=("Segoe UI", 14), fg=self.text_color,
                         bg=self.background_color)
        label.pack(pady=(20, 5))

        entry_frame = tk.Frame(frame, bg=self.background_color)
        entry_frame.pack(pady=5)

        self.password_var = tk.StringVar()
        self.password_entry = ttk.Entry(entry_frame, textvariable=self.password_var, show="*", font=("Segoe UI", 14), width=30)
        self.password_entry.pack(side=tk.LEFT, ipady=5)

        self.show_password_var = tk.BooleanVar()
        show_checkbox = ttk.Checkbutton(entry_frame, text="Show", variable=self.show_password_var,
                                        command=self.toggle_password_visibility)
        show_checkbox.pack(side=tk.LEFT, padx=10)

        # Analyze Button
        analyze_button = ttk.Button(frame, text="Analyze Password", command=self.analyze_password)
        analyze_button.pack(pady=20)

        # Strength Meter
        self.strength_label = tk.Label(frame, text="Password Strength: None", font=("Segoe UI", 12, "bold"),
                                       fg=self.text_color, bg=self.background_color)
        self.strength_label.pack()

        self.strength_meter = tk.Canvas(frame, width=300, height=20, bg="#e0e0e0", bd=0, highlightthickness=0)
        self.strength_meter.pack(pady=10)

        # Crack Time
        self.crack_time_label = tk.Label(frame, text="Estimated Time to Crack: N/A", font=("Segoe UI", 12),
                                         fg=self.light_text, bg=self.background_color)
        self.crack_time_label.pack(pady=5)

        # Analysis & Feedback
        feedback_label = tk.Label(frame, text="Analysis & Feedback", font=("Segoe UI", 14, "bold"),
                                  fg=self.primary_color, bg=self.background_color)
        feedback_label.pack(pady=(20, 5))

        self.feedback_text = tk.Text(frame, height=10, wrap=tk.WORD, font=("Segoe UI", 11),
                                     bg=self.background_color, fg=self.text_color, bd=1, relief=tk.SOLID)
        self.feedback_text.pack(expand=True, fill=tk.BOTH, padx=10, pady=10)
        self.feedback_text.config(state=tk.DISABLED)

    def setup_generator_tab(self):
        frame = self.generator_tab

        label = tk.Label(frame, text="Generate a Strong Password", font=("Segoe UI", 14, "bold"),
                         fg=self.primary_color, bg=self.background_color)
        label.pack(pady=(20, 10))

        # Options
        options_frame = tk.Frame(frame, bg=self.background_color)
        options_frame.pack(pady=5)

        tk.Label(options_frame, text="Length:", font=("Segoe UI", 12), bg=self.background_color).grid(row=0, column=0, padx=5)
        self.length_var = tk.IntVar(value=12)
        length_spinbox = tk.Spinbox(options_frame, from_=8, to=64, textvariable=self.length_var, width=5)
        length_spinbox.grid(row=0, column=1, padx=5)

        self.include_uppercase = tk.BooleanVar(value=True)
        tk.Checkbutton(options_frame, text="Uppercase", variable=self.include_uppercase,
                       bg=self.background_color).grid(row=0, column=2, padx=5)

        self.include_numbers = tk.BooleanVar(value=True)
        tk.Checkbutton(options_frame, text="Numbers", variable=self.include_numbers,
                       bg=self.background_color).grid(row=0, column=3, padx=5)

        self.include_symbols = tk.BooleanVar(value=True)
        tk.Checkbutton(options_frame, text="Symbols", variable=self.include_symbols,
                       bg=self.background_color).grid(row=0, column=4, padx=5)

        # Generate Button
        generate_button = ttk.Button(frame, text="Generate Password", command=self.generate_password)
        generate_button.pack(pady=20)

        # Result
        self.generated_password_var = tk.StringVar()
        generated_password_entry = ttk.Entry(frame, textvariable=self.generated_password_var, font=("Segoe UI", 14), width=30)
        generated_password_entry.pack(pady=10, ipady=5)

    def toggle_password_visibility(self):
        show_char = "" if self.show_password_var.get() else "*"
        self.password_entry.config(show=show_char)

    def analyze_password(self):
        password = self.password_var.get()
        if not password:
            self.show_feedback("Please enter a password to analyze.", is_error=True)
            return

        # Zxcvbn analysis
        results = zxcvbn(password)
        score = results['score']
        crack_time = results['crack_times_display']['offline_slow_hashing_1e4_per_second']
        feedback = results['feedback']

        # Update strength meter
        self.update_strength_meter(score)

        # Update strength label and crack time
        strength_texts = ["Very Weak", "Weak", "Medium", "Strong", "Very Strong"]
        self.strength_label.config(text=f"Password Strength: {strength_texts[score]}")
        self.crack_time_label.config(text=f"Estimated Time to Crack: {crack_time}")

        # Custom Analysis & Feedback
        analysis = self.create_analysis(password, results)
        self.show_feedback(analysis)

    def update_strength_meter(self, score):
        self.strength_meter.delete("all")
        fill_color = self.strength_colors[score]
        width = (score + 1) * 60
        self.strength_meter.create_rectangle(0, 0, width, 20, fill=fill_color, outline="")

    def show_feedback(self, text, is_error=False):
        self.feedback_text.config(state=tk.NORMAL)
        self.feedback_text.delete(1.0, tk.END)
        self.feedback_text.insert(tk.END, text)
        self.feedback_text.config(state=tk.DISABLED)

    def create_analysis(self, password, results):
        feedback_lines = []

        # Length Check
        if len(password) < 8:
            feedback_lines.append("❌ Password is too short. Minimum 8 characters recommended.")
        elif len(password) >= 12:
            feedback_lines.append("✅ Great! Your password has a strong length.")

        # Common password check
        if password.lower() in self.common_passwords:
            feedback_lines.append("❌ This password is too common! Choose something more unique.")

        # Character variety
        if not any(c.islower() for c in password):
            feedback_lines.append("❌ No lowercase letters found.")
        if not any(c.isupper() for c in password):
            feedback_lines.append("❌ No uppercase letters found.")
        if not any(c.isdigit() for c in password):
            feedback_lines.append("❌ No numbers found.")
        if not any(c in string.punctuation for c in password):
            feedback_lines.append("❌ No symbols found.")

        # Zxcvbn feedback
        if results['feedback']['warning']:
            feedback_lines.append(f"⚠️ {results['feedback']['warning']}")
        for suggestion in results['feedback']['suggestions']:
            feedback_lines.append(f"💡 {suggestion}")

        # If no feedback, it's very strong!
        if not feedback_lines:
            feedback_lines.append("✅ Your password looks excellent!")

        return "\n".join(feedback_lines)

    def generate_password(self):
        length = self.length_var.get()
        if length < 8:
            length = 8

        chars = string.ascii_lowercase
        if self.include_uppercase.get():
            chars += string.ascii_uppercase
        if self.include_numbers.get():
            chars += string.digits
        if self.include_symbols.get():
            chars += string.punctuation

        if not chars:
            self.generated_password_var.set("Select at least one option!")
            return

        password = ''.join(random.choice(chars) for _ in range(length))
        self.generated_password_var.set(password)

# Run the app
if __name__ == "__main__":
    root = tk.Tk()
    app = EnhancedPasswordCheckerAndGenerator(root)
    root.mainloop()
