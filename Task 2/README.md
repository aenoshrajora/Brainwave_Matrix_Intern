# 🔐 Password Checker

A simple yet powerful **Password Checker** desktop application built with **Python** and **Tkinter**. Analyze the strength of your passwords, get security feedback, and generate strong, unique passwords with ease!

---

## 🚀 Features

✅ **Password Strength Analysis**  
✅ **Estimates Time to Crack Your Password**  
✅ **Detailed Feedback & Suggestions for Improvement**  
✅ **Checks Against a Large Common Password List (10,000+)**  
✅ **Password Generator with Custom Options**  
✅ **User-Friendly Interface (Resizable & Responsive)**  
✅ **Works Offline (No Internet Required)**

---

## 🛠️ Technologies Used

- **Python 3**
- **Tkinter** for the Graphical User Interface
- **zxcvbn** library for advanced password strength estimation
- **JSON** for managing the common passwords list
- **PIL (Pillow)** for image handling (optional)

---

## 📸 Screenshots

| Password Checker | Password Generator |
|------------------|--------------------|
| ![Password Checker](Password%20Checker.png) | ![Password Generator](Password%20Generator.png) |

---

## ⚙️ How It Works

### ✅ Password Checker
- Enter a password to analyze.
- Displays a **strength score** (Very Weak → Very Strong).
- Estimates **time to crack** the password.
- Gives **detailed feedback** on how to improve your password.
- Checks if your password appears in a **common password list** (top 10,000 passwords).

### 🔐 Password Generator
- Customize:
  - Length (8 to 64 characters)
  - Include **Uppercase Letters**
  - Include **Numbers**
  - Include **Symbols**
- Generates **random secure passwords** instantly.

---

## 📝 Installation & Setup

### 1. Clone the repository
```bash
git clone https://github.com/aenoshrajora/Brainwave_Matrix_Intern/tree/main/Task%202.git
cd Task\ 2
```

### 2. Install Dependencies
```bash
pip install zxcvbn pillow tkinter
```

### 3. Run the Application
```bash
python Password Checker.py
```
