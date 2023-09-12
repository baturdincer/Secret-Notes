from tkinter import *
from PIL import ImageTk, Image
from cryptography.fernet import Fernet
import os

def generate_key():
    """
    Generates a key and save it into a file
    """
    key = Fernet.generate_key()
    with open("secret.key", "wb") as key_file:
        key_file.write(key)

def load_key():
    """
    Load the previously generated key
    """
    if os.stat("secret.key").st_size == 0:
        generate_key()

    with open("secret.key", "rb") as keyfile:
        key= keyfile.read()

    return key

def encrypt_message(message):
    """
    Decrypts a message
    """
    key = load_key()
    encoded_message = message.encode()
    f = Fernet(key)
    encrypted_message = f.encrypt(encoded_message)
    return encrypted_message

def decrypt_message(message):
    """
    Encrypts a message
    """
    key = load_key()
    encoded_message = message.encode()
    f = Fernet(key)
    decrypted_message = str(f.decrypt(encoded_message),"utf8")
    return decrypted_message


def titlefunc():
    title=titleEntry.get()
    return title

def secretfunc():
    secret=secretText.get("1.0",END)
    return secret

def masterkeyfunc():
    masterkey=masterKeyEntry.get()
    return masterkey

def encryptsave():
    with open("secretnotes.txt", "a") as file:
        file.writelines(titlefunc()+'\n')
        file.writelines(str(encrypt_message(secretfunc()),'utf8')+"\n")
        file.writelines(str(encrypt_message(masterkeyfunc()),'utf8')+"\n")
    titleEntry.delete(0,END)
    secretText.delete("1.0",END)
    masterKeyEntry.delete(0, END)

def decryptfunc():
    decryptedsecret = "Enter correct title or masterkey"
    title=titlefunc()
    password=masterkeyfunc()
    titleEntry.delete(0,END)
    secretText.delete("1.0",END)
    masterKeyEntry.delete(0, END)
    with open("secretnotes.txt", "r") as file:
        lines=file.readlines()
    for i in range(len(lines)):
        if (title+"\n")==lines[i]:
            print("no problem")
            masterkey= decrypt_message(lines[i+2])
            if masterkey== password:
                decryptedsecret=decrypt_message(lines[i+1])
                print("no problem")
    secretText.insert("1.0",decryptedsecret)

window = Tk()
window.title("Secret Notes")
window.minsize(height=800, width=500)
window.config(padx=30,pady=50)

img = Image.open("seal.png")
img = img.resize(size=(130,130))
img=ImageTk.PhotoImage(img)
panel = Label(window, image = img)
panel.pack()
padtext1= Label(pady=25)
padtext1.pack()

titleLabel= Label(text="Enter your title", font=("Arial", 15))
titleLabel.pack()
titleEntry=Entry(width=40)
titleEntry.pack()
padtext2= Label()
padtext2.pack()

secretLabel= Label(text="Enter your secret", font=("Arial", 15))
secretLabel.pack()
secretText=Text(width=50,height=20)
secretText.pack()

masterKeyLabel=Label(text="Enter master key", font=("Arial", 15))
masterKeyLabel.pack()
masterKeyEntry=Entry(width=50)
masterKeyEntry.pack()

encryptButton=Button(text="Save & encrypt", command=encryptsave)
encryptButton.pack()

decryptButton=Button(text="Decrypt",command=decryptfunc)
decryptButton.pack()

window.mainloop()