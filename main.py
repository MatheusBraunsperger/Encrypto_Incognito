import tkinter.messagebox
from tkinter import *
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet


def user_interface():
    def button_command_decrypt():
        if entry_key.get() == "" or len(entry_msg.get('1.0', END)) == 1:
            print("botão has been pressed")
            tkinter.messagebox.showerror(title="ERROR", message="Required fields are blank")

        else:
            # Generate Key
            password_privided = entry_key.get()  # can be a input in a string format
            password = password_privided.encode()  # convert to bytes

            salt = b'\n\x99\xfa\x08v.\x83^\xd5\xe1\x00a\xef,D\xe4'

            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
                backend=default_backend()
            )

            key = base64.urlsafe_b64encode(kdf.derive(password))
            # print(key)

            # Save key to file
            # file = open("Key.txt", "w")
            # file.write(str(key))
            # file.close()

            # Mensagem e dar encode nela
            message = entry_msg.get('1.0', END)
            encrypted = message.encode()

            # criar objeto Fernet
            f = Fernet(key)

            # Descriptografar
            decrypted = f.decrypt(encrypted).decode("utf-8")
            print(decrypted)
            entry_msg.delete('1.0', END)
            entry_msg.insert('1.0', decrypted)

    def button_command_incrypt():

        if entry_key.get() == "" or len(entry_msg.get('1.0', END)) == 1:
            print("botão has been pressed")
            tkinter.messagebox.showerror(title="ERROR", message="Required fields are blank")

        else:
            # Generate Key
            password_privided = entry_key.get()  # can be a input in a string format
            password = password_privided.encode()  # convert to bytes

            salt = b'\n\x99\xfa\x08v.\x83^\xd5\xe1\x00a\xef,D\xe4'

            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
                backend=default_backend()
            )

            key = base64.urlsafe_b64encode(kdf.derive(password))
            print(key)

            # Save key to file
            # file = open("Key.txt", "w")
            # file.write(str(password_privided))
            # file.close()

            # Mensagem e dar encode nela
            message = entry_msg.get('1.0', END)
            encoded = message.encode()

            # criar objeto Fernet
            f = Fernet(key)

            # Criptografar
            encrypted = f.encrypt(encoded).decode("utf-8")
            print(encrypted)
            entry_msg.delete('1.0', END)
            entry_msg.insert('1.0', encrypted)

    version = "0.3.1"

    # janela
    janela = Tk()
    janela.title("Encrypto Incognito " + version)
    # janela.iconbitmap(r"logo.ico")
    janela.configure(bg="grey33")
    janela.geometry("620x300")
    janela.resizable(False, False)

    texto_inicial = Label(janela, text="Encrypt or Decrypt, your call :", bg="grey33", font=55, fg="white")
    texto_inicial.grid(row=1, column=2, pady=10)
    texto_inicial.config(font=("Calibri", 20))

    # -----------------------------------------------------------------------------------------------------
    frame_content = Frame(janela, width=100, bg="grey33")
    frame_content.grid(row=2, column=2, padx=20, pady=10)

    msg_label = Label(frame_content, text="Key", bg="grey33", fg="white")
    msg_label.grid(row=1, column=2, sticky=W)
    entry_key = Entry(frame_content, width=70)
    entry_key.grid(row=2, column=2)

    msg_label2 = Label(frame_content, text="Text you want do encrypt or decrypt", bg="grey33", fg="white")
    msg_label2.grid(row=3, column=2, sticky=W)
    entry_msg = Text(frame_content, width=53, height=3)
    entry_msg.grid(row=4, column=2)

    # -----------------------------------------------------------------------------------------------------
    frame_buttons = Frame(janela, width=100, bg="grey33")
    frame_buttons.grid(row=3, column=2, padx=20, pady=10)

    Button(frame_buttons, text="Encrypt", command=button_command_incrypt).grid(row=1, column=1, padx=20)
    Button(frame_buttons, text="Decrypt", command=button_command_decrypt).grid(row=1, column=2, padx=20)

    # -----------------------------------------------------------------------------------------------------

    frame_description = Frame(janela, width=10, bg="grey33")
    frame_description.grid(row=1, column=3, rowspan=3, padx=0, pady=10)
    teste_label = Text(frame_description, width=17, height=17, bg="grey33", fg="white")
    teste_label.grid(row=1, column=1)

    teste_label.insert("1.0",
"""     Read Me
You can write any
key that you like
just don't forget
it, you will need
it to decryption              
    Have Fun                   
    _____  __   
  /\_____\/\_\  
 ( (_____/\/_/  
  \ \__\   /\_\ 
  / /__/_ / / / 
 ( (_____( (_(  
  \/_____/\/_/  
""")

    janela.mainloop()


user_interface()



