import tkinter as tk
from tkinter import messagebox, scrolledtext, simpledialog
import binascii
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP
import socket
import json

class EncryptionService:
    def __init__(self):
        key = RSA.generate(2048)
        self.public_key = key.publickey().export_key()
        self.private_key = key.export_key()

    def encrypt_message(self, message):
        encryptor = PKCS1_OAEP.new(RSA.import_key(self.public_key))
        encrypted_data = encryptor.encrypt(message.encode())
        return binascii.hexlify(encrypted_data).decode('utf-8')

    def decrypt_message(self, encrypted_message):
        decryptor = PKCS1_OAEP.new(RSA.import_key(self.private_key))
        decrypted_data = decryptor.decrypt(binascii.unhexlify(encrypted_message))
        return decrypted_data.decode()


class User:
    def __init__(self, username, password):
        self.username = username
        self.password = password
        self.email_accounts = []

    def add_email_account(self, email_address):
        # Check if an account with this email already exists
        for account in self.email_accounts:
            if account.email_address == email_address:
                return account
        # If not, create a new one
        new_account = EmailAccount(email_address, self)
        self.email_accounts.append(new_account)
        return new_account


class EmailAccount:
    def __init__(self, email_address, user):
        self.email_address = email_address
        self.user = user
        self.mailbox = []

    def send_email(self, recipients, subject, body, encryption_service):
        email = EmailMessage(self.email_address, recipients, subject, body)
        email.encrypt(encryption_service)
        self.mailbox.append(email)  # Simulating email sending by storing in mailbox
        return email

    def receive_email(self, email_message, encryption_service):
        email_message.decrypt(encryption_service)
        self.mailbox.append(email_message)  # Simulating email reception


class EmailMessage:
    def __init__(self, sender, recipients, subject, body):
        self.sender = sender
        self.recipients = recipients
        self.subject = subject
        self.body = body
        self.encrypted = False

    def encrypt(self, encryption_service):
        self.body = encryption_service.encrypt_message(self.body)
        self.encrypted = True

    def decrypt(self, encryption_service):
        if self.encrypted:
            self.body = encryption_service.decrypt_message(self.body)
            self.encrypted = False


class JsonSocketClient:
    def __init__(self, server_ip, server_port):
        self.server_ip = server_ip
        self.server_port = server_port
        self.client_socket = None
        self.create_socket()

    def create_socket(self):
        """Create a new socket."""
        if self.client_socket is not None:
            self.client_socket.close()
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def connect(self):
        """Connect to the server."""
        try:
            self.client_socket.connect((self.server_ip, self.server_port))
            print(f"Connected to {self.server_ip} on port {self.server_port}.")
        except socket.error as e:
            print(f"Failed to connect: {e}")
            self.create_socket()  # Recreate the socket if connect fails

    def send_message(self, message):
        """Send a message to the server."""
        try:
            self.client_socket.sendall(message.encode())
        except Exception as e:
            print(f"Failed to send message: {e}")

    def receive_message(self):
        """Receive a message from the server."""
        try:
            response = self.client_socket.recv(1024)
            return response.decode()
        except Exception as e:
            print(f"Failed to receive message: {e}")
            return None
    def send_json(self, data):
        """Send JSON data to the server."""
        try:
            # Serialize the data to a JSON formatted str and encode to bytes
            json_data = json.dumps(data).encode('utf-8')
            self.client_socket.sendall(json_data)
            print("JSON data sent successfully.")
        except Exception as e:
            print(f"Failed to send JSON data: {e}")

    def close(self):
        """Close the socket connection."""
        if self.client_socket:
            self.client_socket.close()
            print("Connection closed.")



class ApplicationGUI:
    def __init__(self, master):
        self.master = master
        self.master.title("Secure Email Client")

        self.encryption_service = EncryptionService()  # Ensure it is a class attribute
        self.logged_in_user = None  # This will be a User object after login

        self.login_frame = tk.Frame(master)
        self.email_frame = None
        self.setup_login_frame()

    def setup_login_frame(self):
        tk.Label(self.login_frame, text="Username").pack()
        self.username_entry = tk.Entry(self.login_frame)
        self.username_entry.pack()

        tk.Label(self.login_frame, text="Password").pack()
        self.password_entry = tk.Entry(self.login_frame, show='*')
        self.password_entry.pack()

        tk.Button(self.login_frame, text="Login", command=self.login).pack()
        self.login_frame.pack()

    def login(self):
        username = self.username_entry.get()
        password = self.password_entry.get()  # In real applications, handle password securely
        self.logged_in_user = User(username, password)
        self.setup_email_interface()

    def setup_email_interface(self):
        if self.login_frame:
            self.login_frame.pack_forget()
        self.email_frame = tk.Frame(self.master)
        tk.Label(self.email_frame, text="Welcome, " + self.logged_in_user.username).pack()
        tk.Button(self.email_frame, text="Send Email", command=self.send_email).pack()
        self.email_frame.pack()

    def send_email(self):
        recipient = simpledialog.askstring("Recipient", "Enter the recipient's email:")
        subject = simpledialog.askstring("Subject", "Enter the subject:")
        body = simpledialog.askstring("Body", "Enter the body:")
        if recipient and subject and body:
            # Ensure that user has an email account
            if not self.logged_in_user.email_accounts:
                account = self.logged_in_user.add_email_account(self.logged_in_user.username + "@example.com")
            else:
                account = self.logged_in_user.email_accounts[0]  # Use the first account
            email = account.send_email([recipient], subject, body, self.encryption_service)
            messagebox.showinfo("Success", "Email sent with encrypted body: " + email.body)


if __name__ == "__main__":
    server_ip = "192.168.149.57"  # Địa chỉ IP của server
    server_port = 25  # Cổng mà server đang lắng nghe
    client = JsonSocketClient(server_ip, server_port)
    # Example JSON data
    json_data = {
        "name": "John Doe",
        "email": "john@example.com",
        "age": 30
    }

    client.connect()
    client.send_message("Hello, server!")
    client.send_json(json_data)
    response = client.receive_message()
    Connect = client.connect()
    if response:
        print("Received from server:", response)
    if Connect == False :
        client.close()
    root = tk.Tk()
    app = ApplicationGUI(root)
    root.mainloop()
