import binascii
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP
import smtplib
import os
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from received_mail import receive_emails_imap
# User Class
class User:
    def __init__(self,username, password):
        self.username = username
        self.password = password  # This should be hashed in a real application
        self.emailAccounts = []

    def addEmailAccount(self, emailAccount):
        self.emailAccounts.append(emailAccount)

    def removeEmailAccount(self, emailAccount):
        self.emailAccounts.remove(emailAccount)

# EmailAccount Class
class EmailAccount:
    def __init__(self, accountID, emailAddress, user):
        self.accountID = accountID
        self.emailAddress = emailAddress
        self.user = user
        self.mailbox = []

    def sendEmail(self, emailMessage, storage_service):
        emailMessage.sender = self.emailAddress
        storage_service.saveEmail(emailMessage)

# EmailMessage Class
class EmailMessage:
    def __init__(self, messageID, sender, recipients, subject, body, attachments=None, encrypted=False):
        self.messageID = messageID
        self.sender = sender
        self.recipients = recipients
        self.subject = subject
        self.body = body
        self.attachments = attachments if attachments else []
        self.encrypted = encrypted

    def encrypt(self, encryption_service):
        if not self.encrypted:
            self.body = encryption_service.encrypt_message(self.body)
            self.encrypted = True

    def decrypt(self, encryption_service):
        if self.encrypted:
            self.body = encryption_service.decrypt_message(self.body)
            self.encrypted = False

# EncryptionService Class
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

# SMTPService Class
class SMTPClient:
    def __init__(self, server_address, port, timeout, username=None, password=None, use_tls=True):
        self.server_address = server_address
        self.port = port
        self.username = username
        self.password = password
        self.use_tls = use_tls
        self.connection = None
        self.timeout = timeout

    def connect(self):
        """Connect to the SMTP server and optionally start TLS."""
        self.connection = smtplib.SMTP(self.server_address, self.port, timeout=self.timeout)
        self.connection.ehlo()  # Can be called for all SMTP servers.
        if self.use_tls:
            self.connection.starttls()
            self.connection.ehlo()  # Say hello again after starting TLS
        if self.username and self.password:
            self.connection.login(self.username, self.password)

    def send_email(self, sender, recipients, subject, body):
        """Send an email through the connected SMTP server."""
        if not self.connection:
            raise Exception("SMTP client is not connected to a server.")

        message = MIMEMultipart()
        message['From'] = sender
        message['To'] = ', '.join(recipients)
        message['Subject'] = subject
        message.attach(MIMEText(body, 'plain'))

        self.connection.sendmail(sender, recipients, message.as_string())

    def disconnect(self):
        """Close the connection to the SMTP server."""
        if self.connection:
            self.connection.quit()
            self.connection = None

# StorageService Class
class StorageService:
    def __init__(self, storage_location):
        self.storage_location = storage_location
        if not os.path.exists(storage_location):
            os.makedirs(storage_location)

    def saveEmail(self, message):
        with open(f"{self.storage_location}/{message.messageID}.txt", "wb") as file:
            file.write(f"Subject: {message.subject}\nBody: {message.body}".encode())

    def retrieveEmail(self, messageID):
        try:
            with open(f"{self.storage_location}/{messageID}.txt", "rb") as file:
                return file.read().decode()
        except FileNotFoundError:
            return None

# Main function to test classes
def main():
    # Create user and services
    user1 = User("minhdq@unomail.id.vn", "Minhdo962004")
    encryption_service = EncryptionService()
    storage_service = StorageService('/path/to/email/storage')  # Adjust path as needed

    # Create and add an email account to the user
    email_account = EmailAccount("1", "user1@example.com", user1)
    user1.addEmailAccount(email_account)

    # Create an email message
    email = EmailMessage("001", "minhdq@unomail.id.vn", "hahahaha@unomail.id.vn", "Test Subject", "Hello, this is a test email.")

    # Encrypt, send, and save the email
    email.encrypt(encryption_service)
    email_account.sendEmail(email, storage_service)

    # Retrieve and decrypt the email for display
    retrieved_email_content = storage_service.retrieveEmail("001")
    print("Retrieved Email Content:", retrieved_email_content)

    #Connect to Server
    smtp_client = SMTPClient("192.168.117.57", 587, 120, username="minhdq@unomail.id.vn",password="Minhdo962004", use_tls=True)
    try:
        smtp_client.connect()
        smtp_client.send_email("minhdq@unomail.id.vn", "hahahaha@unomail.id.vn", "Test Subject",
                               "This is a test email sent via SMTPClient class.")
        print("Email sent successfully!")
    except Exception as e:
        print(f"Failed to send email: {e}")
    finally:
        smtp_client.disconnect()

    server = 'imap.example.com'
    port = 993
    username = 'your-email@example.com'
    password = 'yourpassword'

    # Receive all emails
    emails = receive_emails_imap(server, port, username, password)
if __name__ == "__main__":
    main()
