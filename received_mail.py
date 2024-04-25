import imaplib
import email


def receive_emails_imap(server, port, username, password, mailbox='INBOX', search_criteria='ALL'):
    # Connect to the IMAP server
    mail = imaplib.IMAP4_SSL(server, port)

    # Login to the server
    mail.login(username, password)

    # Select the mailbox (folder) you want to interact with
    mail.select(mailbox)

    # Search for all emails or emails based on a specific search criteria
    result, data = mail.search(None, search_criteria)
    if result != 'OK':
        print("No messages found!")
        return []

    # Fetch all the emails based on the search criteria
    emails = []
    for num in data[0].split():
        result, data = mail.fetch(num, '(RFC822)')  # Fetch the full email
        if result != 'OK':
            print("ERROR getting message", num)
            continue

        # Parse the email content to a readable format
        msg = email.message_from_bytes(data[0][1])
        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_type() == "text/plain":
                    body = part.get_payload(decode=True)
                    print("From:", msg['From'])
                    print("Subject:", msg['Subject'])
                    print("Body:", body.decode())
        else:
            body = msg.get_payload(decode=True)
            print("From:", msg['From'])
            print("Subject:", msg['Subject'])
            print("Body:", body.decode())

        emails.append(msg)

    # Logout from the server
    mail.logout()

    return emails

