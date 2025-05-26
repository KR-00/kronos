import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

def send_email_alert(subject, body, from_email, app_password, to_email):
    """
    Sends an email alert using Gmail SMTP.
    
    Args:
        subject (str): Subject of the email
        body (str): Body of the email
        from_email (str): Sender Gmail address
        app_password (str): Gmail App password
        to_email (str): Receiver email address
    """
    try:
        # Create the email content
        msg = MIMEMultipart()
        msg['From'] = from_email
        msg['To'] = to_email
        msg['Subject'] = subject

        msg.attach(MIMEText(body, 'plain'))

        # Connect to Gmail SMTP server
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(from_email, app_password)
        server.send_message(msg)
        server.quit()
        
        print("[+] Email alert sent successfully.")
        
    except Exception as e:
        print(f"[!] Failed to send email alert: {e}")
