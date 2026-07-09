from dotenv import load_dotenv
import os
from pathlib import Path

try:
    import sib_api_v3_sdk
    from sib_api_v3_sdk.rest import ApiException
except ImportError:
    sib_api_v3_sdk = None
    ApiException = Exception

load_dotenv(Path(__file__).resolve().parent / ".env")

BREVO_API_KEY = os.getenv("BREVO_API_KEY")
SENDER_EMAIL = os.getenv("SENDER_EMAIL")
SENDER_NAME = os.getenv("SENDER_NAME", "AI Security Platform")


def send_otp_email(receiver_email: str, otp: str):
    if not BREVO_API_KEY or not SENDER_EMAIL:
        print("Brevo email is not configured; OTP email was not sent.")
        return False

    if sib_api_v3_sdk is None:
        print("sib-api-v3-sdk is not installed; OTP email was not sent.")
        return False

    configuration = sib_api_v3_sdk.Configuration()
    configuration.api_key["api-key"] = BREVO_API_KEY

    api_instance = sib_api_v3_sdk.TransactionalEmailsApi(
        sib_api_v3_sdk.ApiClient(configuration)
    )

    subject = "Email Verification OTP"

    html_content = f"""
    <html>
    <body style="font-family:Arial,sans-serif">
        <h2>AI Security Intelligence Platform</h2>

        <p>Your verification code is:</p>

        <h1 style="letter-spacing:5px;color:#2563eb;">
            {otp}
        </h1>

        <p>This OTP will expire in <b>10 minutes</b>.</p>

        <p>If you didn't request this, ignore this email.</p>

        <hr>

        <small>AI Security Intelligence Platform</small>
    </body>
    </html>
    """

    email = sib_api_v3_sdk.SendSmtpEmail(
        to=[{"email": receiver_email}],
        sender={
            "email": SENDER_EMAIL,
            "name": SENDER_NAME
        },
        subject=subject,
        html_content=html_content
    )

    try:
        print("=" * 60)
        print("Sending OTP Email...")
        print(f"To: {receiver_email}")
        print(f"Sender: {SENDER_EMAIL}")

        response = api_instance.send_transac_email(email)

        print("Brevo Response:")
        print(response)

        print("=" * 60)

        return True

    except ApiException as e:
        print("=" * 60)
        print("BREVO ERROR")
        print(e)
        print("=" * 60)
        return False
