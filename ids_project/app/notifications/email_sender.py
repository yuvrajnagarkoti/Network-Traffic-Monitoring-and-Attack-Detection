"""
SMTP email sender.

Sends a single email notification via a TLS-secured SMTP connection.
Supports both HTML and plain-text content.  All connection parameters
come from the Flask application configuration.

Configuration keys used:
  MAIL_SERVER         (str)  SMTP hostname
  MAIL_PORT           (int)  SMTP port (default 587 for STARTTLS)
  MAIL_USE_TLS        (bool) Use STARTTLS when True
  MAIL_USERNAME       (str)  SMTP login (empty → no auth)
  MAIL_PASSWORD       (str)  SMTP password
  MAIL_DEFAULT_SENDER (str)  From address
"""

import logging
import smtplib
import ssl
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Optional

logger = logging.getLogger(__name__)


class EmailSender:
    """Thin wrapper around smtplib for sending alert notifications."""

    def __init__(self, app=None) -> None:
        self.app = app

    def send(
        self,
        recipient: str,
        subject: str,
        body: str,
        html_body: Optional[str] = None,
    ) -> bool:
        """Send a single email message.

        Args:
            recipient:  Destination email address.
            subject:    Email subject line.
            body:       Plain-text fallback body.
            html_body:  Optional HTML body for rich mail clients.

        Returns:
            True on success, False on any SMTP error.
        """
        cfg = self._get_config()

        sender = cfg.get("MAIL_DEFAULT_SENDER", "ids@localhost")
        server = cfg.get("MAIL_SERVER", "localhost")
        port = int(cfg.get("MAIL_PORT", 587))
        use_tls = cfg.get("MAIL_USE_TLS", False)
        username = cfg.get("MAIL_USERNAME", "")
        password = cfg.get("MAIL_PASSWORD", "")

        try:
            msg = MIMEMultipart("alternative") if html_body else MIMEMultipart()
            msg["Subject"] = subject
            msg["From"] = sender
            msg["To"] = recipient

            msg.attach(MIMEText(body, "plain"))
            if html_body:
                msg.attach(MIMEText(html_body, "html"))

            if use_tls:
                context = ssl.create_default_context()
                with smtplib.SMTP(server, port, timeout=10) as smtp:
                    smtp.ehlo()
                    smtp.starttls(context=context)
                    if username:
                        smtp.login(username, password)
                    smtp.sendmail(sender, [recipient], msg.as_string())
            else:
                with smtplib.SMTP(server, port, timeout=10) as smtp:
                    if username:
                        smtp.login(username, password)
                    smtp.sendmail(sender, [recipient], msg.as_string())

            logger.info("Email sent to %s: %s", recipient, subject[:80])
            return True

        except smtplib.SMTPAuthenticationError as exc:
            logger.error("SMTP auth failed for %s: %s", server, exc)
        except smtplib.SMTPRecipientsRefused as exc:
            logger.error("Recipient refused %s: %s", recipient, exc)
        except smtplib.SMTPException as exc:
            logger.error("SMTP error sending to %s: %s", recipient, exc)
        except OSError as exc:
            logger.error("Network error connecting to SMTP %s:%d — %s", server, port, exc)

        return False

    def _get_config(self) -> dict:
        """Return app config as a plain dict."""
        if self.app is not None:
            return self.app.config
        from flask import current_app
        return current_app.config
