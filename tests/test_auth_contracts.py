import os
import sys
from pathlib import Path

os.environ.setdefault("DATABASE_URL", "postgresql://user:pass@localhost:5432/aisecurity_test")
os.environ.setdefault("SECRET_KEY", "test-secret")
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

import pytest
from pydantic import ValidationError

from schemas import ResetPasswordRequest, UserSignup
from security import generate_api_key, hash_password, verify_password


def test_signup_schema_accepts_frontend_payload():
    payload = UserSignup(email="analyst@example.com", password="Str0ng!Pass", full_name="Security Analyst")

    assert payload.email == "analyst@example.com"
    assert payload.full_name == "Security Analyst"


def test_reset_password_requires_six_digit_otp_shape():
    with pytest.raises(ValidationError):
        ResetPasswordRequest(email="analyst@example.com", otp="123", new_password="Str0ng!Pass")


def test_password_hashing_uses_non_plaintext_hash():
    password = "Str0ng!Pass"
    hashed = hash_password(password)

    assert hashed != password
    assert verify_password(password, hashed)


def test_generated_api_key_has_lookup_prefix_and_hash():
    raw_key, key_hash, prefix = generate_api_key()

    assert raw_key.startswith("sk_live_")
    assert prefix == raw_key[:12]
    assert key_hash != raw_key
    assert len(key_hash) == 64
