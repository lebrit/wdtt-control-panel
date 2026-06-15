import unittest

from wdtt_panel.security import (
    create_session,
    hash_password,
    read_session,
    verify_csrf,
    verify_password,
)


class SecurityTests(unittest.TestCase):
    def test_password_hash_roundtrip(self):
        encoded = hash_password("A-long-panel-password-123")
        self.assertTrue(verify_password("A-long-panel-password-123", encoded))
        self.assertFalse(verify_password("wrong-password", encoded))

    def test_signed_session_and_csrf(self):
        token, csrf = create_session("admin", "session-secret", ttl=60)
        session = read_session(token, "session-secret")
        self.assertIsNotNone(session)
        self.assertTrue(verify_csrf(csrf, session, "session-secret"))
        self.assertFalse(verify_csrf("wrong", session, "session-secret"))
        self.assertIsNone(read_session(token + "x", "session-secret"))


if __name__ == "__main__":
    unittest.main()
