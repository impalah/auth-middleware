"""Tests for User.email tolerating blank claims from IdPs that send `email: ""`."""

import pytest
from pydantic import ValidationError

from auth_middleware.types.user import User


class TestUserBlankEmail:
    """A blank/whitespace-only email claim must not fail User construction."""

    def test_empty_string_email_becomes_none(self):
        """Empty-string email, e.g. Authentik's claim for a user with none set."""
        user = User(id="user-1", name="No Email", email="")

        assert user.email is None

    def test_whitespace_only_email_becomes_none(self):
        """Whitespace-only email is blank in intent, not a real address."""
        user = User(id="user-2", name="Blank Email", email="   ")

        assert user.email is None

    def test_none_email_stays_none(self):
        """Explicit None is unaffected (already the documented default)."""
        user = User(id="user-3", name="Null Email", email=None)

        assert user.email is None

    def test_missing_email_defaults_to_none(self):
        """Omitting email entirely still defaults to None."""
        user = User(id="user-4", name="No Email Field")

        assert user.email is None

    def test_valid_email_is_preserved(self):
        """A real address still validates and round-trips unchanged."""
        user = User(id="user-5", name="Real Email", email="ana@example.com")

        assert user.email == "ana@example.com"

    def test_invalid_non_blank_email_still_rejected(self):
        """A non-blank but malformed address must still fail validation."""
        with pytest.raises(ValidationError, match="email"):
            User(id="user-6", name="Bad Email", email="not-an-email")
