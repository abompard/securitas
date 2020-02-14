import datetime
import re
from unittest import mock

import jwt
import pytest
import python_freeipa
from bs4 import BeautifulSoup
from flask import get_flashed_messages, current_app

from securitas import ipa_admin, mailer
from securitas.security.ipa import untouched_ipa_client
from securitas.utility.password_reset import PasswordResetLock


@pytest.fixture
def token_for_dummy_user(dummy_user):
    last_change = ipa_admin.user_show("dummy")["krblastpwdchange"]
    return str(
        jwt.encode(
            {"username": "dummy", "last_change": last_change},
            current_app.config["SECRET_KEY"],
            algorithm="HS256",
        ),
        "ascii",
    )


def test_password_reset(client):
    """Test the password reset page"""
    result = client.get('/password-reset?username=fred')
    page = BeautifulSoup(result.data, 'html.parser')
    assert page.title
    assert page.title.string == 'Password Reset - The Fedora Project'


def test_password_reset_no_username(client):
    """Test the password reset page with no username """
    result = client.get('/password-reset')
    assert result.status_code == 404


@pytest.mark.vcr()
def test_password_reset_user(client, logged_in_dummy_user):
    """Test the redirect to the authed password reset"""
    result = client.get('/password-reset')
    assert result.location == f"http://localhost/user/dummy/password-reset"

    result = client.get('/password-reset', follow_redirects=True)
    page = BeautifulSoup(result.data, 'html.parser')
    pageheading = page.select("#pageheading")[0]
    assert pageheading.get_text(strip=True) == "Password Reset for dummy"


@pytest.mark.vcr()
def test_password_changes_wrong_user(client, logged_in_dummy_user):
    """Verify that we error if trying to change another user's password"""
    result = client.post(
        '/user/admin/password-reset',
        data={
            "username": "admin",
            "current_password": "dummy_password",
            "password": "secretpw",
            "password_confirm": "secretpw",
        },
    )
    assert result.status_code == 302
    messages = get_flashed_messages(with_categories=True)
    assert len(messages) == 1
    category, message = messages[0]
    assert message == "You do not have permission to edit this account."
    assert category == "danger"


@pytest.mark.vcr()
def test_password_changes_user(
    client, logged_in_dummy_user, dummy_group, no_password_min_time
):
    """Verify that password changes"""
    ipa_admin.group_add_member("dummy-group", users="dummy")
    result = client.post(
        '/user/dummy/password-reset',
        data={
            "username": "dummy",
            "current_password": "dummy_password",
            "password": "secretpw",
            "password_confirm": "secretpw",
        },
    )
    assert result.status_code == 302
    messages = get_flashed_messages(with_categories=True)
    assert len(messages) == 1
    category, message = messages[0]
    assert message == "Your password has been changed"
    assert category == "success"


@pytest.mark.vcr()
def test_non_matching_passwords_user(client, logged_in_dummy_user):
    """Verify that passwords that dont match are caught"""
    result = client.post(
        '/user/dummy/password-reset',
        data={
            "username": "jbloggs",
            "current_password": "sdsds",
            "password": "password1",
            "password_confirm": "password2",
        },
    )
    assert result.status_code == 200
    page = BeautifulSoup(result.data, 'html.parser')
    password_input = page.select("input[name='password']")[0]
    assert 'is-invalid' in password_input['class']
    invalidfeedback = password_input.find_next('div', class_='invalid-feedback')
    assert invalidfeedback.get_text(strip=True) == "Passwords must match"


@pytest.mark.vcr()
def test_password_user(client, logged_in_dummy_user):
    """Verify that current password must be correct"""
    result = client.post(
        '/user/dummy/password-reset',
        data={
            "username": "dummy",
            "current_password": "1",
            "password": "LongSuperSafePassword",
            "password_confirm": "LongSuperSafePassword",
        },
        follow_redirects=True,
    )
    assert result.status_code == 200
    page = BeautifulSoup(result.data, 'html.parser')
    print(page.prettify())
    password_input = page.select("input[name='current_password']")[0]
    assert 'is-invalid' in password_input['class']
    invalidfeedback = password_input.find_next('div', class_='invalid-feedback')
    assert (
        invalidfeedback.get_text(strip=True)
        == "The old password or username is not correct"
    )


def test_non_matching_passwords(client):
    """Verify that passwords that dont match are caught"""
    result = client.post(
        '/password-reset?username=jbloggs',
        data={
            "current_password": "sdsds",
            "password": "password1",
            "password_confirm": "password2",
        },
    )
    assert result.status_code == 200
    page = BeautifulSoup(result.data, 'html.parser')
    password_input = page.select("input[name='password']")[0]
    assert 'is-invalid' in password_input['class']
    invalidfeedback = password_input.find_next('div', class_='invalid-feedback')
    assert invalidfeedback.get_text(strip=True) == "Passwords must match"


@pytest.mark.vcr()
def test_password(client, dummy_user):
    """Verify that current password must be correct"""
    result = client.post(
        '/password-reset?username=dummy',
        data={
            "current_password": "1",
            "password": "LongSuperSafePassword",
            "password_confirm": "LongSuperSafePassword",
        },
        follow_redirects=True,
    )
    assert result.status_code == 200
    page = BeautifulSoup(result.data, 'html.parser')
    password_input = page.select("input[name='current_password']")[0]
    assert 'is-invalid' in password_input['class']
    invalidfeedback = password_input.find_next('div', class_='invalid-feedback')
    assert (
        invalidfeedback.get_text(strip=True)
        == "The old password or username is not correct"
    )


@pytest.mark.vcr()
def test_password_no_user(client):
    """Verify that user must exist"""
    result = client.post(
        '/password-reset?username=dudemcpants',
        data={
            "current_password": "1",
            "password": "LongSuperSafePassword",
            "password_confirm": "LongSuperSafePassword",
        },
        follow_redirects=True,
    )
    assert result.status_code == 200
    page = BeautifulSoup(result.data, 'html.parser')
    password_input = page.select("input[name='current_password']")[0]
    assert 'is-invalid' in password_input['class']
    invalidfeedback = password_input.find_next('div', class_='invalid-feedback')
    assert (
        invalidfeedback.get_text(strip=True)
        == "The old password or username is not correct"
    )


@pytest.mark.vcr()
def test_time_sensitive_password_policy(client, dummy_user):
    """Verify that new password policies are upheld"""
    result = client.post(
        '/password-reset?username=dummy',
        data={
            "current_password": "dummy_password",
            "password": "somesupersecretpassword",
            "password_confirm": "somesupersecretpassword",
        },
        follow_redirects=True,
    )
    page = BeautifulSoup(result.data, 'html.parser')
    password_input = page.select("input[name='password']")[0]
    assert 'is-invalid' in password_input['class']
    # the dummy user is created and has its password immediately changed,
    # so this next attempt should failt with a constraint error.
    invalidfeedback = password_input.find_next('div', class_='invalid-feedback')
    assert (
        invalidfeedback.get_text(strip=True)
        == "Constraint violation: Too soon to change password"
    )


@pytest.mark.vcr()
def test_short_password(client, dummy_user, no_password_min_time):
    """Verify that new password policies are upheld"""
    result = client.post(
        '/password-reset?username=dummy',
        data={
            "current_password": "dummy_password",
            "password": "1",
            "password_confirm": "1",
        },
        follow_redirects=True,
    )
    page = BeautifulSoup(result.data, 'html.parser')
    password_input = page.select("input[name='password']")[0]
    assert 'is-invalid' in password_input['class']
    invalidfeedback = password_input.find_next('div', class_='invalid-feedback')
    assert (
        invalidfeedback.get_text(strip=True)
        == "Constraint violation: Password is too short"
    )


def test_reset_generic_error(client):
    """Reset password with an unhandled error"""
    client_mock = mock.Mock()
    with mock.patch(
        "securitas.controller.password.untouched_ipa_client"
    ) as untouched_ipa_client:
        untouched_ipa_client.return_value = client_mock
        client_mock.change_password.side_effect = python_freeipa.exceptions.FreeIPAError(
            message="something went wrong", code="4242"
        )
        result = client.post(
            '/password-reset?username=dummy',
            data={
                "current_password": "dummy_password",
                "password": "password",
                "password_confirm": "password",
            },
        )
    assert result.status_code == 200
    page = BeautifulSoup(result.data, 'html.parser')
    submit_button = page.select("button[type='submit']")[0]
    form_errors = submit_button.find_previous("div", id="formerrors")
    assert form_errors is not None
    form_error = form_errors.find("div", class_="text-danger")
    assert form_error is not None
    assert form_error.get_text(strip=True) == 'Could not change password.'


@pytest.mark.vcr()
def test_password_changes(client, dummy_user, no_password_min_time):
    """Verify that password changes"""
    result = client.post(
        '/password-reset?username=dummy',
        data={
            "current_password": "dummy_password",
            "password": "secretpw",
            "password_confirm": "secretpw",
        },
    )
    assert result.status_code == 302
    assert result.location == f"http://localhost/"
    messages = get_flashed_messages(with_categories=True)
    assert len(messages) == 1
    category, message = messages[0]
    assert message == "Your password has been changed"
    assert category == "success"


def test_forgot_password_ask(client):
    result = client.get('/forgot-password/ask')
    assert result.status_code == 200


@pytest.mark.vcr()
def test_forgot_password_ask_post(client, dummy_user):
    with mailer.record_messages() as outbox:
        with mock.patch.object(PasswordResetLock, "store") as store:
            result = client.post('/forgot-password/ask', data={"username": "dummy"})
    assert result.status_code == 302
    assert result.location == f"http://localhost/"
    # Confirmation message
    messages = get_flashed_messages(with_categories=True)
    assert len(messages) == 1
    category, message = messages[0]
    assert message == (
        "An email has been sent to your address with instructions on how to reset your password"
    )
    assert category == "success"
    # Sent email
    assert len(outbox) == 1
    message = outbox[0]
    assert message.subject == "Password reset procedure"
    assert message.recipients == ["dummy@example.com"]
    # Valid token
    token_match = re.search(r"\?token=([^\s\"']+)", message.body)
    assert token_match is not None
    token = token_match.group(1)
    token_data = jwt.decode(token, current_app.config["SECRET_KEY"])
    assert token_data.get("username") == "dummy"
    assert "last_change" in token_data
    # Lock activated
    store.assert_called_once()


@pytest.mark.vcr()
def test_forgot_password_ask_post_non_existant_user(client):
    result = client.post('/forgot-password/ask', data={"username": "nosuchuser"})
    assert result.status_code == 200
    page = BeautifulSoup(result.data, 'html.parser')
    username_input = page.select_one("input[name='username']")
    assert username_input is not None
    assert 'is-invalid' in username_input['class']
    invalidfeedback = username_input.find_next('div', class_='invalid-feedback')
    assert invalidfeedback.get_text(strip=True) == "User nosuchuser does not exist"


@pytest.mark.vcr()
def test_forgot_password_ask_no_smtp(client, dummy_user):
    with mock.patch("securitas.controller.password.mailer") as mailer:
        mailer.send.side_effect = ConnectionRefusedError
        with mock.patch.object(PasswordResetLock, "store") as store:
            with mock.patch("securitas.controller.password.app.logger") as logger:
                result = client.post('/forgot-password/ask', data={"username": "dummy"})
    assert result.status_code == 302
    assert result.location == f"http://localhost/"
    mailer.send.assert_called_once()
    # Lock untouched
    store.assert_not_called()
    # Error message
    messages = get_flashed_messages(with_categories=True)
    assert len(messages) == 1
    category, message = messages[0]
    assert message == "We could not send you an email, please retry later"
    assert category == "danger"
    # Log message
    logger.error.assert_called_once()


def test_forgot_password_ask_still_valid(client):
    with mailer.record_messages() as outbox:
        with mock.patch.object(PasswordResetLock, "valid_until") as valid_until:
            valid_until.return_value = datetime.datetime.now() + datetime.timedelta(
                minutes=2
            )
            result = client.post('/forgot-password/ask', data={"username": "dummy"})
    # Error message
    assert result.status_code == 200
    page = BeautifulSoup(result.data, 'html.parser')
    submit_button = page.select("button[type='submit']")[0]
    form_errors = submit_button.find_previous("div", id="formerrors")
    assert form_errors is not None
    form_error = form_errors.find("div", class_="text-danger")
    assert form_error is not None
    assert form_error.get_text(strip=True).startswith(
        "You have already requested a password reset, you need to wait "
    )
    # No sent email
    assert len(outbox) == 0


def test_forgot_password_change_no_token(client):
    result = client.get('/forgot-password/change')
    assert result.status_code == 302
    assert result.location == f"http://localhost/forgot-password/ask"
    messages = get_flashed_messages(with_categories=True)
    assert len(messages) == 1
    category, message = messages[0]
    assert message == "No token provided, please request one."
    assert category == "warning"


def test_forgot_password_change_invalid_token(client):
    result = client.get('/forgot-password/change?token=this-is-invalid')
    assert result.status_code == 302
    assert result.location == f"http://localhost/forgot-password/ask"
    messages = get_flashed_messages(with_categories=True)
    assert len(messages) == 1
    category, message = messages[0]
    assert message == "The token is invalid, please request a new one."
    assert category == "warning"


@pytest.mark.vcr()
def test_forgot_password_change_not_active(client, token_for_dummy_user):
    with mock.patch.multiple(
        PasswordResetLock, valid_until=mock.DEFAULT, delete=mock.DEFAULT
    ) as patches:
        valid_until = patches["valid_until"]
        valid_until.return_value = None
        result = client.get(f'/forgot-password/change?token={token_for_dummy_user}')
    patches["delete"].assert_called_once()
    assert result.status_code == 302
    assert result.location == f"http://localhost/forgot-password/ask"
    messages = get_flashed_messages(with_categories=True)
    assert len(messages) == 1
    category, message = messages[0]
    assert message == "The token has expired, please request a new one."
    assert category == "warning"


@pytest.mark.vcr()
def test_forgot_password_change_too_old(client, token_for_dummy_user):
    with mock.patch.multiple(
        PasswordResetLock, valid_until=mock.DEFAULT, delete=mock.DEFAULT
    ) as patches:
        valid_until = patches["valid_until"]
        valid_until.return_value = datetime.datetime.now() - datetime.timedelta(
            minutes=1
        )
        result = client.get(f'/forgot-password/change?token={token_for_dummy_user}')
    patches["delete"].assert_called_once()
    assert result.status_code == 302
    assert result.location == f"http://localhost/forgot-password/ask"
    messages = get_flashed_messages(with_categories=True)
    assert len(messages) == 1
    category, message = messages[0]
    assert message == "The token has expired, please request a new one."
    assert category == "warning"


@pytest.mark.vcr()
def test_forgot_password_change_recent_password_change(
    client, dummy_user, token_for_dummy_user, no_password_min_time
):
    ipa_admin.group_add_member("dummy-group", users="dummy")
    ipa = untouched_ipa_client(current_app)
    ipa.change_password("dummy", "dummy_password", "dummy_password")
    with mock.patch.multiple(
        PasswordResetLock, valid_until=mock.DEFAULT, delete=mock.DEFAULT
    ) as patches:
        valid_until = patches["valid_until"]
        valid_until.return_value = datetime.datetime.now() + datetime.timedelta(
            minutes=2
        )
        result = client.get(f'/forgot-password/change?token={token_for_dummy_user}')
    patches["delete"].assert_called_once()
    assert result.status_code == 302
    assert result.location == f"http://localhost/forgot-password/ask"
    messages = get_flashed_messages(with_categories=True)
    assert len(messages) == 1
    category, message = messages[0]
    assert message == (
        "Your password has been changed since you requested this token, please request a new one."
    )
    assert category == "warning"
