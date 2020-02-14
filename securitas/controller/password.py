import datetime

from flask import abort, flash, render_template, redirect, request, url_for, session
from flask_mail import Message
import python_freeipa
import jwt

from securitas import app, ipa_admin, mailer
from securitas.security.ipa import untouched_ipa_client, maybe_ipa_session
from securitas.utility import with_ipa
from securitas.utility.password_reset import PasswordResetLock
from securitas.form.password_reset import (
    PasswordResetForm,
    ForgottenPasswordForm,
    NewPasswordForm,
)


def _validate_change_pw_form(form, username, ipa=None):
    if ipa is None:
        ipa = untouched_ipa_client(app)

    current_password = form.current_password.data
    password = form.password.data

    res = None
    try:
        res = ipa.change_password(username, password, current_password)
    except python_freeipa.exceptions.PWChangeInvalidPassword:
        form.current_password.errors.append(
            "The old password or username is not correct"
        )
    except python_freeipa.exceptions.PWChangePolicyError as e:
        form.password.errors.append(e.policy_error)
    except python_freeipa.exceptions.FreeIPAError as e:
        # If we made it here, we hit something weird not caught above. We didn't
        # bomb out, but we don't have IPA creds, either.
        app.logger.error(
            f'An unhandled error {e.__class__.__name__} happened while reseting '
            f'the password for user {username}: {e.message}'
        )
        form.errors['non_field_errors'] = ['Could not change password.']

    if res and res.ok:
        flash('Your password has been changed', 'success')
        app.logger.info(f'Password for {username} was changed')
    return res


@app.route('/password-reset', methods=['GET', 'POST'])
def password_reset():
    # If already logged in, redirect to the logged in reset form
    ipa = maybe_ipa_session(app, session)
    username = session.get('securitas_username')
    if ipa and username:
        return redirect(url_for('auth_password_reset', username=username))

    username = request.args.get('username')
    if not username:
        abort(404)
    form = PasswordResetForm()

    if form.validate_on_submit():
        res = _validate_change_pw_form(form, username)
        if res and res.ok:
            return redirect(url_for('root'))

    return render_template(
        'password-reset.html', password_reset_form=form, username=username
    )


@app.route('/user/<username>/password-reset', methods=['GET', 'POST'])
@with_ipa(app, session)
def auth_password_reset(ipa, username):
    if session.get('securitas_username') != username:
        flash('You do not have permission to edit this account.', 'danger')
        return redirect(url_for('root'))

    form = PasswordResetForm()

    if form.validate_on_submit():
        res = _validate_change_pw_form(form, username, ipa)
        if res and res.ok:
            return redirect(url_for('root'))

    return render_template('password-reset.html', password_reset_form=form)


@app.route('/forgot-password/ask', methods=['GET', 'POST'])
def forgot_password_ask():
    form = ForgottenPasswordForm()
    if form.validate_on_submit():
        username = form.username.data
        lock = PasswordResetLock(username)
        valid_until = lock.valid_until()
        now = datetime.datetime.now()
        if valid_until is not None and now < valid_until:
            wait_min = int((valid_until - now).total_seconds() / 60)
            wait_sec = int((valid_until - now).total_seconds() % 60)
            form.errors['non_field_errors'] = [
                f'You have already requested a password reset, you need to wait {wait_min} '
                f'minute(s) and {wait_sec} seconds before you can request another.'
            ]
        else:
            try:
                user = ipa_admin.user_show(username)
            except python_freeipa.exceptions.NotFound:
                form.username.errors.append(f"User {username} does not exist")
            else:
                token = str(
                    jwt.encode(
                        {"username": username, "last_change": user["krblastpwdchange"]},
                        app.config["SECRET_KEY"],
                        algorithm="HS256",
                    ),
                    "ascii",
                )
                # Send the email
                email_context = {"token": token, "username": username}
                email = Message(
                    body=render_template("forgot-password-email.txt", **email_context),
                    html=render_template("forgot-password-email.html", **email_context),
                    sender=app.config["MAIL_FROM"],
                    recipients=[user["mail"][0]],
                    subject="Password reset procedure",
                )
                try:
                    mailer.send(email)
                except ConnectionRefusedError as e:
                    app.logger.error(f"Impossible to send a password reset email: {e}")
                    flash(
                        "We could not send you an email, please retry later", "danger"
                    )
                    return redirect(url_for('root'))

                app.logger.debug(email)
                lock.store()
                app.logger.info(
                    f'{username} forgot their password and requested a token'
                )
                flash(
                    "An email has been sent to your address with instructions on how to reset "
                    "your password",
                    "success",
                )
                return redirect(url_for('root'))
    return render_template('forgot-password-ask.html', form=form)


@app.route('/forgot-password/change', methods=['GET', 'POST'])
def forgot_password_change():
    token = request.args.get('token')
    if not token:
        flash('No token provided, please request one.', 'warning')
        return redirect(url_for('forgot_password_ask'))
    try:
        token_data = jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
    except jwt.exceptions.DecodeError:
        flash("The token is invalid, please request a new one.", "warning")
        return redirect(url_for('forgot_password_ask'))
    username = token_data["username"]
    lock = PasswordResetLock(username)
    valid_until = lock.valid_until()
    now = datetime.datetime.now()
    if valid_until is None or now > valid_until:
        lock.delete()
        flash("The token has expired, please request a new one.", "warning")
        return redirect(url_for('forgot_password_ask'))
    user = ipa_admin.user_show(username)
    if user["krblastpwdchange"] != token_data["last_change"]:
        lock.delete()
        flash(
            "Your password has been changed since you requested this token, please request "
            "a new one.",
            "warning",
        )
        return redirect(url_for('forgot_password_ask'))

    form = NewPasswordForm()
    if form.validate_on_submit():
        password = form.password.data
        try:
            ipa_admin.user_mod(username, userpassword=password)
            # Change the password as the user, so it's not expired.
            ipa = untouched_ipa_client(app)
            ipa.change_password(username, password, password)
        except python_freeipa.exceptions.PWChangePolicyError as e:
            form.password.errors.append(e.policy_error)
        except python_freeipa.exceptions.FreeIPAError as e:
            # If we made it here, we hit something weird not caught above.
            app.logger.error(
                f'An unhandled error {e.__class__.__name__} happened while reseting '
                f'the password for user {username}: {e.message}'
            )
            form.errors['non_field_errors'] = ['Could not change password.']
        else:
            lock.delete()
            flash('Your password has been changed', 'success')
            app.logger.info(
                f"Password for {username} was changed after completing the forgotten "
                f"password process."
            )
            return redirect(url_for('root'))
    return render_template(
        'forgot-password-change.html', username=username, form=form, token=token
    )
