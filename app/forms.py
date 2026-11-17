"""WTForms definitions. Flask-WTF adds a CSRF token to every form."""
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileRequired
from wtforms import PasswordField, SelectField, StringField, SubmitField
from wtforms.validators import DataRequired, EqualTo, Length, Optional

from .models import Role

ROLE_CHOICES = [(r.value, r.label) for r in Role]


class LoginForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired(), Length(max=64)])
    password = PasswordField("Password", validators=[DataRequired(), Length(max=128)])
    submit = SubmitField("Sign in")


class ChangePasswordForm(FlaskForm):
    current_password = PasswordField("Current password", validators=[DataRequired(), Length(max=128)])
    new_password = PasswordField("New password", validators=[DataRequired(), Length(max=128)])
    confirm_password = PasswordField(
        "Confirm new password",
        validators=[DataRequired(), EqualTo("new_password", message="Passwords do not match.")],
    )
    submit = SubmitField("Change password")


class UploadForm(FlaskForm):
    file = FileField("Document", validators=[FileRequired()])
    submit = SubmitField("Encrypt & upload")


class ActionForm(FlaskForm):
    """Empty form used only to carry a CSRF token on POST-only actions."""


class CreateUserForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired(), Length(min=3, max=32)])
    role = SelectField("Role", choices=ROLE_CHOICES, default=Role.STAFF.value, validators=[DataRequired()])
    temp_password = PasswordField("Temporary password", validators=[DataRequired(), Length(max=128)])
    submit = SubmitField("Create user")


class ChangeRoleForm(FlaskForm):
    role = SelectField("Role", choices=ROLE_CHOICES, validators=[DataRequired()])
    submit = SubmitField("Update")


class ResetPasswordForm(FlaskForm):
    temp_password = PasswordField("Temporary password", validators=[DataRequired(), Length(max=128)])
    submit = SubmitField("Reset")


class AuditFilterForm(FlaskForm):
    class Meta:
        csrf = False  # GET-only, read-only filter form

    username = StringField("User", validators=[Optional(), Length(max=64)])
    action = SelectField("Action", validators=[Optional()])
    result = SelectField("Result", validators=[Optional()])
    date_from = StringField("From", validators=[Optional(), Length(max=10)])
    date_to = StringField("To", validators=[Optional(), Length(max=10)])
