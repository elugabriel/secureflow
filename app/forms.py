# app/forms.py

from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField, SelectField
from wtforms.validators import DataRequired, Email, EqualTo, ValidationError
from email_validator import validate_email, EmailNotValidError
from .models import User

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Sign In')

class RegistrationForm(FlaskForm):
    first_name = StringField('First Name', validators=[DataRequired()])
    last_name = StringField('Last Name', validators=[DataRequired()])
    phone = StringField('Phone Number', validators=[DataRequired()])
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    password2 = PasswordField('Repeat Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user is not None:
            raise ValidationError('Please use a different username.')

    def validate_email(self, email):
        try:
            v = validate_email(email.data)
            email.data = v.email
        except EmailNotValidError as e:
            raise ValidationError(str(e))

class MessageForm(FlaskForm):
    body = StringField('Message', validators=[DataRequired()])
    recipient = StringField('Recipient Username', validators=[DataRequired()])
    aes_algorithm = SelectField('AES Algorithm', choices=[
        ('AES-128', 'AES-128'),
        ('AES-192', 'AES-192'),
        ('AES-256', 'AES-256')
    ], validators=[DataRequired()])
    submit = SubmitField('Send')
