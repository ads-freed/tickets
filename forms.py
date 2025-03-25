from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, TextAreaField, SubmitField, FileField, SelectField, RadioField, SelectMultipleField
from wtforms.validators import DataRequired, Email, EqualTo, Optional, Length

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(1, 64)])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(1, 64)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), EqualTo('confirm', message='Passwords must match')])
    confirm = PasswordField('Repeat Password', validators=[DataRequired()])
    submit = SubmitField('Register')

class ProfileForm(FlaskForm):
    name = StringField('Name', validators=[Optional(), Length(max=120)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    # New fields for password update
    new_password = PasswordField('New Password', validators=[Optional(), Length(min=6)])
    confirm_password = PasswordField('Confirm New Password', validators=[Optional(), EqualTo('new_password', message='Passwords must match')])
    submit = SubmitField('Update Profile')

class TicketForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired(), Length(1, 140)])
    description = TextAreaField('Description', validators=[DataRequired()])
    priority = RadioField(
        'Priority', 
        choices=[('normal', 'Normal'), ('critical', 'Critical'), ('high', 'High'), ('urgent', 'Urgent')],
        default='normal',
        validators=[DataRequired()]
    )
    attachment = FileField('Attachment')
    submit = SubmitField('Create Ticket')

class ReplyForm(FlaskForm):
    message = TextAreaField('Message', validators=[DataRequired()])
    attachment = FileField('Attachment')
    submit = SubmitField('Reply')

class MessageForm(FlaskForm):
    recipient = SelectField('Recipient', coerce=int)
    message = TextAreaField('Message', validators=[DataRequired()])
    attachment = FileField('Attachment')
    submit = SubmitField('Send')

class UserEditForm(FlaskForm):
    role = SelectField(
        'Role', 
        choices=[('customer', 'Customer'), ('support', 'Support'), ('admin', 'Admin')],
        validators=[DataRequired()]
    )
    permissions = SelectMultipleField(
        'Permissions',
        choices=[
            ('view', 'View'),
            ('create', 'Create'),
            ('update', 'Update'),
            ('delete', 'Delete'),
            ('edit', 'Edit')
        ],
        validators=[DataRequired()]
    )
    submit = SubmitField('Update User')
