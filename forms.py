from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, TextAreaField, SubmitField, FileField, SelectField
from wtforms.validators import DataRequired, Email, EqualTo, Length

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
    name = StringField('Name', validators=[Length(max=120)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Update Profile')

class TicketForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired(), Length(1, 140)])
    description = TextAreaField('Description', validators=[DataRequired()])
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
