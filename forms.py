from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, TextAreaField, EmailField, FileField
from wtforms.validators import DataRequired, Email, Length, Regexp
from flask_wtf.file import FileAllowed


# TODO: Create a RegisterForm to register new users
class RegisterForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    name = StringField("Name", validators=[DataRequired()])
    submit = SubmitField(
        "Register",
        render_kw={"class": "btn btn-success"}  # Add button styles
    )


# TODO: Create a LoginForm to login existing users
class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Let Me In!", render_kw={"class": "btn btn-success"})


class ForgotPasswordForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired()])
    submit = SubmitField("Get OTP", render_kw={"class": "btn btn-success"})


class VerifyOtpForm(FlaskForm):
    otp = StringField("Enter OTP", validators=[DataRequired()])
    submit = SubmitField("Verify OTP", render_kw={"class": "btn btn-success"})


class NewPasswordForm(FlaskForm):
    new_password = PasswordField("New Password", validators=[DataRequired()])
    confirm_password = PasswordField("Confirm Password", validators=[DataRequired()])
    submit = SubmitField("submit", render_kw={"class": "btn btn-success"})


class ContactForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired(), Length(max=50)])
    email = EmailField('Email', validators=[DataRequired(), Email(), Length(max=120)])
    message = TextAreaField('Message', validators=[DataRequired(), Length(max=500)])
    submit = SubmitField('Submit', render_kw={"class": "btn btn-success"})


class ConfirmForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired(), Length(max=50)])
    email = EmailField("Email", validators=[DataRequired(), Email(), Length(max=120)])
    phone = StringField('Phone Number', validators=[DataRequired(), Regexp(r'^\+?\d{10,15}$', message="Enter a valid phone number")])
    address = TextAreaField('Delivery Address', validators=[DataRequired(), Length(max=200)])
    payment_proof = FileField('Upload Payment Proof', validators=[FileAllowed(['jpg', 'jpeg', 'png', 'pdf'], message='Only images or PDF files are allowed.')])
    submit = SubmitField('Confirm', render_kw={"class": "btn btn-success"})