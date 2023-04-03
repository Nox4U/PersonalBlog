from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, EmailField
from wtforms.validators import DataRequired, URL, Email, Length
from flask_ckeditor import CKEditorField

##WTForm
class CreatePostForm(FlaskForm):
    title = StringField("Blog Post Title", validators=[DataRequired()])
    subtitle = StringField("Subtitle", validators=[DataRequired()])
    img_url = StringField("Blog Image URL", validators=[DataRequired(), URL()])
    body = CKEditorField("Blog Content", validators=[DataRequired()])
    submit = SubmitField("Submit Post")


class ContactMe(FlaskForm):
    name= StringField("Name", validators=[DataRequired()])
    email = EmailField("Email Address", validators=[Email()])
    phone_number = StringField("Phone Number", validators=[DataRequired()])
    message = CKEditorField("Blog Content", validators=[DataRequired()])
    submit = SubmitField("Send")


class RegisterForm(FlaskForm):
    name= StringField("Name", validators=[DataRequired(), Length(max=100)])
    email = EmailField("Email Address", validators=[Email(), Length(max=100)])
    password = PasswordField("Password",validators=[DataRequired()])
    submit = SubmitField("SIGN ME UP!")


class LoginForm(FlaskForm):
    email = EmailField("Email Address", validators=[Email()])
    password = StringField("Password", validators=[DataRequired()])
    submit = SubmitField("LET ME IN!")


class CommentForm(FlaskForm):
    comment = CKEditorField("Comment", validators=[DataRequired()])
    submit = SubmitField("Submit Comment")