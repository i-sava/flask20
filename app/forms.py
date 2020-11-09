from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import DataRequired, Length, Email, EqualTo


class RegistrationForm(FlaskForm):
    username = StringField('Username', 
                            validators=[Length(min=4, max=25, 
                            message ='Це поле має бути довжиною між 4 та 25 символів'), 
                            DataRequired(message ="Це поле обов'язкове")])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', 
                            validators=[Length(min=6, 
                            message ='Це поле має бути більше 6 cимволів'), 
                            DataRequired(message ="Це поле обов'язкове")])
    confirm_password = PasswordField('Confirm Password', 
                            validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign up')


class LoginForm(FlaskForm): 
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')




'''


class Search(FlaskForm):
	search_text = StringField('Search for', validators=[DataRequired(message ='Це поле обовязкове')])
	submit = SubmitField('Search')

'''