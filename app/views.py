from flask import render_template, url_for, flash, redirect, request
from app import app, db, bcrypt
from app.forms import RegistrationForm, LoginForm
from app.models import User, Post

@app.route('/')
def index():
	return render_template('index.html', name = 'Інженерія програмного забезпечення', 
		title='PNU')

@app.route("/register", methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user == None:
            hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
            user = User(username=form.username.data, email=form.email.data, password=hashed_password)
            db.session.add(user)
            db.session.commit()
            flash(f'Account created for {form.username.data}!', category = 'success')
            return redirect(url_for('login'))
        else:
            flash(f'Account вже існує for {form.username.data}!', category = 'warning')
    return render_template('register.html', title='Register', form=form)

@app.route("/login", methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            flash('You have been logged in!', category = 'success')
            return redirect(url_for('index'))
        else:
            flash('Login unsuccessful. Please check username and password', category = 'warning')
    return render_template('login.html', form=form, title='Login')


@app.route('/posts', methods=['GET', 'POST'])
def posts():
    user = { 'nickname': 'Miguel' } # видуманий користувач
    posts = [ # список видуманих постів
        { 
            'author': { 'nickname': 'John' }, 
            'body': 'Beautiful day in Portland!' 
        },
        { 
            'author': { 'nickname': 'Susan' }, 
            'body': 'The Avengers movie was so cool!' 
        }
    ]
    return render_template("posts.html",
        title = 'Home',
        user = user,
        posts = posts)


'''
@app.route('/user/add', methods=['GET'])
def user_records():
    """Create a user via query string parameters."""
    username = request.args.get('user')
    email = request.args.get('email')
    if username and email:
        existing_user = User.query.filter(User.username == username or User.email == email).first()
        if existing_user:
            flash(f'{username} ({email}) already created!')
            
        new_user = User(username=username, email=email, about="In West Philadelphia born and raised, \
            on the playground is where I spent most of my days", admin=False)  # Create an instance of the User class
        db.session.add(new_user)  # Adds new User record to database
        db.session.commit()  # Commits all changes
        redirect(url_for('user_records'))
    return render_template(
        'users.jinja2',
        users=User.query.all(),
        title="Show Users"
    )

@app.errorhandler(404)
def pageNotFount(error):
    return render_template('page404.html', error=error), 404


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        flash("Дані успішно відправлено " + email, category = 'success')
        #flash("Дякуємо", category = 'info')
        return render_template('login.html', form=form, title= email)
    elif request.method == 'POST':
        flash("Дані введено некоректно", category = 'warning')
        #form.username.data = ''
    return render_template('login.html', form=form, title= 'Гість !!')


    '''

mainmenu = [
            {'name_1': 'viev_function_value_1'},
            {'name_2': 'viev_function_value_1'} 
        ]
