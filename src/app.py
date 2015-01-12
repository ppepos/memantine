import datetime

from flask import Flask
from flask.ext.script import Manager
from flask.ext.login import UserMixin, LoginManager
from flask.ext.mongoengine import MongoEngine
from flask.ext.wtf import Form
from flask.ext.bootstrap import Bootstrap
from werkzeug.security import generate_password_hash, check_password_hash
from wtforms import StringField, SubmitField
from wtforms.validators import Required

app = Flask(__name__)
manager = Manager(app)

# LoginManager Parameters
login_manager = LoginManager()
login_manager.session_protection = 'strong'
login_manager.login_view = 'login'
login_manager.init_app(app)

app.config['SECRET_KEY'] = 'YOURSECRETKEYHERE'
app.config['MONGODB_SETTINGS'] = {
        'DB': 'memantine',
        }

db = MongoEngine(app)

class User(UserMixin, db.Document):
    username = db.StringField(max_length=32, unique=True, required=True)
    password_hash = db.StringField(max_length=128)

    @property
    def password(self):
        raise AttributeError('Password is a write-only attribute')

    @password.setter
    def password(self, password):
        print "NEW PASSWD HASH:", generate_password_hash(password)
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

    def get_id(self):
        return User.objects.get(username=username)['_id']


class Spending(db.Document):
    item = db.StringField(max_length=64, required=True)
    description = db.StringField(max_length=512, required=False)
    spender = db.StringField(max_length=32, required=True)
    date = db.DateTimeField(default=datetime.datetime.now, required=True)
    comment = db.StringField(max_length=512, required=False)


class LoginForm(Form):
    username = StringField('Username', validators=[Required(), Length(1,32)])
    password = PasswordField('Password', validators=[Required()])
    remember_me = BooleanField('Keep me logged in')
    submit = SubmitField('Log In')


# User Mixin required callback function
@login_manager.user_loader
def load_user(self):
    return User.objects.get(id=user_id)

@app.route('/')
def index():
    return '<h1>Welcome to Memantine!</h1><br /><h2>Under Construction!</h2>'

@app.route('/index')
def dev_index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.objects.get(username=form.username.data).first()
        if user is not None and user.verify_password(form.password.data):
            login_user(user, form.remember_me.data)
            return redirect(url_for('index'))
        flash('Invalid username or password')
    return render_template('login.html')
            

if __name__ == "__main__":
    # app.run(debug=True)
    manager.run()

