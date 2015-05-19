import os
import datetime

from flask import Flask, redirect, render_template, session, url_for, flash
from flask.ext.script import Manager
from flask.ext.login import UserMixin, LoginManager, login_user, logout_user, \
                            login_required, current_user
from flask.ext.mongoengine import MongoEngine
from flask.ext.wtf import Form
from flask.ext.bootstrap import Bootstrap
from werkzeug.security import generate_password_hash, check_password_hash
from wtforms import StringField, SubmitField, PasswordField, BooleanField, \
                    DateTimeField, DecimalField
from wtforms.validators import Required, Length, Optional, NumberRange

app = Flask(__name__)
manager = Manager(app)

# LoginManager Parameters
login_manager = LoginManager()
login_manager.session_protection = 'strong'
login_manager.login_view = 'login'
login_manager.init_app(app)

app.config['SECRET_KEY'] = os.environ.get('MEMANTINE_SECRET', 'defaultsecret')
app.config['MONGODB_SETTINGS'] = {
        'host': os.environ.get('MEMANTINE_MONGO_HOST', 'localhost'),
        'db': 'memantine',
        }

db = MongoEngine(app)
bootstrap = Bootstrap(app)

class User(UserMixin, db.Document):
    username = db.StringField(max_length=32, unique=True, required=True)
    password_hash = db.StringField(max_length=128)
    total_spent = db.DecimalField(required=True, min_value=0, precision=2)
    display_name = db.StringField(max_length=32, unique=True, required=True)

    @property
    def password(self):
        raise AttributeError('Password is a write-only attribute')

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

    def get_id(self):
        return unicode(self.id)


class Spending(db.Document):
    item = db.StringField(max_length=64, required=True)
    description = db.StringField(max_length=512, required=False)
    spender = db.StringField(max_length=32, required=True)
    amount = db.DecimalField(required=True)
    date = db.DateTimeField(default=datetime.datetime.now, required=True)
    comment = db.StringField(max_length=512, required=False)


class RegisterForm(Form):
    username = StringField('Username', validators=[Required(), Length(1,32)])
    password = PasswordField('Password', validators=[Required()])
    display_name = StringField('Display Name', validators=[Required()])
    submit = SubmitField('Register')


class AccountSettingsForm(Form):
    display_name = StringField(validators=[Length(0,32)])
    password = PasswordField('Password')
    submit = SubmitField('Save')


class LoginForm(Form):
    username = StringField('Username', validators=[Required(), Length(1,32)])
    password = PasswordField('Password', validators=[Required()])
    remember_me = BooleanField('Keep me logged in')
    submit = SubmitField('Log In')


class SpendingsForm(Form):
    date = DateTimeField('Date', default=datetime.datetime.now(), format='%Y/%m/%d %H:%M:%S', validators=[Optional()])
    item = StringField('Item', validators=[Required()])
    description = StringField('Description', filters = [lambda x: x or None])
    amount = DecimalField('Amount', validators=[Required(), NumberRange(min=0)])
    comment = StringField('Comment', filters = [lambda x: x or None])
    submit = SubmitField('Submit')


# User Mixin required callback function
@login_manager.user_loader
def load_user(user_id):
    return User.objects.get(id=unicode(user_id))


@app.route('/')
@login_required
def index():
    recent_spendings = {}
    users = User.objects.only("username", "total_spent")
    total_spent_by_all_users = sum(user.total_spent for user in users)
    current_user_id = current_user.get_id()
    for user in users:
        if user.get_id() == current_user_id:
            current_user_balance = user.total_spent - (total_spent_by_all_users / users.count())
        # item, amount, date of last 3 spendings of user
        recent_spendings[user.username] = Spending.objects(spender=user.username).only("item", "amount", "date").order_by("-date")[:3]

    return render_template('index.html', users=users, recent=recent_spendings, current_user_balance=current_user_balance)



@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        user = User()
        user.username = form.username.data
        user.password = form.password.data
        user.display_name = form.display_name.data
        user.total_spent = 0.00
        user.save()
        return redirect(url_for('index'))
    else:
        return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        try:
            user = User.objects.get(username=form.username.data)
        except User.DoesNotExist as e:
            user = None
        if user is not None and user.verify_password(form.password.data):
            login_user(user, form.remember_me.data)
            return redirect(url_for('index'))
        flash('Invalid username or password')
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.')
    return redirect(url_for('index'))

@app.route('/account', methods=['GET', 'POST'])
@login_required
def account_settings():
    form = AccountSettingsForm()
    if form.validate_on_submit():

        new_display = None
        new_pass = None

        if form.display_name.data != '':
            new_display = form.display_name.data
        if form.password.data != '':
            new_pass = form.password.data

        if new_display or new_pass:
            user_id = current_user.get_id()
            user = load_user(user_id)
            if new_display:
                user.display_name = new_display
            if new_pass:
                user.password = new_pass
            user.save()

            flash('Successfully updated your settingst')

    form = AccountSettingsForm()
    return render_template('account_settings.html', form=form)

@app.route('/spending', methods=['GET', 'POST'])
@login_required
def spend():
    form = SpendingsForm()
    if form.validate_on_submit():
        spending = Spending()
        spending.spender = current_user.username
        spending.item = form.item.data
        spending.description = form.description.data
        spending.date = form.date.data
        spending.comment = form.comment.data
        spending.amount = form.amount.data
        spending.save()
        user_id = current_user.get_id()
        user = load_user(user_id)
        user.total_spent = user.total_spent + spending.amount
        user.save()

        flash('Successfully saved %s' % spending.item)

    form = SpendingsForm()
    return render_template('new_spending.html', form=form)


@app.route('/userspending/', defaults={'username': 'self'})
@app.route('/userspending/<username>')
@login_required
def user_spendings(username):
    if username == 'self':
        user_id = current_user.get_id()
        user = load_user(user_id)
    else:
        user = User.objects.get_or_404(username=username)
    spendings = Spending.objects(spender=user.username)
    return render_template('user_spendings.html', user=user, spendings=spendings)


if __name__ == "__main__":
    manager.run()

