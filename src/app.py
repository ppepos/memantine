import os
import datetime

from flask import Flask, redirect, render_template, session, url_for, flash
from flask.ext.bootstrap import Bootstrap
from flask.ext.login import UserMixin, LoginManager, login_user, logout_user, \
    login_required, current_user
from flask.ext.migrate import Migrate, MigrateCommand
from flask.ext.script import Manager
from flask.ext.sqlalchemy import SQLAlchemy
from flask.ext.wtf import Form
from werkzeug.security import generate_password_hash, check_password_hash
from wtforms import StringField, SubmitField, PasswordField, BooleanField, \
                    DateTimeField, DecimalField, SelectField
from wtforms.validators import Required, Length, Optional, NumberRange

app = Flask(__name__)

basedir = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))

# LoginManager Parameters
login_manager = LoginManager()
login_manager.session_protection = 'strong'
login_manager.login_view = 'login'
login_manager.init_app(app)

app.config['DEBUG'] = True
app.config['SECRET_KEY'] = os.environ.get('MEMANTINE_SECRET', 'defaultsecret')
app.config['SQLALCHEMY_DATABASE_URI'] = \
        'sqlite:///' + os.path.join(basedir, 'data.sqlite')
app.config['SQLALCHEMY_COMMIT_ON_TEARDOWN'] = True

bootstrap = Bootstrap(app)
db = SQLAlchemy(app)
migrate = Migrate(app, db)
manager = Manager(app)

manager.add_command('db', MigrateCommand)


class User(UserMixin, db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(32), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    display_name = db.Column(db.String(32), unique=True, nullable=False)

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

    def __repr__(self):
        return "<User: %s, %s>" % (self.id, self.display_name)


class Transaction(db.Model):
    __tablename__ = 'transaction'
    id = db.Column(db.Integer, primary_key=True)
    item = db.Column(db.String(64), nullable=True)
    description = db.Column(db.String(512), nullable=True)
    amount = db.Column(db.Integer, nullable=False)
    date = db.Column(db.DateTime(), nullable=False)
    comment = db.Column(db.String(512), nullable=True)

    spender_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'))

    spender = db.relationship("User", backref="transactions_spent", foreign_keys=[spender_id])
    receiver = db.relationship("User", backref="transactions_received", foreign_keys=[receiver_id])


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
    for_user = SelectField('For', coerce=int)
    item = StringField('Item', validators=[Required()])
    description = StringField('Description', filters = [lambda x: x or None])
    amount = DecimalField('Amount', validators=[Required(), NumberRange(min=0)])
    comment = StringField('Comment', filters=[lambda x: x or None])
    submit = SubmitField('Submit')

    def __init__(self):
        super(SpendingsForm, self).__init__()
        user_id = current_user.get_id()
        self.for_user.choices = [(user.id, user.display_name) for user in User.query.all() if unicode(user.id) != user_id]
        self.for_user.choices += [(0, "Everyone")]


class PaybackForm(Form):
    date = DateTimeField('Date', default=datetime.datetime.now(), format='%Y/%m/%d %H:%M:%S', validators=[Optional()])
    for_user = SelectField('For', coerce=int)
    amount = DecimalField('Amount', validators=[Required(), NumberRange(min=0)])
    comment = StringField('Comment', filters=[lambda x: x or None])
    submit = SubmitField('Submit')

    def __init__(self):
        super(PaybackForm, self).__init__()
        user_id = current_user.get_id()
        self.for_user.choices = [(user.id, user.display_name) for user in User.query.all() if unicode(user.id) != user_id]


class QuickPaybackForm(Form):
    date = DateTimeField('Date', default=datetime.datetime.now(), format='%Y/%m/%d %H:%M:%S', validators=[Optional()])
    amount = DecimalField('Amount', validators=[Required(), NumberRange(min=0)])
    comment = StringField('Comment', filters=[lambda x: x or None])
    submit = SubmitField('Submit')

    def __init__(self):
        super(QuickPaybackForm, self).__init__()
        user_id = current_user.get_id()


# User Mixin required callback function
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


@app.route('/')
@login_required
def index():
    recent_spendings = {}
    balances = {}
    users = User.query.all()
    for user in users:

        recent_spendings[user.username] = Transaction.query.filter_by(spender=user).order_by(Transaction.date.desc())[:3]

        transactions_to = Transaction.query.filter_by(receiver=user, spender=current_user)
        transactions_from = Transaction.query.filter_by(receiver=current_user, spender=user)
        total = sum(t.amount for t in transactions_from) - sum(t.amount for t in transactions_to)
        balances[user.username] = total / 100.00

    transactions_spent = current_user.transactions_spent
    transactions_received = current_user.transactions_received
    total_out = sum(transaction.amount for transaction in transactions_spent)
    total_in = sum(transaction.amount for transaction in transactions_received)
    current_user_balance = (total_out - total_in) / 100.00

    return render_template('index.html', users=users, recent=recent_spendings, current_user_balance=current_user_balance, balances=balances)


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        user = User()
        user.username = form.username.data
        user.password = form.password.data
        user.display_name = form.display_name.data
        db.session.add(user)
        db.session.commit()
        return redirect(url_for('index'))
    else:
        return render_template('register.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.verify_password(form.password.data):
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

        if form.display_name.data.strip() != '':
            new_display = form.display_name.data.strip()
        if form.password.data.strip() != '':
            new_pass = form.password.data.strip()

        if new_display or new_pass:
            user_id = current_user.get_id()
            user = load_user(user_id)
            if new_display:
                user.display_name = new_display
            if new_pass:
                user.password = new_pass
            db.session.add(user)
            db.session.commit()

            flash('Successfully updated your settingst')

    form = AccountSettingsForm()
    return render_template('account_settings.html', form=form)


@app.route('/spending', methods=['GET', 'POST'])
@login_required
def spend():
    form = SpendingsForm()
    if form.validate_on_submit():
        user_id = current_user.get_id()
        user = load_user(user_id)

        if form.for_user.data == 0:
            for receiver in User.query.all():

                if unicode(receiver.id) == user_id:
                    continue

                user_count = user.query.count()

                transaction = Transaction()
                transaction.spender = user
                transaction.receiver = receiver
                transaction.item = form.item.data
                transaction.description = form.description.data
                transaction.date = form.date.data
                transaction.comment = form.comment.data
                transaction.amount = int(form.amount.data * 100 / user_count)
                db.session.add(transaction)

        else:
            receiver = User.query.get(form.for_user.data)
            transaction = Transaction()
            transaction.spender = user
            transaction.receiver = receiver
            transaction.item = form.item.data
            transaction.description = form.description.data
            transaction.date = form.date.data
            transaction.comment = form.comment.data
            transaction.amount = int(form.amount.data * 100)
            db.session.add(transaction)

        db.session.commit()
        flash('Successfully saved %s' % transaction.item)

        form = SpendingsForm()

    return render_template('new_spending.html', form=form)


@app.route('/payback', methods=['POST', 'GET'])
@login_required
def payback():
    form = PaybackForm()
    if form.validate_on_submit():
        user_id = current_user.get_id()
        user = load_user(user_id)

        receiver = User.query.get(form.for_user.data)
        transaction = Transaction()
        transaction.spender = user
        transaction.receiver = receiver
        transaction.date = form.date.data
        transaction.comment = form.comment.data
        transaction.amount = int(form.amount.data * 100)
        transaction.item = "Payback %s" % receiver.display_name
        db.session.add(transaction)
        db.session.commit()

        flash('Successfully saved payback to %s' % receiver.username)

    return render_template('new_spending.html', form=form)


@app.route('/quick_payback/<username>', methods=['POST', 'GET'])
@login_required
def quick_payback(username):
    form = QuickPaybackForm()

    if form.validate_on_submit():
        user_id = current_user.get_id()
        user = load_user(user_id)

        receiver = User.query.filter_by(username=username).one()
        transaction = Transaction()
        transaction.spender = user
        transaction.receiver = receiver
        transaction.date = form.date.data
        transaction.comment = form.comment.data
        transaction.amount = int(form.amount.data * 100)
        transaction.item = "Payback %s" % receiver.display_name
        db.session.add(transaction)
        db.session.commit()

        flash('Successfully saved payback to %s' % receiver.username)
    else:
        to_user = User.query.filter_by(username=username).one()
        transactions_to = Transaction.query.filter_by(receiver=to_user, spender=current_user)
        transactions_from = Transaction.query.filter_by(receiver=current_user, spender=to_user)
        total = sum(t.amount for t in transactions_from) - sum(t.amount for t in transactions_to)
        form.amount.data = total / 100.00

    return render_template('new_spending.html', form=form)


@app.route('/userspending/', defaults={'username': 'self'})
@app.route('/userspending/<username>')
@login_required
def user_spendings(username):
    if username == 'self':
        user_id = current_user.get_id()
        user = load_user(user_id)
    else:
        user = User.query.filter_by(username=username).first()
    spendings = Transaction.query.filter_by(spender=user)
    return render_template('user_spendings.html', user=user, spendings=spendings)


if __name__ == "__main__":
    manager.run()

