from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_user, logout_user, login_required, current_user
from .models import User, Message
from .forms import LoginForm, RegistrationForm, MessageForm
from . import db
from .utils import generate_aes_key_and_iv, encrypt_message
from .forms import DecryptMessageForm

bp = Blueprint('main', __name__)

@bp.route('/')
@bp.route('/index')
def index():
    return render_template('index.html')

@bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user is None or not user.check_password(form.password.data):
            flash('Invalid username or password')
            return redirect(url_for('main.login'))
        login_user(user)
        next_page = request.args.get('next')
        if not next_page or urlparse(next_page).netloc != '':
            next_page = url_for('main.index')
        flash('Logged in successfully!')
        return redirect(next_page)
    return render_template('login.html', form=form)

@bp.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('main.index'))

@bp.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(
            first_name=form.first_name.data,
            last_name=form.last_name.data,
            phone=form.phone.data,
            username=form.username.data,
            email=form.email.data
        )
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('Congratulations, you are now a registered user!')
        return redirect(url_for('main.login'))
    return render_template('register.html', form=form)


@bp.route('/send_message', methods=['GET', 'POST'])
@login_required
def send_message():
    form = MessageForm()
    if form.validate_on_submit():
        aes_algorithm = form.aes_algorithm.data
        aes_key, aes_iv = generate_aes_key_and_iv(aes_algorithm)
        encrypted_body = encrypt_message(form.body.data, aes_algorithm, aes_key, aes_iv)

        recipient = User.query.filter_by(username=form.recipient.data).first()
        if recipient:
            message = Message(
                sender_id=current_user.id,
                recipient_id=recipient.id,
                body=encrypted_body,
                aes_algorithm=aes_algorithm,
                aes_key=aes_key,
                aes_iv=aes_iv
            )
            db.session.add(message)
            db.session.commit()
            flash('Your message has been sent.')
            return redirect(url_for('main.index'))
        else:
            flash('Recipient not found.')
    return render_template('send_message.html', form=form)


@bp.route('/messages')
@login_required
def messages():
    received_messages = Message.query.filter_by(recipient_id=current_user.id).all()
    decrypted_messages = [(msg, msg.body) for msg in received_messages]
    return render_template('messages.html', messages=decrypted_messages)


@bp.route('/decrypt_message/<int:message_id>', methods=['GET'])
@login_required
def decrypt_message(message_id):
    message = Message.query.get(message_id)
    if message and message.recipient_id == current_user.id:
        decrypted_body = decrypt_message(
            message.body,
            message.aes_algorithm,
            message.aes_key,
            message.aes_iv
        )
        flash(f'Decrypted message: {decrypted_body}')
    else:
        flash('Message not found or you are not authorized to view it.')
    return redirect(url_for('main.messages'))



from .utils import decrypt_message

@bp.route('/decrypt_message/<int:message_id>', methods=['GET'])
@login_required
def decrypt_message_route(message_id):
    message = Message.query.get(message_id)
    if message and message.recipient_id == current_user.id:
        try:
            decrypted_body = decrypt_message(
                message.body,
                message.aes_algorithm,
                message.aes_key,
                message.aes_iv
            )
            flash(f'Decrypted message: {decrypted_body}')
        except Exception as e:
            flash(f'Error decrypting message: {e}')
    else:
        flash('Message not found or you are not authorized to view it.')
    return redirect(url_for('main.messages'))

@bp.route('/decrypt_message_manual', methods=['GET', 'POST'])
@login_required
def decrypt_message_manual():
    form = DecryptMessageForm()
    decrypted_message = None
    if form.validate_on_submit():
        try:
            decrypted_message = decrypt_message(
                form.encrypted_message.data,
                form.aes_algorithm.data,
                form.aes_key.data,
                form.aes_iv.data
            )
        except Exception as e:
            flash(f'Error decrypting message: {e}')
    return render_template('decrypt_message_manual.html', form=form, decrypted_message=decrypted_message)



