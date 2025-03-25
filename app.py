import os
from datetime import datetime
from flask import Flask, render_template, redirect, url_for, flash, request, send_from_directory, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, current_user, login_required
from flask_socketio import SocketIO, emit, join_room
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.utils import secure_filename
import logging
from logging.handlers import RotatingFileHandler
from models import User, db

# Initialize app and configurations
app = Flask(__name__)
app.config.from_object('config.Config')
app.config['DEBUG'] = True

# Setup database and login manager
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Setup SocketIO for realtime notifications (requires eventlet or gevent)
socketio = SocketIO(app)

# Setup rate limiting
limiter = Limiter(app, key_func=get_remote_address)

# Import models and forms (models import login_manager and db defined above)
from models import User, Ticket, TicketReply, Message
from forms import LoginForm, RegistrationForm, ProfileForm, TicketForm, ReplyForm, MessageForm, UserEditForm

# Ensure upload folder exists
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

# Set up logging with rotation
if not os.path.exists('logs'):
    os.mkdir('logs')
file_handler = RotatingFileHandler('logs/app.log', maxBytes=10240, backupCount=10)
file_handler.setFormatter(logging.Formatter(
    '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
))
file_handler.setLevel(logging.INFO)
app.logger.addHandler(file_handler)
app.logger.setLevel(logging.INFO)
app.logger.info('Ticketing system startup')

# ---------------------------
# Routes and Views
# ---------------------------

@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

# User Authentication Routes

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.check_password(form.password.data):
            login_user(user)
            flash('Logged in successfully.', 'success')
            return redirect(url_for('dashboard'))
        flash('Invalid username or password.', 'danger')
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

@app.route('/register', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    form = RegistrationForm()
    if form.validate_on_submit():
        if User.query.filter((User.username==form.username.data) | (User.email==form.email.data)).first():
            flash('Username or email already exists.', 'warning')
        else:
            user = User(username=form.username.data, email=form.email.data)
            user.set_password(form.password.data)
            db.session.add(user)
            db.session.commit()
            flash('Registration successful. Please log in.', 'success')
            return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    form = ProfileForm(obj=current_user)
    if form.validate_on_submit():
        current_user.name = form.name.data
        current_user.email = form.email.data
        
        # Update password if provided
        if form.new_password.data:
            current_user.set_password(form.new_password.data)
            flash('Your password has been updated.', 'success')
        else:
            flash('Profile updated.', 'success')
        
        db.session.commit()
        return redirect(url_for('profile'))
    return render_template('profile.html', form=form, permissions=current_user.permissions)

# Dashboard and Ticket Management

@app.route('/dashboard')
@login_required
def dashboard():
    # Get filter parameter (e.g., ?status=open)
    status_filter = request.args.get('status')
    if current_user.role in ['admin', 'support']:
        query = Ticket.query
        if status_filter:
            query = query.filter_by(status=status_filter)
        tickets = query.order_by(Ticket.created_at.desc()).all()
    else:
        tickets = Ticket.query.filter_by(creator_id=current_user.id).order_by(Ticket.created_at.desc()).all()
    return render_template('dashboard.html', tickets=tickets, status_filter=status_filter)

# Example: Emitting ticket event notifications
@app.route('/ticket/new', methods=['GET', 'POST'])
@login_required
def ticket_create():
    form = TicketForm()
    if form.validate_on_submit():
        ticket = Ticket(
            title=form.title.data, 
            description=form.description.data, 
            creator_id=current_user.id,
            priority=form.priority.data  # capture selected priority
        )
        db.session.add(ticket)
        db.session.commit()
        # Generate ticket number after ticket ID is assigned
        ticket.generate_ticket_number()
        db.session.commit()
        # Handle file attachment if provided...
        flash('Ticket created successfully.', 'success')
        # Emit a ticket creation notification to all connected clients
        socketio.emit('ticket_event', {
            'action': 'created',
            'ticket_number': ticket.ticket_number,
            'priority': ticket.priority,
            'created_at': ticket.created_at.strftime('%Y-%m-%d %H:%M')
        }, broadcast=True)
        return redirect(url_for('dashboard'))
    return render_template('ticket_create.html', form=form)

# Example: Emitting notification for ticket reply
@app.route('/ticket/<int:ticket_id>', methods=['GET', 'POST'])
@login_required
def ticket_detail(ticket_id):
    ticket = Ticket.query.get_or_404(ticket_id)
    # Permission check omitted for brevity
    form = ReplyForm()
    if form.validate_on_submit():
        reply = TicketReply(ticket_id=ticket.id, user_id=current_user.id, message=form.message.data)
        # Handle attachment if provided...
        db.session.add(reply)
        db.session.commit()
        flash('Reply added.', 'success')
        socketio.emit('ticket_event', {
            'action': 'replied',
            'ticket_number': ticket.ticket_number,
            'updated_at': ticket.updated_at.strftime('%Y-%m-%d %H:%M')
        }, broadcast=True)
        return redirect(url_for('ticket_detail', ticket_id=ticket.id))
    return render_template('ticket_detail.html', ticket=ticket, form=form)

# Example: Emitting private message notifications
@app.route('/chat/<int:user_id>', methods=['GET', 'POST'])
@login_required
def private_chat(user_id):
    recipient = User.query.get_or_404(user_id)
    form = MessageForm()
    form.recipient.choices = [(recipient.id, recipient.username)]
    messages = Message.query.filter(
        ((Message.sender_id==current_user.id) & (Message.recipient_id==recipient.id)) |
        ((Message.sender_id==recipient.id) & (Message.recipient_id==current_user.id))
    ).order_by(Message.created_at).all()
    if form.validate_on_submit():
        msg = Message(sender_id=current_user.id, recipient_id=recipient.id, message=form.message.data)
        # Handle attachment if provided...
        db.session.add(msg)
        db.session.commit()
        flash('Message sent.', 'success')
        # Emit private message notification only to the recipient (and optionally sender)
        socketio.emit('private_message', {
            'sender': current_user.username,
            'preview': msg.message[:20],
            'recipient_id': recipient.id,
            'created_at': msg.created_at.strftime('%H:%M')
        }, broadcast=True)
        return redirect(url_for('private_chat', user_id=recipient.id))
    return render_template('chat.html', recipient=recipient, form=form, messages=messages)

# SocketIO connection and event handler example
@socketio.on('connect')
def handle_connect():
    app.logger.info(f'User connected: {current_user.get_id()}')
    if current_user.is_authenticated:
        join_room(current_user.get_id())

# Administration Panel

@app.route('/admin/users')
@login_required
def admin_users():
    if current_user.role != 'admin':
        abort(403)
    users = User.query.all()
    return render_template('admin/users.html', users=users)

@app.route('/admin/logs')
@login_required
def admin_logs():
    if current_user.role != 'admin':
        abort(403)
    # Read last 100 lines from the log file
    try:
        with open('logs/app.log', 'r') as f:
            lines = f.readlines()[-100:]
    except Exception:
        lines = []
    return render_template('admin/logs.html', logs=lines)

@app.route('/admin/user/<int:user_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_user(user_id):
    if current_user.role != 'admin':
        abort(403)
    user = User.query.get_or_404(user_id)
    form = UserEditForm(obj=user)
    if form.validate_on_submit():
        user.role = form.role.data
        # Store the selected permissions as a comma-separated string.
        user.permissions = ','.join(form.permissions.data)
        db.session.commit()
        flash('User updated successfully.', 'success')
        return redirect(url_for('admin_users'))
    # Prepopulate the permissions field if they exist.
    if request.method == 'GET' and user.permissions:
        form.permissions.data = user.permissions.split(',')
    return render_template('admin/edit_user.html', form=form, user=user)

# Serve uploaded files
@app.route('/uploads/<filename>')
@login_required
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# ---------------------------
# SocketIO Events
# ---------------------------
@socketio.on('connect')
def handle_connect():
    app.logger.info(f'User connected: {current_user.get_id()}')
    # Optionally join a room for private notifications
    if current_user.is_authenticated:
        join_room(current_user.get_id())

# ---------------------------
# Error Handlers
# ---------------------------
@app.errorhandler(403)
def forbidden(error):
    return render_template('errors/403.html'), 403

@app.errorhandler(404)
def not_found(error):
    return render_template('errors/404.html'), 404

# ---------------------------
# Main
# ---------------------------
if __name__ == '__main__':
    # Create tables if they do not exist
    with app.app_context():
        db.create_all()
    # In production, use a proper WSGI server and eventlet/gevent
    socketio.run(app, debug=True)
