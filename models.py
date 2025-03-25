from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from app import db, login_manager
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    name = db.Column(db.String(120))
    password_hash = db.Column(db.String(128))
    role = db.Column(db.String(20), default='customer')  # roles: customer, support, admin
    # New permissions field: comma-separated list (e.g., "view,create,update")
    permissions = db.Column(db.String(200), default='view')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    # Relationships
    tickets = db.relationship('Ticket', backref='creator', lazy='dynamic')
    messages_sent = db.relationship('Message', foreign_keys='Message.sender_id', backref='sender', lazy='dynamic')
    messages_received = db.relationship('Message', foreign_keys='Message.recipient_id', backref='recipient', lazy='dynamic')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password, method='pbkdf2:sha256')

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class Ticket(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ticket_number = db.Column(db.String(20), unique=True)
    title = db.Column(db.String(140))
    description = db.Column(db.Text)
    status = db.Column(db.String(20), default='open')  # open, in progress, closed
    priority = db.Column(db.String(20), default='normal')
    creator_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    assigned_to = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    # Relationships
    replies = db.relationship('TicketReply', backref='ticket', lazy='dynamic')

    def generate_ticket_number(self):
        # Example: "Ticket# 03-25-024" where 03 is month, 25 is year, and id padded to 3 digits.
        now = datetime.utcnow()
        self.ticket_number = f"Ticket# {now.strftime('%m-%y')}-{str(self.id).zfill(3)}"

class TicketReply(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ticket_id = db.Column(db.Integer, db.ForeignKey('ticket.id'))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    message = db.Column(db.Text)
    attachment = db.Column(db.String(140))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    recipient_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    message = db.Column(db.Text)
    attachment = db.Column(db.String(140))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class PrivateMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    recipient_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    message = db.Column(db.Text, nullable=False)
    attachment = db.Column(db.String(255), nullable=True)  # File path
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
