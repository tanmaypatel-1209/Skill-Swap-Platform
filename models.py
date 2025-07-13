from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    skills_offered = db.Column(db.String(200), nullable=False)
    skills_wanted = db.Column(db.String(200), nullable=False)
    rating = db.Column(db.Float, default=0.0)
    photo_filename = db.Column(db.String(120), nullable=True)
    availability = db.Column(db.String(50), default='Flexible')
    photo_url = db.Column(db.String(500))  # Changed from photo_filename
    photo_public_id = db.Column(db.String(300))  # New field for Cloudinary reference
    # Add these missing fields:
    location = db.Column(db.String(100))
    bio = db.Column(db.Text)
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, server_default=db.func.now())
class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    request_id = db.Column(db.Integer, db.ForeignKey('request.id'), nullable=False)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, server_default=db.func.now())
    read = db.Column(db.Boolean, default=False)
    
<<<<<<< HEAD
    sender = db.relationship('User', backref='messages')
=======
    sender = db.relationship('User', backref='messages')
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()

# Request table
class Request(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, nullable=False)
    receiver_id = db.Column(db.Integer, nullable=False)
    status = db.Column(db.String(20), default="pending")

# Chat Message table
class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, nullable=False)
    receiver_id = db.Column(db.Integer, nullable=False)
    message = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
>>>>>>> 6add0c4 (add file)
