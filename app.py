from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer
import os
from datetime import datetime

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'super_secret_123')

# Email Configuration
app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.environ.get('MAIL_USE_TLS', 'true').lower() == 'true'
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_DEFAULT_SENDER')
app.config['SECURITY_PASSWORD_SALT'] = os.environ.get('SECURITY_PASSWORD_SALT', 'another_secret_salt_123')
mail = Mail(app)
serializer = URLSafeTimedSerializer(app.secret_key)

# Database setup
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'postgresql://postgres:nQQSxXyRhAcikuTpKSvttuilUxGVqPlb@yamanote.proxy.rlwy.net:11425/railway')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Upload configuration
UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024  # 2MB
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    skills_offered = db.Column(db.String(200), nullable=False)
    skills_wanted = db.Column(db.String(200), nullable=False)
    rating = db.Column(db.Float, default=0.0)
    photo_filename = db.Column(db.String(120))
    location = db.Column(db.String(100))
    availability = db.Column(db.String(100))
    bio = db.Column(db.Text)
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Request(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    requester_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    recipient_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    skill_requested = db.Column(db.String(200), nullable=False)
    message = db.Column(db.String(500))
    status = db.Column(db.String(20), default='pending')
    created_at = db.Column(db.DateTime, server_default=db.func.now())
    updated_at = db.Column(db.DateTime, onupdate=db.func.now())
    
    requester = db.relationship('User', foreign_keys=[requester_id])
    recipient = db.relationship('User', foreign_keys=[recipient_id])

@app.route('/')
def home():
    query = request.args.get('q', '')
    location = request.args.get('location', '')
    availability = request.args.get('availability', '')

    users = User.query

    if query:
        users = users.filter(
            db.or_(
                User.skills_offered.ilike(f'%{query}%'),
                User.skills_wanted.ilike(f'%{query}%'),
                User.name.ilike(f'%{query}%')
            )
        )
    if location:
        users = users.filter(User.location.ilike(f'%{location}%'))
    if availability:
        users = users.filter(User.availability.ilike(f'%{availability}%'))

    return render_template('home.html', users=users.all())

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        name = request.form['name']
        skills_offered = request.form['skills_offered']
        skills_wanted = request.form['skills_wanted']
        location = request.form.get('location', '')
        availability = request.form.get('availability', '')
        bio = request.form.get('bio', '')

        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('Email already registered. Try logging in.', 'error')
            return redirect(url_for('signup'))

        photo_filename = None
        if 'photo' in request.files:
            file = request.files['photo']
            if file and file.filename != '' and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                unique_filename = f"{email.split('@')[0]}_{filename}"
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], unique_filename))
                photo_filename = unique_filename

        hashed_pw = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(
            email=email,
            password=hashed_pw,
            name=name,
            skills_offered=skills_offered,
            skills_wanted=skills_wanted,
            photo_filename=photo_filename,
            location=location,
            availability=availability,
            bio=bio,
            is_admin=(email == os.environ.get('ADMIN_EMAIL'))
        )
        db.session.add(new_user)
        db.session.commit()

        session['user_id'] = new_user.id
        flash('Signup successful!', 'success')
        return redirect(url_for('profile'))

    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            flash('Login successful!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Invalid credentials', 'error')
            return redirect(url_for('login'))

    return render_template('login.html')

@app.route('/profile')
def profile():
    if 'user_id' not in session:
        flash('Please login to view your profile', 'error')
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    pending_requests = Request.query.filter_by(recipient_id=user.id, status='pending').all()
    return render_template('profile.html', user=user, pending_requests=pending_requests)

@app.route('/request/<int:user_id>', methods=['GET', 'POST'])
def request_skill(user_id):
    if 'user_id' not in session:
        flash('Please login to send requests', 'error')
        return redirect(url_for('login'))
    
    recipient = User.query.get_or_404(user_id)
    requester = User.query.get(session['user_id'])
    
    if request.method == 'POST':
        skill_requested = request.form['skill_requested']
        message = request.form.get('message', '')
        
        new_request = Request(
            requester_id=requester.id,
            recipient_id=recipient.id,
            skill_requested=skill_requested,
            message=message
        )
        db.session.add(new_request)
        db.session.commit()
        
        try:
            msg = Message(
                subject=f"New Skill Swap Request for {skill_requested}",
                recipients=[recipient.email],
                body=f"""Hello {recipient.name},

{requester.name} has requested to swap skills with you for: {skill_requested}

Message: {message}

Please login to your account to respond to this request.

Best regards,
Skill Swap Team
"""
            )
            mail.send(msg)
            flash('Request sent successfully!', 'success')
        except Exception as e:
            print(f"Error sending email: {e}")
            flash('Request saved but email could not be sent', 'warning')
        
        return redirect(url_for('home'))
    
    return render_template('request.html', recipient=recipient)

@app.route('/request/<int:request_id>/<action>')
def handle_request(request_id, action):
    if 'user_id' not in session:
        flash('Please login to manage requests', 'error')
        return redirect(url_for('login'))
    
    req = Request.query.get_or_404(request_id)
    
    if req.recipient_id != session['user_id']:
        flash('Unauthorized action', 'error')
        return redirect(url_for('home'))
    
    if action == 'accept':
        req.status = 'accepted'
        try:
            msg = Message(
                subject=f"Your skill swap request was accepted!",
                recipients=[req.requester.email],
                body=f"""Hello {req.requester.name},

{req.recipient.name} has accepted your skill swap request for: {req.skill_requested}

You can now contact them at: {req.recipient.email}

Happy skill swapping!

Best regards,
Skill Swap Team
"""
            )
            mail.send(msg)
        except Exception as e:
            print(f"Error sending acceptance email: {e}")
    elif action == 'reject':
        req.status = 'rejected'
    
    db.session.commit()
    flash(f"Request {action}ed!", 'success')
    return redirect(url_for('profile'))

@app.route('/rate/<int:user_id>', methods=['POST'])
def rate_user(user_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    rating = request.form.get('rating')
    if not rating or not rating.isdigit() or int(rating) < 1 or int(rating) > 5:
        flash('Invalid rating', 'error')
        return redirect(url_for('profile'))
    
    user = User.query.get(user_id)
    if user.rating == 0:
        user.rating = int(rating)
    else:
        user.rating = round((user.rating + int(rating)) / 2, 1)
    db.session.commit()
    
    flash('Rating submitted!', 'success')
    return redirect(url_for('profile'))

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(email=email).first()
        if user:
            token = serializer.dumps(email, salt=app.config['SECURITY_PASSWORD_SALT'])
            reset_url = url_for('reset_password', token=token, _external=True)
            try:
                msg = Message(
                    subject="Password Reset Request",
                    recipients=[email],
                    body=f"""To reset your password, visit the following link:
{reset_url}

This link will expire in 1 hour.

If you didn't request this, please ignore this email.
"""
                )
                mail.send(msg)
                flash('Password reset link sent to your email', 'info')
            except Exception as e:
                print(f"Error sending email: {e}")
                flash('Could not send reset email. Please try again.', 'error')
        else:
            flash('Email not found', 'error')
        return redirect(url_for('forgot_password'))
    return render_template('forgot_password.html')

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        email = serializer.loads(
            token,
            salt=app.config['SECURITY_PASSWORD_SALT'],
            max_age=3600
        )
    except:
        flash('Invalid or expired token', 'error')
        return redirect(url_for('forgot_password'))
    
    if request.method == 'POST':
        user = User.query.filter_by(email=email).first()
        if user:
            user.password = generate_password_hash(request.form['password'])
            db.session.commit()
            flash('Password updated successfully', 'success')
            return redirect(url_for('login'))
    
    return render_template('reset_password.html', token=token)

@app.route('/admin')
def admin_dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    if not user.is_admin:
        flash('Unauthorized access', 'error')
        return redirect(url_for('home'))
    
    users = User.query.all()
    requests = Request.query.order_by(Request.created_at.desc()).all()
    return render_template('admin.html', users=users, requests=requests)

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('You have logged out.', 'info')
    return redirect(url_for('home'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)