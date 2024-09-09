from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from datetime import datetime
from models import db, User, Training, Registration
from config import Config

app = Flask(__name__)
app.config.from_object(Config)

db.init_app(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def index():
    trainings = Training.query.all()
    registrations = {}
    if current_user.is_authenticated:
        for training in trainings:
            registrations[training.id] = Registration.query.filter_by(training_id=training.id).join(User).with_entities(User.username).all()
    return render_template('index.html', trainings=trainings, Registration=Registration, registrations=registrations)

@app.route('/register/<int:training_id>', methods=['GET', 'POST'])
@login_required
def register(training_id):
    training = Training.query.get_or_404(training_id)
    if request.method == 'POST':
        if Registration.query.filter_by(user_id=current_user.id, training_id=training.id).first():
            flash('You are already registered for this training.', 'error')
        elif training.registrations.count() >= training.max_participants:
            flash('This training session is full.', 'error')
        else:
            new_registration = Registration(user_id=current_user.id, training_id=training.id)
            db.session.add(new_registration)
            db.session.commit()
            flash('Registration successful!', 'success')
        return redirect(url_for('index'))
    return render_template('register.html', training=training)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form['username']).first()
        if user and user.check_password(request.form['password']):
            login_user(user)
            flash('Logged in successfully.', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password', 'error')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully.', 'success')
    return redirect(url_for('index'))

@app.route('/admin')
@login_required
def admin():
    if not current_user.is_admin:
        flash('You do not have permission to access this page.', 'error')
        return redirect(url_for('index'))
    trainings = Training.query.all()
    registrations = {}
    for training in trainings:
        registrations[training.id] = Registration.query.filter_by(training_id=training.id).join(User).with_entities(User.username, User.email).all()
    return render_template('admin.html', trainings=trainings, registrations=registrations)

@app.route('/admin/add_training', methods=['GET', 'POST'])
@login_required
def add_training():
    if not current_user.is_admin:
        flash('You do not have permission to access this page.', 'error')
        return redirect(url_for('index'))
    if request.method == 'POST':
        date = datetime.strptime(request.form['date'], '%Y-%m-%dT%H:%M')
        max_participants = int(request.form['max_participants'])
        new_training = Training(date=date, max_participants=max_participants)
        db.session.add(new_training)
        db.session.commit()
        flash('New training added successfully!', 'success')
        return redirect(url_for('admin'))
    return render_template('add_training.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        
        existing_user = User.query.filter((User.username == username) | (User.email == email)).first()
        if existing_user:
            flash('Username or email already exists.', 'error')
        else:
            new_user = User(username=username, email=email)
            new_user.set_password(password)
            db.session.add(new_user)
            db.session.commit()
            flash('Account created successfully. Please log in.', 'success')
            return redirect(url_for('login'))
    return render_template('signup.html')

@app.route('/unregister/<int:training_id>', methods=['POST'])
@login_required
def unregister(training_id):
    training = Training.query.get_or_404(training_id)
    registration = Registration.query.filter_by(user_id=current_user.id, training_id=training.id).first()
    if registration:
        db.session.delete(registration)
        db.session.commit()
        flash('You have been unregistered from the training.', 'success')
    else:
        flash('You are not registered for this training.', 'error')
    return redirect(url_for('index'))

# Add these new routes after the existing admin routes

@app.route('/admin/edit_training/<int:training_id>', methods=['GET', 'POST'])
@login_required
def edit_training(training_id):
    if not current_user.is_admin:
        flash('You do not have permission to access this page.', 'error')
        return redirect(url_for('index'))
    
    training = Training.query.get_or_404(training_id)
    
    if request.method == 'POST':
        training.date = datetime.strptime(request.form['date'], '%Y-%m-%dT%H:%M')
        training.max_participants = int(request.form['max_participants'])
        db.session.commit()
        flash('Training updated successfully!', 'success')
        return redirect(url_for('admin'))
    
    return render_template('edit_training.html', training=training)

@app.route('/admin/delete_training/<int:training_id>', methods=['POST'])
@login_required
def delete_training(training_id):
    if not current_user.is_admin:
        flash('You do not have permission to access this page.', 'error')
        return redirect(url_for('index'))
    
    training = Training.query.get_or_404(training_id)
    db.session.delete(training)
    db.session.commit()
    flash('Training deleted successfully!', 'success')
    return redirect(url_for('admin'))

import click

@app.cli.command("init-db")
def init_db_command():
    db.create_all()
    print("Database tables created successfully.")

@app.cli.command("create-admin")
@click.option('--username', prompt=True)
@click.option('--email', prompt=True)
@click.option('--password', prompt=True, hide_input=True, confirmation_prompt=True)
def create_admin(username, email, password):
    admin = User(username=username, email=email, is_admin=True)
    admin.set_password(password)
    db.session.add(admin)
    db.session.commit()
    print(f"Admin user '{username}' created successfully.")

if __name__ == '__main__':
    app.run(debug=True)