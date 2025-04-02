# app.py
from flask import Flask, render_template, request, redirect, url_for, flash, current_app
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer
from database import db
from models import User, Timetable, LeaveRequest
from timetable_logic import TimetableLogic
import random

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'  # Replace with a secure key
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///timetable.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'your-email@gmail.com'  # Replace with your email
app.config['MAIL_PASSWORD'] = 'your-app-password'  # Replace with your app password

# Initialize extensions
db.init_app(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
mail = Mail(app)
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# Flask-Login user loader
@login_manager.user_loader
def load_user(user_id):
    from models import User
    return User.query.get(int(user_id))

# Timetable logic instance
timetable_logic = TimetableLogic(db, app)

# Initialize database tables before any routes are accessed
with app.app_context():
    try:
        db.create_all()
        print("Database tables created successfully.")
    except Exception as e:
        print(f"Error creating database tables: {e}")

# Root route: Redirect to login if not authenticated
@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

# Registration route (Allow multiple HODs)
@app.route('/register', methods=['GET', 'POST'])
def register():
    from models import User
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        department = request.form['department']

        if not all([username, email, password, department]):
            flash('All fields are required.', 'danger')
            return redirect(url_for('register'))

        if User.query.filter_by(username=username).first():
            flash('Username already exists.', 'danger')
            return redirect(url_for('register'))
        if User.query.filter_by(email=email).first():
            flash('Email already exists.', 'danger')
            return redirect(url_for('register'))

        new_hod = User(username=username, email=email, role="HOD", department=department)
        new_hod.set_password(password)
        db.session.add(new_hod)
        db.session.commit()

        login_user(new_hod)
        flash('HOD registered successfully!', 'success')
        return redirect(url_for('dashboard'))

    return render_template('register.html')

# Add Teacher route (HOD only, restricted to their department)
@app.route('/add_teacher', methods=['GET', 'POST'])
@login_required
def add_teacher():
    from models import User
    if current_user.role != "HOD":
        flash('Only HODs can add teachers.', 'danger')
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        department = current_user.department  # HOD can only add to their own department

        if not all([username, email, password]):
            flash('All fields are required.', 'danger')
            return redirect(url_for('add_teacher'))

        if User.query.filter_by(username=username).first():
            flash('Username already exists.', 'danger')
            return redirect(url_for('add_teacher'))
        if User.query.filter_by(email=email).first():
            flash('Email already exists.', 'danger')
            return redirect(url_for('add_teacher'))

        new_teacher = User(username=username, email=email, role="Teacher", department=department)
        new_teacher.set_password(password)
        db.session.add(new_teacher)
        db.session.commit()

        flash(f'Teacher {username} added successfully!', 'success')
        return redirect(url_for('create_timetable', user_id=new_teacher.id))

    return render_template('add_teacher.html')

# Create Timetable route
@app.route('/create_timetable/<int:user_id>', methods=['GET', 'POST'])
@app.route('/create_timetable', methods=['GET', 'POST'])
@login_required
def create_timetable(user_id=None):
    from models import User, Timetable
    if current_user.role != "HOD":
        flash('Only HODs can create timetables.', 'danger')
        return redirect(url_for('dashboard'))

    target_user = current_user if user_id is None else User.query.get_or_404(user_id)
    if user_id and target_user.role != "Teacher":
        flash('You can only create timetables for teachers.', 'danger')
        return redirect(url_for('dashboard'))
    if user_id and target_user.department != current_user.department:
        flash('You can only create timetables for teachers in your department.', 'danger')
        return redirect(url_for('dashboard'))

    # Define the days of the week
    days = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]

    if request.method == 'POST':
        # Get the number of days and sessions from the form
        num_days = int(request.form.get('num_days', 5))
        num_sessions = int(request.form.get('num_sessions', 5))

        # Validate input
        if num_days < 1 or num_days > 7 or num_sessions < 1:
            flash('Number of days must be between 1 and 7, and sessions must be at least 1.', 'danger')
            return redirect(url_for('create_timetable', user_id=user_id))

        # Use only the selected number of days
        selected_days = days[:num_days]

        # Check if the form is submitting the timetable data (checkboxes)
        if 'generate' in request.form:
            # First step: Generate the grid for user input
            return render_template('create_timetable.html', target_user=target_user, days=selected_days, num_sessions=num_sessions)

        # Second step: Save the timetable based on checkbox input
        # Clear existing timetable for the user
        Timetable.query.filter_by(teacher_id=target_user.id).delete()

        # Process the checkbox data
        for day in selected_days:
            for session in range(1, num_sessions + 1):
                # Checkbox name format: "busy-Monday-1" for Monday, Session 1
                checkbox_name = f"busy-{day}-{session}"
                status = "Busy" if checkbox_name in request.form else "Free"
                entry = Timetable(
                    teacher_id=target_user.id,
                    day=day,
                    session=session,
                    status=status
                )
                db.session.add(entry)
        db.session.commit()
        flash(f'Timetable created for {target_user.username}!', 'success')
        return redirect(url_for('dashboard'))

    return render_template('create_timetable.html', target_user=target_user)

# Reset Teacher Password (HOD only, restricted to their department)
@app.route('/reset_teacher_password/<int:teacher_id>', methods=['POST'])
@login_required
def reset_teacher_password(teacher_id):
    from models import User
    if current_user.role != "HOD":
        flash('Only HODs can reset teacher passwords.', 'danger')
        return redirect(url_for('dashboard'))

    teacher = User.query.get_or_404(teacher_id)
    if teacher.role != "Teacher":
        flash('You can only reset passwords for teachers.', 'danger')
        return redirect(url_for('dashboard'))
    if teacher.department != current_user.department:
        flash('You can only reset passwords for teachers in your department.', 'danger')
        return redirect(url_for('dashboard'))

    new_password = request.form['new_password']
    if not new_password:
        flash('New password is required.', 'danger')
        return redirect(url_for('dashboard'))

    teacher.set_password(new_password)
    db.session.commit()
    flash(f'Password reset for {teacher.username}.', 'success')
    return redirect(url_for('dashboard'))

# Remove Teacher (HOD only, restricted to their department)
@app.route('/remove_teacher/<int:teacher_id>', methods=['POST'])
@login_required
def remove_teacher(teacher_id):
    from models import User, Timetable, LeaveRequest
    if current_user.role != "HOD":
        flash('Only HODs can remove teachers.', 'danger')
        return redirect(url_for('dashboard'))

    teacher = User.query.get_or_404(teacher_id)
    if teacher.role != "Teacher":
        flash('You can only remove teachers.', 'danger')
        return redirect(url_for('dashboard'))
    if teacher.department != current_user.department:
        flash('You can only remove teachers in your department.', 'danger')
        return redirect(url_for('dashboard'))

    Timetable.query.filter_by(teacher_id=teacher.id).delete()
    LeaveRequest.query.filter_by(teacher_id=teacher.id).delete()
    LeaveRequest.query.filter_by(substitute_id=teacher.id).delete()
    db.session.delete(teacher)
    db.session.commit()
    flash(f'Teacher {teacher.username} has been removed.', 'success')
    return redirect(url_for('dashboard'))

# Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    from models import User
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            flash('Logged in successfully!', 'success')
            return redirect(url_for('dashboard'))
        flash('Invalid username or password.', 'danger')
    return render_template('login.html')

# Logout route
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully!', 'success')
    return redirect(url_for('login'))

# Dashboard route (Updated to show HOD's timetable and allow leave application)
@app.route('/dashboard')
@login_required
def dashboard():
    from models import User, Timetable
    teachers = []
    timetable = []
    days = []
    num_sessions = 0

    # Define the correct order of days
    day_order = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]

    if current_user.role == "HOD":
        teachers = User.query.filter_by(role="Teacher", department=current_user.department).all()
        # Also fetch the HOD's timetable, if it exists
        timetable = Timetable.query.filter_by(teacher_id=current_user.id).all()
        if timetable:
            timetable_days = set(entry.day for entry in timetable)
            days = [day for day in day_order if day in timetable_days]
            num_sessions = max(entry.session for entry in timetable)
    elif current_user.role == "Teacher":
        timetable = Timetable.query.filter_by(teacher_id=current_user.id).all()
        if not timetable:
            flash('Your timetable has not been created yet. Please contact your HOD.', 'warning')
        else:
            # Get unique days from the timetable
            timetable_days = set(entry.day for entry in timetable)
            # Preserve the order of days as defined in day_order
            days = [day for day in day_order if day in timetable_days]
            num_sessions = max(entry.session for entry in timetable)

    return render_template('dashboard.html', teachers=teachers, timetable=timetable, days=days, num_sessions=num_sessions)

# Apply Leave route (Updated to allow HODs to apply for leave)
@app.route('/apply_leave', methods=['GET', 'POST'])
@login_required
def apply_leave():
    from models import User, Timetable, LeaveRequest
    # Allow both Teachers and HODs to apply for leave
    if current_user.role not in ["Teacher", "HOD"]:
        flash('Only teachers and HODs can apply for leave.', 'danger')
        return redirect(url_for('dashboard'))

    # Get the user's timetable to populate days and sessions
    timetable = Timetable.query.filter_by(teacher_id=current_user.id).all()
    if not timetable:
        flash('Your timetable has not been created yet. Please create a timetable first.', 'warning')
        return redirect(url_for('dashboard'))

    # Define the correct order of days
    day_order = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]
    timetable_days = set(entry.day for entry in timetable)
    days = [day for day in day_order if day in timetable_days]
    num_sessions = max(entry.session for entry in timetable)

    if request.method == 'POST':
        day = request.form['day']
        session = int(request.form['session'])
        substitute_username = request.form.get('substitute', '')

        # Check if the user is busy for the requested session
        user_entry = Timetable.query.filter_by(teacher_id=current_user.id, day=day, session=session).first()
        if user_entry and user_entry.status != "Busy":
            flash('You are free at that session, no need to apply for leave.', 'warning')
            return redirect(url_for('apply_leave'))

        # Get potential substitutes (same department, excluding the current user)
        # Include both Teachers and HODs as potential substitutes
        potential_substitutes = User.query.filter(
            User.role.in_(["Teacher", "HOD"]),
            User.department == current_user.department,
            User.id != current_user.id
        ).all()
        substitute = None

        # If a substitute is specified, check their availability
        if substitute_username:
            substitute = User.query.filter_by(username=substitute_username, department=current_user.department).first()
            if substitute:
                sub_entry = Timetable.query.filter_by(teacher_id=substitute.id, day=day, session=session).first()
                if sub_entry and sub_entry.status == "Busy":
                    flash(f'{substitute.username} is busy during that session and cannot be a substitute.', 'warning')
                    substitute = None  # Reset substitute to find another

        # If no substitute is specified or the specified one is busy, find an available substitute
        if not substitute:
            available_substitutes = []
            for user in potential_substitutes:
                sub_entry = Timetable.query.filter_by(teacher_id=user.id, day=day, session=session).first()
                if sub_entry and sub_entry.status == "Free":
                    available_substitutes.append(user)
            if available_substitutes:
                substitute = random.choice(available_substitutes)
            else:
                flash('No substitute available for that session.', 'danger')
                return redirect(url_for('apply_leave'))

        # Update the timetable entry for the user
        user_entry.status = "On Leave"
        user_entry.substitute_id = substitute.id
        db.session.add(user_entry)

        # Record the leave request
        leave = LeaveRequest(
            teacher_id=current_user.id,
            substitute_id=substitute.id,
            day=day,
            session=session
        )
        db.session.add(leave)
        db.session.commit()

        # Notify the HOD (if the user is a Teacher) or another HOD (if the user is an HOD)
        if current_user.role == "Teacher":
            hod = User.query.filter_by(role="HOD", department=current_user.department).first()
            if hod:
                msg_hod = Message("New Leave Request", sender=app.config['MAIL_USERNAME'], recipients=[hod.email])
                msg_hod.body = f"Teacher {current_user.username} has requested leave on {day}, session {session}."
                mail.send(msg_hod)
        else:  # HOD applying for leave
            # Notify another HOD in the same department, if available
            other_hod = User.query.filter_by(role="HOD", department=current_user.department).filter(User.id != current_user.id).first()
            if other_hod:
                msg_hod = Message("New Leave Request", sender=app.config['MAIL_USERNAME'], recipients=[other_hod.email])
                msg_hod.body = f"HOD {current_user.username} has requested leave on {day}, session {session}."
                mail.send(msg_hod)

        # Notify the substitute
        msg_sub = Message("Substitute Assignment", sender=app.config['MAIL_USERNAME'], recipients=[substitute.email])
        msg_sub.body = f"You are assigned as a substitute for {current_user.username} on {day}, session {session}."
        mail.send(msg_sub)

        flash('Leave request submitted successfully!', 'success')
        return redirect(url_for('dashboard'))

    # Potential substitutes for the dropdown (Teachers and HODs in the same department, excluding the current user)
    potential_substitutes = User.query.filter(
        User.role.in_(["Teacher", "HOD"]),
        User.department == current_user.department,
        User.id != current_user.id
    ).all()
    return render_template('apply_leave.html', teachers=potential_substitutes, days=days, num_sessions=num_sessions)

# Report route (HOD only, show leave requests from their department)
@app.route('/report')
@login_required
def report():
    from models import User, LeaveRequest
    if current_user.role != "HOD":
        flash('Only HODs can view reports.', 'danger')
        return redirect(url_for('dashboard'))

    # Only show leave requests from users in the HOD's department
    leaves = LeaveRequest.query.join(User, LeaveRequest.teacher_id == User.id).filter(User.department == current_user.department).all()
    return render_template('report.html', leaves=leaves)

# Timetable route
@app.route('/timetable')
@login_required
def timetable():
    from models import Timetable
    if current_user.role != "HOD":
        flash('Teachers can view their timetable on the dashboard.', 'danger')
        return redirect(url_for('dashboard'))

    timetable = Timetable.query.filter_by(teacher_id=current_user.id).all()
    if not timetable:
        flash('Please create your timetable first.', 'warning')
        return redirect(url_for('create_timetable'))

    # Define the correct order of days
    day_order = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]
    timetable_days = set(entry.day for entry in timetable)
    days = [day for day in day_order if day in timetable_days]
    num_sessions = max(entry.session for entry in timetable)
    return render_template('timetable.html', timetable=timetable, days=days, num_sessions=num_sessions)

# Password reset request route
@app.route('/reset_password_request', methods=['GET', 'POST'])
def reset_password_request():
    from models import User
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(email=email).first()
        if user:
            if user.role != "HOD":
                flash('Please contact the HOD to reset your password.', 'danger')
                return redirect(url_for('login'))
            token = serializer.dumps(user.id, salt='password-reset-salt')
            reset_url = url_for('reset_password', token=token, _external=True)
            msg = Message("Password Reset Request", sender=app.config['MAIL_USERNAME'], recipients=[email])
            msg.body = f"To reset your password, visit this link: {reset_url}\nThis link will expire in 1 hour."
            mail.send(msg)
            flash('An email has been sent with instructions to reset your password.', 'success')
        else:
            flash('No account found with that email address.', 'danger')
        return redirect(url_for('login'))
    return render_template('reset_password_request.html')

# Password reset route
@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    from models import User
    try:
        user_id = serializer.loads(token, salt='password-reset-salt', max_age=3600)
        user = User.query.get(user_id)
    except:
        flash('The reset link is invalid or has expired.', 'danger')
        return redirect(url_for('login'))

    if user.role != "HOD":
        flash('Please contact the HOD to reset your password.', 'danger')
        return redirect(url_for('login'))

    if request.method == 'POST':
        password = request.form['password']
        user.set_password(password)
        db.session.commit()
        flash('Your password has been updated! Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('reset_password.html')

if __name__ == '__main__':
    app.run(debug=True)