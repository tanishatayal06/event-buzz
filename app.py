from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import os
from werkzeug.utils import secure_filename
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from flask import request, redirect, flash
from werkzeug.utils import secure_filename
import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///yourdatabase.db'
db = SQLAlchemy(app)
migrate = Migrate(app, db)
app.secret_key = 'your_secret_key_here'

# Setup file upload folder
UPLOAD_FOLDER = 'static/uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

# Setup login manager
login_manager = LoginManager()
login_manager.login_view = 'login_page'
login_manager.init_app(app)

# Many-to-many relationship table for bookings and services
booking_service = db.Table('booking_service',
    db.Column('booking_id', db.Integer, db.ForeignKey('booking.id')),
    db.Column('service_id', db.Integer, db.ForeignKey('service.id'))
)

# Define User model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    avatar = db.Column(db.String(200), nullable=True)

class Service(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    service_type = db.Column(db.String(120), nullable=False)  # Add this line
    name = db.Column(db.String(120), nullable=False)
    phone = db.Column(db.String(120), nullable=True)
    email = db.Column(db.String(120), nullable=True)
    address = db.Column(db.String(120), nullable=True)
    description = db.Column(db.Text, nullable=True)
    photo = db.Column(db.String(120), nullable=True)

    def __repr__(self):
        return f'<Service {self.name}>'



# Define Booking model
class Booking(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    customer_name = db.Column(db.String(100), nullable=False)
    customer_email = db.Column(db.String(100), nullable=False)
    date = db.Column(db.DateTime, nullable=False)
    services = db.relationship('Service', secondary=booking_service, backref=db.backref('bookings'))

# Load user by user_id
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def main_page():
    services_by_type = {
        'Venue': Service.query.filter_by(service_type='Venue').all(),
        'Catering': Service.query.filter_by(service_type='Catering').all(),
        'Planning': Service.query.filter_by(service_type='Planning').all(),
        'Transportation': Service.query.filter_by(service_type='Transportation').all(),
        'Decoration': Service.query.filter_by(service_type='Decoration').all(),
        'Entertainment': Service.query.filter_by(service_type='Entertainment').all()
    }
    return render_template('mainpage.html',  services_by_type=services_by_type)

@app.route('/aboutus')
def about_us():
    return render_template('aboutus.html')

@app.route('/add_service', methods=['GET', 'POST'])
def add_service():
    if request.method == 'POST':
        service_type = request.form['service_type']
        name = request.form['name']
        phone = request.form['phone']
        email = request.form['email']
        address = request.form['address']
        description = request.form['description']
        photo = None

        if 'photo' in request.files:
            photo_file = request.files['photo']
            if photo_file.filename:
                filename = secure_filename(photo_file.filename)
                photo_path = os.path.join('static/uploads', filename)
                photo_file.save(photo_path)
                photo = photo_path

        new_service = Service(
            service_type=service_type,
            name=name,
            phone=phone,
            email=email,
            address=address,
            description=description,
            photo=photo
        )

        db.session.add(new_service)
        db.session.commit()

        flash("Service added successfully!", "success")
        return redirect(url_for('main_page'))  # Redirect to the home page

    return render_template('addservice.html')

@app.route('/catering')
def catering():
    return render_template('catering.html')

@app.route('/decoration')
def decoration():
    return render_template('decoration.html')

@app.route('/entertainment')
def entertainment():
    return render_template('entertainment.html')

@app.route('/eventplanning')
def event_planning():
    return render_template('eventplanning.html')

@app.route('/transportation')
def transportation():
    return render_template('transportation.html')

@app.route('/venue')
def venue():
    return render_template('venue.html')

@app.route('/login_page', methods=['GET', 'POST'])
def login_page():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(username=email).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            flash('Login successful', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid email or password', 'error')
    return render_template('loginpage.html')

@app.route('/registration', methods=['GET', 'POST'])
def registration():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm-password']

        if password != confirm_password:
            flash('Passwords do not match!', 'error')
            return redirect(url_for('registration'))

        existing_user = User.query.filter_by(username=email).first()
        if existing_user:
            flash('User already exists!', 'error')
            return redirect(url_for('registration'))

        hashed_password = generate_password_hash(password)
        new_user = User(username=email, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash('Registered successfully! Please log in.', 'success')
        return redirect(url_for('login_page'))
    return render_template('registration.html')

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'success')
    return redirect(url_for('login_page'))

@app.route('/book', methods=['GET', 'POST'])
@login_required
def book():
    if request.method == 'POST':
        name = request.form['customer_name']
        email = request.form['customer_email']
        date_str = request.form['date']  # This is where the date with time might be coming from
        
        # Adjust the format to handle the time part (e.g., '2025-04-16T02:24')
        date = datetime.strptime(date_str, '%Y-%m-%dT%H:%M')  # Updated format

        service_ids = request.form.getlist('services')
        selected_services = Service.query.filter(Service.id.in_(service_ids)).all()

        booking = Booking(customer_name=name, customer_email=email, date=date, services=selected_services)
        db.session.add(booking)
        db.session.commit()

        flash('Booking confirmed!', 'success')
        return redirect(url_for('booking_confirmation', booking_id=booking.id))

    all_services = Service.query.all()
    return render_template('book.html', services=all_services)


@app.route('/booking_confirmation/<int:booking_id>')
@login_required
def booking_confirmation(booking_id):
    booking = Booking.query.get_or_404(booking_id)
    return render_template('booking_confirmation.html', booking=booking)

@app.route('/booking_details')
@login_required
def booking_details():
    if current_user.is_admin:
        bookings = Booking.query.all()
    else:
        bookings = Booking.query.filter_by(customer_email=current_user.username).all()
    return render_template('booking_details.html', bookings=bookings)

@app.route('/admin_dashboard')
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        flash('You do not have permission to access this page.', 'error')
        return redirect(url_for('dashboard'))
    return render_template('admin_dashboard.html')

@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html', user=current_user)

@app.route('/edit_profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    if request.method == 'POST':
        new_email = request.form['email']
        
        if new_email and new_email != current_user.username:
            existing_user = User.query.filter_by(username=new_email).first()
            if existing_user:
                flash('Email already taken by another user.', 'error')
            else:
                current_user.username = new_email
                db.session.commit()
                flash('Email updated successfully!', 'success')
        return redirect(url_for('profile'))
    
    return render_template('edit_profile.html', user=current_user)

@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        current = request.form['current_password']
        new = request.form['new_password']
        confirm = request.form['confirm_password']

        if not check_password_hash(current_user.password, current):
            flash('Current password is incorrect.', 'error')
        elif new != confirm:
            flash('New passwords do not match.', 'error')
        else:
            hashed_password = generate_password_hash(new)
            current_user.password = hashed_password
            db.session.commit()
            flash('Password updated successfully!', 'success')
            return redirect(url_for('profile'))
    return render_template('change_password.html')

@app.route('/upload_avatar', methods=['POST'])
@login_required
def upload_avatar():
    if 'avatar' not in request.files:
        flash('No file part', 'error')
        return redirect(url_for('profile'))

    file = request.files['avatar']
    if file.filename == '':
        flash('No selected file', 'error')
        return redirect(url_for('profile'))

    filename = secure_filename(file.filename)
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(filepath)

    current_user.avatar = filename
    db.session.commit()
    flash('Profile photo updated!', 'success')
    return redirect(url_for('profile'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        # Create an admin user if not already exists
        if not User.query.filter_by(username='admin@example.com').first():
            admin = User(username='admin@example.com', password=generate_password_hash('adminpassword'), is_admin=True)
            db.session.add(admin)
            db.session.commit()

    app.run(debug=True)
