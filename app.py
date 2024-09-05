from flask import Flask, render_template, request, flash, redirect, url_for,get_flashed_messages, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from keras.models import load_model
from keras.preprocessing import image
from datetime import datetime
import os
import numpy as np
import tensorflow as tf
from PIL import Image

app = Flask(__name__)
app.config['SECRET_KEY'] = 'zafrihaikal'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///krackdatabase.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

model = load_model('C:/Users/zfrhk/Documents/Website/BinaryCNNModel.h5')

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(100), nullable=False)
    detections = db.relationship('Detection', backref='user', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Detection(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    image_path = db.Column(db.String(255))
    prediction = db.Column(db.String(50))
    confidence_level = db.Column(db.Float)
    accuracy = db.Column(db.Float)
    location = db.Column(db.String(255))
    date = db.Column(db.String(20))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def save_detection_result(img_path, prediction, confidence_level, accuracy, location, date):
    try:
        # Separate images into folders based on prediction
        save_folder = 'crack_images' if prediction == 'Crack Detected' else 'uncrack_images'
        
        # Create the destination folder if it doesn't exist
        destination_folder = os.path.join('static/uploads', save_folder)
        os.makedirs(destination_folder, exist_ok=True)
        
        # Construct the destination path
        destination_filename = os.path.basename(img_path)
        destination_path = os.path.join(destination_folder, destination_filename)

        # Check if a file with the same name already exists in the destination folder
        counter = 1
        while os.path.exists(destination_path):
            filename, extension = os.path.splitext(destination_filename)
            destination_filename = f"{filename}_{counter}{extension}"
            destination_path = os.path.join(destination_folder, destination_filename)
            counter += 1

        # Update the image_path in the database to include the folder structure
        image_path = os.path.join(save_folder, destination_filename)

        detection_result = Detection(
            image_path=image_path,
            prediction=prediction,
            confidence_level=confidence_level,
            accuracy=accuracy,
            location=location,
            date=date,
            user=current_user
        )
        db.session.add(detection_result)
        db.session.commit()

        # Move the image to the appropriate folder
        os.rename(img_path, destination_path)

    except Exception as e:
        print(f"An error occurred: {e}")

def create_admin_user():
    admin = User(username='admin')
    admin.set_password('admin_password')  
    db.session.add(admin)
    db.session.commit()

@app.route('/')
def home():
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        existing_user = User.query.filter_by(username=username).first()

        if existing_user:
            flash('Username already exists. Please choose a different one.', 'danger')
            return redirect(url_for('signup'))

        new_user = User(username=username)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()

        flash('Account created successfully. Please Log In.', 'success')
        return redirect(url_for('login'))

    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            login_user(user)
            flash('Login Successful', 'success')

            # Redirect to admin dashboard if the logged-in user is admin
            if username == 'admin':
                return redirect(url_for('admin_dashboard'))
            else:
                return redirect(url_for('dashboard'))
        else:
            flash('Login failed. Check your username and password.', 'danger')

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    session.pop('_flashes', None)
    flash('Logged out successfully.', 'success')
    return redirect(url_for('home'))

# Add this to your app.py

@app.route('/admin_dashboard')
@login_required
def admin_dashboard():
    if current_user.username == 'admin':
        all_detection_results = Detection.query.all()
        return render_template('admin_dashboard.html', all_detection_results=all_detection_results)
    else:
        flash('Unauthorized access to admin dashboard.', 'danger')
        return redirect(url_for('admin_dashboard'))


@app.route('/dashboard')
@login_required
def dashboard():
    detection_results = Detection.query.filter_by(user=current_user).all()
    messages = session.pop('messages', None)
    return render_template('dashboard.html', detection_results=detection_results,messages=messages)

@app.route('/delete_detection/<int:detection_id>', methods=['POST'])
@login_required
def delete_detection(detection_id):
    detection = Detection.query.get(detection_id)

    if detection:
        db.session.delete(detection)
        db.session.commit()
        flash('Detection result deleted successfully.', 'success')
    else:
        flash('Detection result not found.', 'danger')

    # Pass flashed messages to the dashboard route
    return redirect(url_for('dashboard', messages=get_flashed_messages()))

@app.route('/about')
def about():
    detection_results = Detection.query.all()
    
    # Extract prediction classes and their counts
    prediction_classes = [result.prediction for result in detection_results]
    prediction_counts = {cls: prediction_classes.count(cls) for cls in set(prediction_classes)}

    return render_template('about.html', prediction_counts=prediction_counts)

@app.route('/adbout')
def adbout():
    detection_results = Detection.query.all()
    
    # Extract prediction classes and their counts
    prediction_classes = [result.prediction for result in detection_results]
    prediction_counts = {cls: prediction_classes.count(cls) for cls in set(prediction_classes)}

    return render_template('adbout.html', prediction_counts=prediction_counts)


#Detect Section 

@app.route('/crack_detect', methods=['GET', 'POST'])
@login_required
def crack_detect():
    if request.method == 'POST':
        file = request.files['image']

        # Generate a unique filename based on the current timestamp
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        img_filename = f"{timestamp}_{secure_filename(file.filename)}"

        img_path = os.path.join('static/uploads', file.filename)
        file.save(img_path)

        #Get current date and time
        current_date = datetime.now().strftime("%Y-%m-%d")

        # Get Location input form data
        location = request.form['location']

        # Call the predict_crack function
        prediction, confidence_level, accuracy, category = predict_crack(img_path)

        # Save detection result
        save_detection_result(img_path, prediction, confidence_level, accuracy, location, current_date)
        
        # Flash the detection result message
        flash(f'Detection completed successfully.Prediction: {prediction}', category)

        # Redirect to the dashboard
        return redirect(url_for('dashboard'))
    return render_template('crack_detect.html')

def predict_crack(img_path):
   
    img = image.load_img(img_path, target_size=(120, 120), color_mode = "rgb")
    img = image.img_to_array(img)
    img = np.expand_dims(img, axis=0)
    img = img / 255.0
    result = model.predict(img)

    confidence_level = result[0][0]  


    #predictions = model.predict(img)
    score = tf.nn.softmax(result[0])
    # print(class_names)

    if confidence_level < 1e-5:
        prediction = 'Cannot detect'
        category = 'danger'
        accuracy = 100 * np.max(score)
    else:
        prediction = 'Crack Detected' if confidence_level > 0.5 else 'Uncrack Detected'
        category = 'success' if confidence_level > 0.5 else 'danger'
        accuracy = 100 * np.max(score)

    print(accuracy)

    return prediction, confidence_level,  accuracy, category


if __name__ == '__main__':
    with app.app_context():
        db.create_all()

    app.run(debug=True,port=5000)
