from flask import Flask, render_template, request, url_for, redirect, session, flash
from joblib import load
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
import pandas as pd
import os

app = Flask(__name__)
app.secret_key = '1234'

# SQLite database file path
db_file = 'user_registration.db'

# Initialize SQLite database and create tables if they don't exist
def init_db():
    with sqlite3.connect(db_file) as conn:
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL
            )
        ''')
        conn.commit()

init_db()
# Database connection helper function
def get_db_connection():
    conn = sqlite3.connect(db_file)
    conn.row_factory = sqlite3.Row
    return conn

# Load the model
model = load('random_forest_model.joblib')
feature_names = model.feature_names_in_.tolist()

@app.route('/')
def home():
    return render_template('login.html')

@app.route('/predict', methods=['POST'])
def predict():
    engine_size = float(request.form['engine_size'])
    vehicle_class = request.form['vehicle_class']

    input_data_dict = {feature: 0 for feature in feature_names}
    input_data_dict['Engine Size(L)'] = engine_size

    vehicle_class_feature = f'Vehicle Class_{vehicle_class}'
    if vehicle_class_feature in feature_names:
        input_data_dict[vehicle_class_feature] = 1
    else:
        return f'Error: Vehicle class "{vehicle_class}" is not valid.'

    input_data = pd.DataFrame([input_data_dict])
    prediction = model.predict(input_data)

    return f'The predicted CO2 emissions is: {prediction[0]:.2f} g/km'

@app.route('/calculate_total_carbon_emission')
def calculate_total_carbon_emission():
    return render_template('calculator.html')

@app.route('/emission')
def emission_result():
    return render_template('emission.html')

@app.route('/predictor')
def predictor_result():
    return render_template('predictor.html')

@app.route('/index')
def index():
    return render_template('index.html')

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        # Handle forgot password logic here
        return redirect(url_for('login'))
    return render_template('forgotPassword.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        try:
            conn = get_db_connection()
            cursor = conn.cursor()

            # Check if the user exists
            cursor.execute('SELECT * FROM users WHERE email = ?', (email,))
            user = cursor.fetchone()
            conn.close()

            if user:
                # user['password'] corresponds to the password stored in the database
                if check_password_hash(user['password'], password):
                    session['user_id'] = user['id']  # Store the user ID in session
                    flash("Login successful!")
                    return redirect('/index')  # Redirect to a dashboard or home page
                else:
                    flash("Incorrect password. Please try again.")
            else:
                flash("Email not found. Please register first.")
        except Exception as e:
            flash(f"An error occurred: {e}")
        
        return redirect('/login')

    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        # Get form data
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        # Check if passwords match
        if password != confirm_password:
            flash("Passwords do not match!")
            return redirect('/register')

        # Hash the password using pbkdf2:sha256
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

        try:
            # Insert user data into SQLite database
            conn = get_db_connection()
            cursor = conn.cursor()

            # Check if the email already exists
            cursor.execute('SELECT * FROM users WHERE email = ?', (email,))
            existing_user = cursor.fetchone()
            if existing_user:
                flash("Email already registered!")
                return redirect('/register')

            # Insert new user into database
            cursor.execute('INSERT INTO users (email, password) VALUES (?, ?)', (email, hashed_password))
            conn.commit()
            conn.close()

            flash("Registration successful! Please login.")
            return redirect('/login')

        except Exception as e:
            flash(f"An error occurred: {e}")
            return redirect('/register')

    return render_template('register.html')

if __name__ == '__main__':
    # Initialize the database
    if not os.path.exists(db_file):
        init_db()
    app.run(debug=True, host="0.0.0.0")
