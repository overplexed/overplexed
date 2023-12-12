from datetime import datetime
import os
from bson import ObjectId
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from pymongo import MongoClient
from werkzeug.security import check_password_hash, generate_password_hash
from dotenv import load_dotenv

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY")
load_dotenv()

# Configure Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Configure MongoClient
mongo_uri = os.getenv("MONGO_URI")
client = MongoClient(mongo_uri)
db = client.users

# User model for Flask-Login
class User(UserMixin):
    pass

@login_manager.user_loader
def load_user(user_id):
    user_data = db.users.find_one({"_id": ObjectId(user_id)})
    if user_data:
        user = User()
        user.id = str(user_data['_id'])
        return user
    return None

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    connection_status = None  # Initialize connection_status here

    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        # Check MongoDB connection status
        try:
            client.admin.command('ping')  # Attempt to ping the MongoDB server
            connection_status = "Connection to MongoDB: Successful"
        except Exception as e:
            connection_status = f"Connection to MongoDB: Failed ({e})"
        
        # Check if the 'users' collection exists
        if 'users' not in db.list_collection_names():
            error = "User collection does not exist."
            return render_template('login.html', error=error, connection_status=connection_status)
        
        user_data = db.users.find_one({"email": email})
        
        if user_data and check_password_hash(user_data['password'], password):
            user = User()
            user.id = str(user_data['_id'])
            login_user(user)
            return redirect(url_for('index'))
        else:
            error = "Invalid email or password"

    return render_template('login.html', error=error, connection_status=connection_status)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        phone = request.form['phone']
        name = request.form['name']
        password = request.form['password']
        current_time = datetime.now()
        # Check if the 'users' collection exists
        if 'users' not in db.list_collection_names():
            db.create_collection('users')

        # Check if the email is already registered
        existing_user = db.users.find_one({"email": email})
        if existing_user:
            flash("Email is already registered", "error")
        else:
            # Hash the password before storing it
            hashed_password = generate_password_hash(password)

            # Create a new user document
            new_user = {
                "email": email,
                "password": hashed_password,
                "phone":phone,
                "name":name,
                "time": current_time,
                "country":None,
                
            }

            try:
                # Insert the new user into the 'users' collection
                user_id = db.users.insert_one(new_user).inserted_id
                flash("Registration successful. You can now log in.", "success")
                return redirect(url_for('login'))
            except Exception as e:
                flash(f"Registration failed: {e}", "error")

    return render_template('register.html')

@app.route('/')
def index():
        # Check if the user is authenticated before accessing attributes
    if current_user.is_authenticated:
        user_id = current_user.id
        return render_template('index.html', user=user_id)
    else:
        return render_template('index.html', user=None)


@app.route('/success')
def success():
    return "Login successful!"


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.config['SESSION_COOKIE_SECURE'] = True

    # Check MongoDB connection status before starting the app
    try:
        client.admin.command('ping')
        print("Connection to MongoDB: Successful")
    except Exception as e:
        print(f"Connection to MongoDB: Failed ({e})")

    app.run(debug=True)
