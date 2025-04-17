import telebot
import os
import sqlite3
import requests
import logging
import atexit
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from apscheduler.schedulers.background import BackgroundScheduler
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from werkzeug.utils import secure_filename

# Konfigurasi bot Telegram
TOKEN = "7937058330:AAH--JmE_PeKDmljqxxgwg-LOtxfz37IAMU"  # Ganti dengan Token API dari BotFather
WEBHOOK_URL = "https://14d2-36-74-17-187.ngrok-free.app" # Ganti dengan URL webhook Anda

bot = telebot.TeleBot(TOKEN)
app = Flask(__name__)
app.secret_key = 'your_secret_key'
login_manager = LoginManager()
login_manager.init_app(app)
scheduler = BackgroundScheduler()

# File upload configuration
UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Helper function to check allowed file extensions
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Koneksi ke database
DATABASE = 'website_monitor.db'

def connect_db():
    return sqlite3.connect(DATABASE)


# User model
class User(UserMixin):
    def __init__(self, id, username, role, chat_id=None):
        self.id = id
        self.username = username
        self.role = role
        self.chat_id = chat_id

@login_manager.user_loader
def load_user(user_id):
    connection = connect_db()
    cursor = connection.cursor()
    cursor.execute("SELECT id, username, role, chat_id FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    cursor.close()
    connection.close()
    if user:
        return User(user[0], user[1], user[2], user[3])
    return None

# Fungsi untuk memeriksa status website
def check_website_status(url):
    try:
        # Ensure the URL has a valid protocol
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url

        # Set headers to mimic Google Chrome on Windows 11
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.5735.199 Safari/537.36'
        }

        # Make the request with the updated headers
        response = requests.get(url, headers=headers, timeout=10)
        logging.debug(f"HTTP status code for {url}: {response.status_code}")
        logging.debug(f"Response content for {url}: {response.text[:200]}")  # Log the first 200 characters of the response
        response.raise_for_status()  # Raise an error for HTTP status codes 4xx/5xx

        # If the response is successful, return "Online"
        return "Online"
    except requests.HTTPError as http_err:
        logging.error(f"HTTP error occurred for {url}: {http_err}")
        return "Offline"
    except requests.ConnectionError:
        logging.error(f"Connection error occurred for {url}")
        return "Offline"
    except requests.Timeout:
        logging.error(f"Timeout occurred for {url}")
        return "Offline"
    except Exception as e:
        logging.error(f"An unexpected error occurred for {url}: {e}")
        return "Offline"
    
# Fungsi untuk mengirim status website ke grup chat tertentu
def send_website_status(user_id):
    logging.debug(f"send_website_status triggered for user_id: {user_id}")
    
    # Hardcoded group chat ID
    chat_id = -4766264035
    
    logging.debug(f"Chat ID for user {user_id}: {chat_id}")
    
    connection = connect_db()
    cursor = connection.cursor()
    
    # Fetch websites and the username of the owner
    cursor.execute("""
        SELECT u.username, w.webname, w.url 
        FROM websites w
        JOIN users u ON w.user_id = u.id
        WHERE w.user_id = ?
    """, (user_id,))
    websites = cursor.fetchall()
    cursor.close()
    connection.close()
    
    if not websites:
        logging.warning(f"No websites found for user {user_id}.")
        return
    
    message = "🌐 Website Status Update 🌐\n"
    for username, webname, url in websites:
        status = check_website_status(url)
        logging.debug(f"Website: {webname}, URL: {url}, Status: {status}, Owner: {username}")
        if "Blocked" in status:
            message += f"🚫 {webname} ({url})\nOwner: {username}\nStatus: {status}\n\n"
        elif "Offline" in status:
            message += f"❌ {webname} ({url})\nOwner: {username}\nStatus: {status}\n\n"
        else:
            message += f"✅ {webname} ({url})\nOwner: {username}\nStatus: {status}\n\n"
    
    try:
        logging.debug(f"Sending message to chat ID {chat_id}: {message}")
        bot.send_message(chat_id, message, disable_web_page_preview=True)
        logging.debug(f"Message sent successfully to chat ID {chat_id}")
    except Exception as e:
        logging.error(f"Failed to send message to chat ID {chat_id}: {e}")

# Fungsi untuk menjadwalkan pengiriman status website untuk setiap pengguna
def schedule_website_status_updates():
    connection = connect_db()
    cursor = connection.cursor()
    cursor.execute("SELECT id FROM users")
    users = cursor.fetchall()
    cursor.close()
    connection.close()
    
    for user in users:
        user_id = user[0]
        job_id = f"website_status_update_{user_id}"  # Unique job ID for each user
        
        # Check if the job already exists
        if scheduler.get_job(job_id):
            logging.debug(f"Job {job_id} already exists. Skipping...")
            continue
        
        # Schedule a job for each user with a 1-minute interval
        scheduler.add_job(
            send_website_status,
            "interval",
            minutes=1,  # Set interval to 1 minute
            args=[user_id],
            id=job_id  # Unique job ID for each user
        )
        logging.debug(f"Scheduled job {job_id} for user {user_id} with a 1-minute interval.")

# Fungsi untuk memperbarui status website
def refresh_website_statuses(user_id):
    connection = connect_db()
    cursor = connection.cursor()
    cursor.execute("SELECT id, url FROM websites WHERE user_id = ?", (user_id,))
    websites = cursor.fetchall()

    for website_id, url in websites:
        status = check_website_status(url)
        last_checked = datetime.now().strftime('%Y-%m-%d %H:%M:%S')  # Current timestamp
        cursor.execute("UPDATE websites SET status = ?, last_checked = ? WHERE id = ?", (status, last_checked, website_id))
    
    connection.commit()
    cursor.close()
    connection.close()
    logging.debug(f"Refreshed website statuses for user {user_id}")
    
# Endpoint Webhook untuk menerima update dari Telegram
@app.route('/webhook', methods=['POST'])
def webhook():
    update = request.get_json()
    logging.debug(f"Received update: {update}")
    if update:
        bot.process_new_updates([telebot.types.Update.de_json(update)])
    return "OK", 200

# Perintah "/check" untuk mengecek status semua website
@bot.message_handler(commands=['check'])
def handle_check(message):
    if current_user.is_authenticated:
        send_website_status(current_user.id)
        bot.reply_to(message, "✅ Website status checked!")
        logging.debug(f"Checked website status for user {current_user.username}")
    else:
        bot.reply_to(message, "You need to log in to the website first.")
        logging.error("User is not authenticated. Cannot check website status.")

# Halaman utama (Daftar Website)
@app.route('/')
def landing():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    return redirect(url_for('login'))

def get_websites(user_id):
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute("SELECT id, webname, url, status, last_checked FROM websites WHERE user_id = ?", (user_id,))
    websites = cursor.fetchall()
    conn.close()
    return websites

# Daftar Website
@app.route('/index')
@login_required
def index():
    connection = connect_db()
    cursor = connection.cursor()
    
    # Fetch modules for the current user
    cursor.execute("SELECT id, name FROM modules WHERE user_id = ?", (current_user.id,))
    modules = [{"id": row[0], "name": row[1]} for row in cursor.fetchall()]  # Convert to dictionaries
    
    cursor.close()
    connection.close()
    
    # Fetch websites for the current user
    websites = get_websites(current_user.id)
    
    return render_template("index.html", modules=modules, websites=websites)

@app.route('/module/<int:module_id>')
@login_required
def module_websites(module_id):
    connection = connect_db()
    cursor = connection.cursor()
    
    # Fetch module name
    cursor.execute("SELECT name FROM modules WHERE id = ? AND user_id = ?", (module_id, current_user.id))
    module = cursor.fetchone()
    if not module:
        flash("Module not found or you don't have access to it.", "danger")
        return redirect(url_for('index'))
    
    module_name = module[0]
    
    # Fetch websites in the module
    cursor.execute("SELECT id, webname, url, status FROM websites WHERE module_id = ? AND user_id = ?", (module_id, current_user.id))
    websites = [{"id": row[0], "webname": row[1], "url": row[2], "status": row[3]} for row in cursor.fetchall()]
    
    cursor.close()
    connection.close()
    
    return render_template("module_websites.html", module_name=module_name, websites=websites, module_id=module_id)

# Tambah Modul
@app.route('/add_module', methods=['GET', 'POST'])
@login_required
def add_module():
    if request.method == 'POST':
        module_name = request.form['name']
        connection = connect_db()
        cursor = connection.cursor()
        cursor.execute("INSERT INTO modules (name, user_id) VALUES (?, ?)", (module_name, current_user.id))
        connection.commit()
        cursor.close()
        connection.close()
        return redirect(url_for('index'))
    
    return render_template("add_module.html")

# Tambah Website
@app.route('/add_website', methods=['GET', 'POST'])
@login_required
def add_website():
    module_id = request.args.get('module_id', None)
    connection = connect_db()
    cursor = connection.cursor()
    
    if request.method == 'POST':
        webname = request.form['webname']
        url = request.form['url']
        module_id = request.form['module_id']
        status = check_website_status(url)
        
        cursor.execute(
            "INSERT INTO websites (webname, url, status, user_id, module_id) VALUES (?, ?, ?, ?, ?)",
            (webname, url, status, current_user.id, module_id)
        )
        connection.commit()
        cursor.close()
        connection.close()
        return redirect(url_for('module_websites', module_id=module_id))
    
    # Fetch modules for the current user
    cursor.execute("SELECT id, name FROM modules WHERE user_id = ?", (current_user.id,))
    modules = cursor.fetchall()
    cursor.close()
    connection.close()
    
    return render_template("add_website.html", modules=modules, selected_module=module_id)

# Edit Website
@app.route('/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_website(id):
    connection = connect_db()
    cursor = connection.cursor()
    
    if request.method == 'POST':
        webname = request.form['webname']
        url = request.form['url']
        
        # Update only webname and url
        cursor.execute("UPDATE websites SET webname = ?, url = ? WHERE id = ? AND user_id = ?", 
                    (webname, url, id, current_user.id))
        connection.commit()
        cursor.close()
        connection.close()
        return redirect(url_for('index'))
    
    # Fetch the website details
    cursor.execute("SELECT id, webname, url FROM websites WHERE id = ? AND user_id = ?", (id, current_user.id))
    website = cursor.fetchone()
    if not website:
        flash("Website not found or you don't have access to it.", "danger")
        return redirect(url_for('index'))
    
    cursor.close()
    connection.close()
    
    # Pass data to the template
    return render_template('edit_website.html', website={
        "id": website[0],
        "webname": website[1],
        "url": website[2]
    })

# Fungsi untuk menghapus website
@app.route('/delete_website/<int:id>', methods=['POST'])
@login_required
def delete_website(id):
    connection = connect_db()
    cursor = connection.cursor()
    cursor.execute("DELETE FROM websites WHERE id = ? AND user_id = ?", (id, current_user.id))
    connection.commit()
    cursor.close()
    connection.close()
    flash("Website has been successfully removed.", "success")
    return redirect(url_for('index'))

# Remove Module
@app.route('/remove_module/<int:module_id>', methods=['POST'])
@login_required
def remove_module(module_id):
    connection = connect_db()
    cursor = connection.cursor()
    
    # Check if the module exists and belongs to the current user
    cursor.execute("SELECT id FROM modules WHERE id = ? AND user_id = ?", (module_id, current_user.id))
    module = cursor.fetchone()
    if not module:
        flash("Module not found or you don't have access to it.", "danger")
        return redirect(url_for('index'))
    
    # Delete all websites associated with the module
    cursor.execute("DELETE FROM websites WHERE module_id = ?", (module_id,))
    
    # Delete the module itself
    cursor.execute("DELETE FROM modules WHERE id = ?", (module_id,))
    
    connection.commit()
    cursor.close()
    connection.close()
    
    flash("Module and its associated websites have been successfully removed.", "success")
    return redirect(url_for('index'))

# Login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        connection = connect_db()
        cursor = connection.cursor()
        cursor.execute("SELECT id, username, password, role, chat_id FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        cursor.close()
        connection.close()
        if user and check_password_hash(user[2], password):
            login_user(User(user[0], user[1], user[3], user[4]))
            return redirect(url_for('index'))  # Redirect to index after login
        else:
            flash('Invalid username or password')
    return render_template('login.html')

def hash_password(password):
    return generate_password_hash(password, method='pbkdf2:sha256')

# Profile
@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    connection = connect_db()
    cursor = connection.cursor()

    if request.method == 'POST':
        name = request.form['name']
        username = request.form['username']
        password = request.form.get('password', None)
        profile_picture = request.files.get('profile_picture', None)

        # Update profile picture if provided
        if profile_picture:
            picture_path = f"static/uploads/{current_user.id}_{profile_picture.filename}"
            profile_picture.save(picture_path)
        else:
            picture_path = None

        # Update password if provided
        if password:
            hashed_password = hash_password(password)
            cursor.execute(
                "UPDATE users SET name = ?, username = ?, password = ?, profile_picture = ? WHERE id = ?",
                (name, username, hashed_password, picture_path, current_user.id)
            )
        else:
            cursor.execute(
                "UPDATE users SET name = ?, username = ?, profile_picture = ? WHERE id = ?",
                (name, username, picture_path, current_user.id)
            )

        connection.commit()
        flash("Profile updated successfully!", "success")
        return redirect(url_for('profile'))

    # Fetch current user details
    cursor.execute("SELECT name, username, profile_picture FROM users WHERE id = ?", (current_user.id,))
    user = cursor.fetchone()
    cursor.close()
    connection.close()

    return render_template('profile.html', user={
        "name": user[0],
        "username": user[1],
        "profile_picture": user[2]
    })

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        profile_picture = request.files.get('profile_picture')

        # Handle profile picture upload
        profile_picture_path = None
        if profile_picture and allowed_file(profile_picture.filename):
            filename = secure_filename(f"{username}_{profile_picture.filename}")
            profile_picture_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            profile_picture.save(profile_picture_path)
            profile_picture_path = f"uploads/{filename}"  # Save relative path to the database
            print(f"Profile picture saved at: {profile_picture_path}")  # Debug statement

        # Save user to the database
        connection = connect_db()
        cursor = connection.cursor()
        cursor.execute(
            "INSERT INTO users (username, name, email, password, profile_picture) VALUES (?, ?, ?, ?, ?)",
            (username, name, email, hash_password(password), profile_picture_path)
        )
        connection.commit()
        cursor.close()
        connection.close()

        flash("Registration successful! Please log in.", "success")
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/manage_users', methods=['GET', 'POST'])
@login_required
def manage_users():
    # Ensure only owners can access this page
    if current_user.role != 'owner':
        flash("You do not have permission to access this page.", "danger")
        return redirect(url_for('index'))

    connection = connect_db()
    cursor = connection.cursor()

    if request.method == 'POST': 
        # Handle role update
        user_id = request.form.get('user_id')
        new_role = request.form.get('role')
        if user_id and new_role:
            cursor.execute("UPDATE users SET role = ? WHERE id = ?", (new_role, user_id))
            connection.commit()
            flash("User role updated successfully.", "success")

        # Handle user deletion
        delete_user_id = request.form.get('delete_user_id')
        if delete_user_id:
            cursor.execute("DELETE FROM users WHERE id = ?", (delete_user_id,))
            connection.commit()
            flash("User deleted successfully.", "success")

    # Fetch all users
    cursor.execute("SELECT id, username, name, email, role FROM users")
    users = cursor.fetchall()
    cursor.close()
    connection.close()

    return render_template('manage_users.html', users=users)

# Logout
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# Set webhook Telegram
def set_webhook():
    url = f"https://api.telegram.org/bot{TOKEN}/getWebhookInfo"
    try:
        response = requests.get(url, timeout=10).json()  # Add a 10-second timeout
        if response.get("result", {}).get("url") != f"{WEBHOOK_URL}/webhook":
            url = f"https://api.telegram.org/bot{TOKEN}/setWebhook?url={WEBHOOK_URL}/webhook"
            response = requests.get(url, timeout=10)  # Add a 10-second timeout
            print(response.json())
        else:
            print("Webhook sudah diatur, tidak perlu mengatur ulang.")
    except requests.exceptions.RequestException as e:
        logging.error(f"Failed to set webhook: {e}")

# Delete webhook Telegram
def delete_webhook():
    url = f"https://api.telegram.org/bot{TOKEN}/deleteWebhook"
    response = requests.get(url)
    print(response.json())

if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    set_webhook()
    atexit.register(delete_webhook)
    
    # Clear all existing jobs
    scheduler.remove_all_jobs()
    logging.debug("Cleared all existing jobs in the scheduler.")
    
    # Schedule the send_website_status job for each user
    schedule_website_status_updates()
    
    # Log all scheduled jobs
    for job in scheduler.get_jobs():
        logging.debug(f"Scheduled job: {job.id}")
    
    # Start the scheduler
    scheduler.start()
    app.run(port=5000, debug=True)