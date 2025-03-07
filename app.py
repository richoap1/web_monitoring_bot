import telebot
import sqlite3
import requests
import logging
import atexit
from flask import Flask, render_template, request, redirect, url_for, json, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from apscheduler.schedulers.background import BackgroundScheduler
from werkzeug.security import generate_password_hash, check_password_hash

# Konfigurasi bot Telegram
TOKEN = "7937058330:AAHHvr7_0m48l0Opml-yd9qejmi59BHr0Us"  # Ganti dengan Token API dari BotFather
WEBHOOK_URL = "https://2a5b-110-138-202-206.ngrok-free.app"
CHAT_ID = None  # Initialize CHAT_ID as None

bot = telebot.TeleBot(TOKEN)
app = Flask(__name__)
app.secret_key = 'your_secret_key'
login_manager = LoginManager()
login_manager.init_app(app)
scheduler = BackgroundScheduler()

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

# Fungsi untuk menyimpan chat_id pengguna
@bot.message_handler(commands=['start', 'help'])
def handle_start_help(message):
    global CHAT_ID
    logging.debug(f"Received message: {message}")
    CHAT_ID = message.chat.id
    logging.debug(f"Set CHAT_ID to {CHAT_ID}")
    if current_user.is_authenticated:
        bot.reply_to(message, "Chat ID has been saved!")
        logging.debug(f"Chat ID {CHAT_ID} for user {current_user.username} has been saved to the program.")
    else:
        bot.reply_to(message, "You need to log in to the website first.")
        logging.error("User is not authenticated. Cannot save chat ID.")

# Fungsi untuk mengirim pesan otomatis setiap 1 menit
def send_status_update():
    if CHAT_ID:  # Ensure CHAT_ID is not empty
        bot.send_message(CHAT_ID, "🔄 Bot masih aktif dan berjalan!")
        logging.debug(f"Sent status update to chat ID {CHAT_ID}")
    else:
        logging.error("CHAT_ID is empty. Cannot send status update.")

# Fungsi untuk mengecek status website
def check_website_status(url):
    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            return "✅ Online"
        else:
            return f"⚠️ Status Code: {response.status_code}"
    except requests.ConnectionError:
        return "❌ Offline"

# Fungsi untuk mengirim status website
def send_website_status(user_id):
    connection = connect_db()
    cursor = connection.cursor()
    cursor.execute("SELECT webname, url FROM websites WHERE user_id = ?", (user_id,))
    websites = cursor.fetchall()
    
    message = "🌐 **Website Status Update:**\n"
    for webname, url in websites:
        status = check_website_status(url)
        message += f"🔍 {webname} ({url})\nStatus: {status}\n\n"
    
    if CHAT_ID:
        try:
            bot.send_message(CHAT_ID, message)
            logging.debug(f"Sent website status update to chat ID {CHAT_ID}")
        except Exception as e:
            logging.error(f"Failed to send message to chat ID {CHAT_ID}: {e}")
    else:
        logging.error("CHAT_ID is empty. Cannot send website status update.")

    cursor.close()
    connection.close()

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
        scheduler.add_job(send_website_status, "interval", minutes=10, args=[user_id])

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

# Daftar Website
@app.route('/index')
@login_required
def index():
    connection = connect_db()
    cursor = connection.cursor()
    cursor.execute("SELECT * FROM websites WHERE user_id = ?", (current_user.id,))
    websites = cursor.fetchall()
    cursor.close()
    connection.close()
    return render_template("index.html", websites=websites)

# Tambah Website
@app.route('/add', methods=['POST'])
@login_required
def add_website():
    webname = request.form['webname']
    url = request.form['url']
    status = check_website_status(url)

    connection = connect_db()
    cursor = connection.cursor()
    cursor.execute("INSERT INTO websites (webname, url, status, user_id) VALUES (?, ?, ?, ?)", (webname, url, status, current_user.id))
    connection.commit()
    cursor.close()
    connection.close()
    
    return redirect(url_for('index'))

# Edit Website
@app.route('/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_website(id):
    connection = connect_db()
    cursor = connection.cursor()

    if request.method == 'POST':
        webname = request.form['webname']
        url = request.form['url']
        status = check_website_status(url)

        cursor.execute("UPDATE websites SET webname = ?, url = ?, status = ? WHERE id = ? AND user_id = ?", (webname, url, status, id, current_user.id))
        connection.commit()
        cursor.close()
        connection.close()
        return redirect(url_for('index'))
    
    cursor.execute("SELECT * FROM websites WHERE id = ? AND user_id = ?", (id, current_user.id))
    website = cursor.fetchone()
    cursor.close()
    connection.close()
    
    return render_template("edit_website.html", website=website)

# Hapus Website
@app.route('/delete/<int:id>')
@login_required
def delete_website(id):
    connection = connect_db()
    cursor = connection.cursor()
    cursor.execute("DELETE FROM websites WHERE id = ? AND user_id = ?", (id, current_user.id))
    connection.commit()
    cursor.close()
    connection.close()
    
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
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password')
    return render_template('login.html')

# Register
@app.route('/register', methods=['GET', 'POST'])
@login_required
def register():
    if current_user.role not in ['admin', 'owner']:
        return "Unauthorized", 403

    if request.method == 'POST':
        username = request.form['username']
        name = request.form['name']
        email = request.form['email']
        password = generate_password_hash(request.form['password'])
        role = 'user'  # Default role

        connection = connect_db()
        cursor = connection.cursor()
        cursor.execute("INSERT INTO users (username, name, email, password, role) VALUES (?, ?, ?, ?, ?)", (username, name, email, password, role))
        connection.commit()
        cursor.close()
        connection.close()
        return redirect(url_for('login'))
    return render_template('register.html')

# Logout
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# Set webhook Telegram
def set_webhook():
    url = f"https://api.telegram.org/bot{TOKEN}/setWebhook?url={WEBHOOK_URL}/webhook"
    response = requests.get(url)
    print(response.json())

# Delete webhook Telegram
def delete_webhook():
    url = f"https://api.telegram.org/bot{TOKEN}/deleteWebhook"
    response = requests.get(url)
    print(response.json())

if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    set_webhook()
    atexit.register(delete_webhook)
    scheduler.add_job(send_status_update, "interval", minutes=1)  # Kirim status bot setiap 1 menit
    schedule_website_status_updates()  # Schedule website status updates for all users
    scheduler.start()
    app.run(port=5000, debug=True)