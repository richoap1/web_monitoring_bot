import sqlite3

DATABASE = 'website_monitor.db'

connection = sqlite3.connect(DATABASE)
cursor = connection.cursor()

# Create users table
cursor.execute('''
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('user', 'admin', 'owner')) DEFAULT 'user',
    chat_id TEXT
)
''')

# Create websites table
cursor.execute('''
CREATE TABLE websites (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    webname TEXT NOT NULL,
    url TEXT NOT NULL,
    status TEXT NOT NULL,
    user_id INTEGER NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id)
)
''')

connection.commit()
cursor.close()
connection.close()