import sqlite3
from werkzeug.security import generate_password_hash

DATABASE = 'website_monitor.db'

def connect_db():
    return sqlite3.connect(DATABASE)

def add_dummy_user():
    connection = connect_db()
    cursor = connection.cursor()
    
    username = 'jackh'
    name = 'Jack H'
    email = 'jackh@example.com'
    password = generate_password_hash('jackh123')
    role = 'user'  # Default role

    cursor.execute("INSERT INTO users (username, name, email, password, role) VALUES (?, ?, ?, ?, ?)", 
                (username, name, email, password, role))
    connection.commit()
    cursor.close()
    connection.close()

if __name__ == '__main__':
    add_dummy_user()
    print("Dummy user added successfully.")