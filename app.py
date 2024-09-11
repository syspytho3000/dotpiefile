import sqlite3
from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)

def get_db_connection():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    conn.execute('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT, email TEXT, bio TEXT)')
    conn.execute('CREATE TABLE IF NOT EXISTS links (id INTEGER PRIMARY KEY, url TEXT, user_id INTEGER)')
    conn.execute('CREATE TABLE IF NOT EXISTS facts (id INTEGER PRIMARY KEY, content TEXT, user_id INTEGER)')
    conn.execute('CREATE TABLE IF NOT EXISTS news_updates (id INTEGER PRIMARY KEY, content TEXT, user_id INTEGER)')
    conn.execute('CREATE TABLE IF NOT EXISTS calendar_events (id INTEGER PRIMARY KEY, event TEXT, date TEXT, user_id INTEGER)')
    conn.close()

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        if user:
            flash('Username already exists', 'danger')
        else:
            hashed_password = generate_password_hash(password)
            conn.execute('INSERT INTO users (username, password, email) VALUES (?, ?, ?)', (username, hashed_password, email))
            conn.commit()
            flash('Registration successful. Please log in.', 'success')
            return redirect(url_for('login'))
        conn.close()
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            flash('Logged in successfully', 'success')
            return redirect(url_for('home'))
        else:
            flash('Invalid username or password', 'danger')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('username', None)
    flash('Logged out successfully', 'success')
    return redirect(url_for('login'))

@app.route('/')
def home():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    conn = get_db_connection()
    links = conn.execute('SELECT * FROM links WHERE user_id = ?', (session['user_id'],)).fetchall()
    facts = conn.execute('SELECT * FROM facts WHERE user_id = ?', (session['user_id'],)).fetchall()
    news_updates = conn.execute('SELECT * FROM news_updates WHERE user_id = ?', (session['user_id'],)).fetchall()
    calendar_events = conn.execute('SELECT * FROM calendar_events WHERE user_id = ?', (session['user_id'],)).fetchall()
    conn.close()
    return render_template('home.html', links=links, facts=facts, news_updates=news_updates, calendar_events=calendar_events)

@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    if request.method == 'POST':
        email = request.form['email']
        bio = request.form['bio']
        conn.execute('UPDATE users SET email = ?, bio = ? WHERE id = ?', (email, bio, session['user_id']))
        conn.commit()
        flash('Profile updated successfully', 'success')
        return redirect(url_for('profile'))
    conn.close()
    return render_template('profile.html', user=user)

# ... (keep all other existing routes)

if __name__ == '__main__':
    init_db()
    app.run(debug=True)