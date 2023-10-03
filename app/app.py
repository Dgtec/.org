import os
import sqlite3
from flask import Flask, render_template, request, url_for, flash, redirect
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.exceptions import abort

def get_db_connection():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    with app.open_resource('schema.sql', mode='r') as f:
        conn.cursor().executescript(f.read())
    conn.commit()
    conn.close()

def get_post(post_id):
    conn = get_db_connection()
    post = conn.execute('SELECT * FROM posts WHERE id = ?', (post_id,)).fetchone()
    conn.close()
    if post is None:
        abort(404)
    return post

app = Flask(__name__)
app.config['SECRET_KEY'] = 's=uW!3D6'
app.config['UPLOAD_FOLDER'] = 'static'

@app.route('/')
def index():
    conn = get_db_connection()
    posts = conn.execute('SELECT * FROM posts').fetchall()
    conn.close()
    return render_template('index.html', posts=posts)

@app.route('/<int:post_id>')
def post(post_id):
    post = get_post(post_id)
    return render_template('post.html', post=post)

@app.route('/create', methods=['GET', 'POST'])
def create():
    if request.method == 'POST':
        title = request.form['title']
        author = request.form['author']
        content = request.form['content']

        if not title:
            flash('Title is required!')
        else:
            conn = get_db_connection()
            conn.execute('INSERT INTO posts (title, author, content) VALUES (?, ?, ?)',
                         (title, author, content))
            conn.commit()
            conn.close()
            return redirect(url_for('index'))

    return render_template('create.html')

@app.route('/<int:id>/edit', methods=['GET', 'POST'])
def edit(id):
    post = get_post(id)

    if request.method == 'POST':
        title = request.form['title']
        author = request.form['author']
        content = request.form['content']

        if not title:
            flash('Title is required!')
        else:
            conn = get_db_connection()
            conn.execute('UPDATE posts SET title = ?, author = ?, content = ? WHERE id = ?',
                         (title, author, content, id))
            conn.commit()
            conn.close()
            return redirect(url_for('index'))

    return render_template('edit.html', post=post)

@app.route('/<int:id>/delete', methods=['POST'])
def delete(id):
    post = get_post(id)
    conn = get_db_connection()
    conn.execute('DELETE FROM posts WHERE id = ?', (id,))
    conn.commit()
    conn.close()
    flash('"{}" was successfully deleted!'.format(post['title']))
    return redirect(url_for('index'))

# Sign up page
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if not username or not password:
            flash('Username and password are required!')
        else:
            conn = get_db_connection()
            hashed_password = generate_password_hash(password)
            conn.execute('INSERT INTO users (username, password) VALUES (?, ?)',
                         (username, hashed_password))
            conn.commit()
            conn.close()
            flash('You have successfully signed up!')
            return redirect(url_for('login'))

    return render_template('signup.html')

# Login page
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if not username or not password:
            flash('Username and password are required!')
        else:
            conn = get_db_connection()
            user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
            conn.close()

            if user and check_password_hash(user['password'], password):
                # Store the user ID in session
                session['user_id'] = user['id']
                flash('You have successfully logged in!')
                return redirect(url_for('profile'))
            else:
                flash('Invalid username or password!')

    return render_template('login.html')

# Profile page
@app.route('/profile', methods=['GET', 'POST'])
def profile():
    # Check if the user is logged in
    if 'user_id' not in session:
        flash('You need to log in to access this page!')
        return redirect(url_for('login'))

    # Get the user's information from the database
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    conn.close()

    if request.method == 'POST':
        # Update the user's profile picture if provided
        if 'profile_picture' in request.files:
            file = request.files['profile_picture']
            if file.filename != '':
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], file.filename))
                # Update the user's profile picture in the database
                conn = get_db_connection()
                conn.execute('UPDATE users SET profile_picture = ? WHERE id = ?',
                             (file.filename, session['user_id']))
                conn.commit()
                conn.close()

    return render_template('profile.html', user=user)

# Logout
@app.route('/logout')
def logout():
    # Remove the user ID from session
    session.pop('user_id', None)
    flash('You have been logged out!')
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run()
