from flask import Flask, render_template, request, redirect, url_for, session, flash, g
import sqlite3
import bcrypt
import os
import logging

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.urandom(24)

# Setup logging
logging.basicConfig(level=logging.DEBUG)

DATABASE = 'instance/database.db'

def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(exception):
    db = g.pop('db', None)
    if db is not None:
        db.close()

# Database Schema Creation
def create_db():
    os.makedirs(os.path.dirname(DATABASE), exist_ok=True)
    if os.path.exists(DATABASE):
        os.remove(DATABASE)

    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS User (
            User_ID INTEGER PRIMARY KEY AUTOINCREMENT,
            Email TEXT NOT NULL UNIQUE,
            Password TEXT NOT NULL,
            User_Type TEXT NOT NULL CHECK(User_Type IN ('scholar', 'supervisor')),
            First_Name TEXT NOT NULL,
            Last_Name TEXT NOT NULL,
            Department TEXT,
            About TEXT,
            Phone TEXT,
            Created_At TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS Scholar (
            Scholar_ID INTEGER PRIMARY KEY AUTOINCREMENT,
            User_ID INTEGER,
            College TEXT,
            FOREIGN KEY (User_ID) REFERENCES User(User_ID) ON DELETE CASCADE
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS Supervisor (
            Supervisor_ID INTEGER PRIMARY KEY AUTOINCREMENT,
            User_ID INTEGER,
            Role TEXT,
            FOREIGN KEY (User_ID) REFERENCES User(User_ID) ON DELETE CASCADE
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS Paper (
            Paper_ID INTEGER PRIMARY KEY AUTOINCREMENT,
            Title TEXT NOT NULL,
            Type TEXT NOT NULL CHECK(Type IN ('journal', 'conference')),
            Status TEXT DEFAULT 'Pending' CHECK(Status IN ('Pending', 'Approved', 'Rejected')),
            Progress INTEGER NOT NULL,
            Scholar_ID INTEGER,
            Remarks TEXT,
            Created_At TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (Scholar_ID) REFERENCES Scholar(Scholar_ID) ON DELETE CASCADE,
            UNIQUE(Title, Scholar_ID)
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS Supervisor_Scholar (
            ID INTEGER PRIMARY KEY AUTOINCREMENT,
            Supervisor_ID INTEGER,
            Scholar_ID INTEGER,
            FOREIGN KEY (Supervisor_ID) REFERENCES Supervisor(Supervisor_ID) ON DELETE CASCADE,
            FOREIGN KEY (Scholar_ID) REFERENCES Scholar(Scholar_ID) ON DELETE CASCADE,
            UNIQUE(Supervisor_ID, Scholar_ID)
        )
    """)

    conn.commit()
    conn.close()

@app.route('/')
@app.route('/home')
def home():
    return render_template('home.html')

@app.route('/logout')
def logout():
    session.pop('email', None)
    session.pop('user_type', None)
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))

@app.route('/profile')
def profile():
    if 'email' not in session:
        flash('Please log in to access this page.', 'danger')
        return redirect(url_for('login'))

    email = session['email']
    user_type = session['user_type']
    conn = get_db()
    cursor = conn.cursor()

    if user_type == 'scholar':
        cursor.execute("SELECT * FROM User JOIN Scholar ON User.User_ID = Scholar.User_ID WHERE User.Email=?", (email,))
        scholar = cursor.fetchone()

        cursor.execute("""
            SELECT Supervisor.First_Name || ' ' || Supervisor.Last_Name as Name FROM User as Supervisor
            JOIN Supervisor_Scholar ON Supervisor.User_ID = Supervisor_Scholar.Supervisor_ID
            JOIN Scholar ON Scholar.Scholar_ID = Supervisor_Scholar.Scholar_ID
            WHERE Scholar.User_ID = ?
        """, (scholar['User_ID'],))
        supervisor = cursor.fetchone()

        cursor.execute("SELECT * FROM Paper WHERE Scholar_ID=?", (scholar['Scholar_ID'],))
        papers = cursor.fetchall()
        conn.close()
        return render_template('profile.html', user_type='scholar', scholar=scholar, supervisor=supervisor, papers=papers)

    elif user_type == 'supervisor':
        cursor.execute("SELECT * FROM User JOIN Supervisor ON User.User_ID = Supervisor.User_ID WHERE User.Email=?", (email,))
        supervisor = cursor.fetchone()

        cursor.execute("SELECT First_Name || ' ' || Last_Name as Name, Scholar_ID FROM User JOIN Scholar ON User.User_ID = Scholar.User_ID")
        scholars = cursor.fetchall()

        cursor.execute("""
            SELECT User.First_Name || ' ' || User.Last_Name as Name, User.Email FROM User
            JOIN Scholar ON User.User_ID = Scholar.User_ID
            JOIN Supervisor_Scholar ON Scholar.Scholar_ID = Supervisor_Scholar.Scholar_ID
            WHERE Supervisor_Scholar.Supervisor_ID = ?
        """, (supervisor['User_ID'],))
        supervised_scholars = cursor.fetchall()
        conn.close()
        return render_template('profile.html', user_type='supervisor', supervisor=supervisor, scholars=scholars, supervised_scholars=supervised_scholars)

    return redirect(url_for('home'))

@app.route('/dashboard')
def dashboard():
    if 'user_type' not in session:
        flash('Please log in to access this page.', 'danger')
        return redirect(url_for('login'))

    if session['user_type'] == 'scholar':
        return redirect(url_for('scholar_dashboard'))
    elif session['user_type'] == 'supervisor':
        return redirect(url_for('supervisor_dashboard'))
    else:
        return redirect(url_for('home'))

@app.route('/dashboard/scholar', methods=['GET', 'POST'])
def scholar_dashboard():
    if 'email' not in session:
        flash('Please log in to access this page.', 'danger')
        return redirect(url_for('login'))

    email = session['email']
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("SELECT Scholar_ID FROM User JOIN Scholar ON User.User_ID = Scholar.User_ID WHERE User.Email=?", (email,))
    scholar_id = cursor.fetchone()['Scholar_ID']

    query = "SELECT * FROM Paper WHERE Scholar_ID=?"
    params = [scholar_id]

    if request.method == 'GET':
        search = request.args.get('search')
        status = request.args.get('status')
        if search:
            query += " AND Title LIKE ?"
            params.append(f"%{search}%")
        if status:
            query += " AND Status=?"
            params.append(status)

    cursor.execute(query, params)
    papers = cursor.fetchall()

    paper_titles = [paper['Title'] for paper in papers]
    paper_progress = [paper['Progress'] for paper in papers]

    selected_paper = None
    if request.method == 'POST':
        paper_id = request.form['paper_id']
        cursor.execute("SELECT * FROM Paper WHERE Paper_ID=? AND Scholar_ID=?", (paper_id, scholar_id))
        selected_paper = cursor.fetchone()

    conn.close()

    return render_template('scholar_dashboard.html', papers=papers, selected_paper=selected_paper, paper_titles=paper_titles, paper_progress=paper_progress)

@app.route('/dashboard/supervisor', methods=['GET', 'POST'])
def supervisor_dashboard():
    if 'email' not in session:
        flash('Please log in to access this page.', 'danger')
        return redirect(url_for('login'))

    email = session['email']
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("SELECT Supervisor_ID FROM User JOIN Supervisor ON User.User_ID = Supervisor.User_ID WHERE User.Email=?", (email,))
    supervisor_id = cursor.fetchone()['Supervisor_ID']

    query = """
        SELECT Paper.Paper_ID, Paper.Title, Paper.Type, Paper.Status, Paper.Progress, Paper.Remarks,
               User.First_Name || ' ' || User.Last_Name as Scholar_Name
        FROM Paper
        JOIN Scholar ON Paper.Scholar_ID = Scholar.Scholar_ID
        JOIN Supervisor_Scholar ON Scholar.Scholar_ID = Supervisor_Scholar.Scholar_ID
        JOIN User ON Scholar.User_ID = User.User_ID
        WHERE Supervisor_Scholar.Supervisor_ID = ?
    """
    params = [supervisor_id]

    if request.method == 'GET':
        search = request.args.get('search')
        status = request.args.get('status')
        if search:
            query += " AND Paper.Title LIKE ?"
            params.append(f"%{search}%")
        if status:
            query += " AND Paper.Status=?"
            params.append(status)

    cursor.execute(query, params)
    papers = cursor.fetchall()
    conn.close()

    return render_template('supervisor_dashboard.html', papers=papers)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password'].encode('utf-8')

        conn = get_db()
        cursor = conn.cursor()

        # Check if the user is a scholar
        cursor.execute("SELECT * FROM User JOIN Scholar ON User.User_ID = Scholar.User_ID WHERE User.Email=?", (email,))
        scholar = cursor.fetchone()

        if scholar and bcrypt.checkpw(password, scholar['Password']):
            session['email'] = email
            session['user_type'] = 'scholar'
            conn.close()
            flash('Login successful!', 'success')
            return redirect(url_for('home'))

        # Check if the user is a supervisor
        cursor.execute("SELECT * FROM User JOIN Supervisor ON User.User_ID = Supervisor.User_ID WHERE User.Email=?", (email,))
        supervisor = cursor.fetchone()

        if supervisor and bcrypt.checkpw(password, supervisor['Password']):
            session['email'] = email
            session['user_type'] = 'supervisor'
            conn.close()
            flash('Login successful!', 'success')
            return redirect(url_for('home'))

        # If login fails
        flash('Invalid email or password', 'danger')
        conn.close()
        return redirect(url_for('login'))

    return render_template('login.html')

@app.route('/signup_scholar', methods=['GET', 'POST'])
def signup_scholar():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password'].encode('utf-8')
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        department = request.form['department']
        about = request.form['about']
        phone = request.form['phone']
        college = request.form['college']

        hashed_password = bcrypt.hashpw(password, bcrypt.gensalt())

        conn = get_db()
        cursor = conn.cursor()

        try:
            cursor.execute("""
                INSERT INTO User (Email, Password, User_Type, First_Name, Last_Name, Department, About, Phone)
                VALUES (?, ?, 'scholar', ?, ?, ?, ?, ?)
            """, (email, hashed_password, first_name, last_name, department, about, phone))
            user_id = cursor.lastrowid

            cursor.execute("""
                INSERT INTO Scholar (User_ID, College)
                VALUES (?, ?)
            """, (user_id, college))

            conn.commit()
            flash('Registration successful!', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Email already exists', 'danger')
        finally:
            conn.close()

    return render_template('signup_scholar.html')

@app.route('/signup_supervisor', methods=['GET', 'POST'])
def signup_supervisor():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password'].encode('utf-8')
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        department = request.form['department']
        about = request.form['about']
        phone = request.form['phone']
        role = request.form['role']

        print("Form Data:", email, first_name, last_name, department, about, phone, role)

        hashed_password = bcrypt.hashpw(password, bcrypt.gensalt())

        conn = get_db()
        cursor = conn.cursor()

        try:
            cursor.execute("""
                INSERT INTO User (Email, Password, User_Type, First_Name, Last_Name, Department, About, Phone)
                VALUES (?, ?, 'supervisor', ?, ?, ?, ?, ?)
            """, (email, hashed_password, first_name, last_name, department, about, phone))
            user_id = cursor.lastrowid

            cursor.execute("""
                INSERT INTO Supervisor (User_ID, Role)
                VALUES (?, ?)
            """, (user_id, role))

            conn.commit()
            flash('Registration successful!', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError as e:
            print("IntegrityError:", e)
            flash('Email already exists', 'danger')
        finally:
            conn.close()

    return render_template('signup_supervisor.html')

@app.route('/add_paper', methods=['POST'])
def add_paper():
    if 'email' not in session:
        flash('Please log in to access this page.', 'danger')
        return redirect(url_for('login'))

    email = session['email']
    title = request.form['title']
    paper_type = request.form['type']
    progress = request.form['progress']

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("SELECT Scholar_ID FROM User JOIN Scholar ON User.User_ID = Scholar.User_ID WHERE User.Email=?", (email,))
    scholar = cursor.fetchone()
    if scholar:
        scholar_id = scholar['Scholar_ID']
        print(f"Scholar ID: {scholar_id}")
    else:
        flash('Scholar not found.', 'danger')
        return redirect(url_for('scholar_dashboard'))

    # Check if a paper with the same title already exists for the scholar
    cursor.execute("SELECT * FROM Paper WHERE Title=? AND Scholar_ID=?", (title, scholar_id))
    existing_paper = cursor.fetchone()

    if existing_paper:
        flash('Paper with the same title already exists for this scholar.', 'danger')
        print("Duplicate paper found.")
    else:
        try:
            cursor.execute("""
                INSERT INTO Paper (Title, Type, Progress, Scholar_ID)
                VALUES (?, ?, ?, ?)
            """, (title, paper_type, progress, scholar_id))
            conn.commit()
            flash('Paper added successfully!', 'success')
            print("Paper added successfully.")
        except sqlite3.IntegrityError as e:
            print("IntegrityError:", e)
            flash('An error occurred while adding the paper.', 'danger')
        finally:
            conn.close()

    return redirect(url_for('scholar_dashboard'))

@app.route('/update_paper_progress', methods=['POST'])
def update_paper_progress():
    if 'email' not in session:
        flash('Please log in to access this page.', 'danger')
        return redirect(url_for('login'))

    paper_id = request.form['paper_id']
    progress = request.form['progress']

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("""
        UPDATE Paper SET Progress=? WHERE Paper_ID=?
    """, (progress, paper_id))

    conn.commit()
    conn.close()

    flash('Paper progress updated successfully!', 'success')
    return redirect(url_for('scholar_dashboard'))

@app.route('/update_profile_scholar', methods=['POST'])
def update_profile_scholar():
    if 'email' not in session:
        flash('Please log in to access this page.', 'danger')
        return redirect(url_for('login'))

    email = session['email']
    first_name = request.form['first_name']
    last_name = request.form['last_name']
    department = request.form['department']
    about = request.form['about']
    phone = request.form['phone']
    college = request.form['college']
    password = request.form['password']

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("SELECT User_ID FROM User WHERE Email=?", (email,))
    user_id = cursor.fetchone()['User_ID']

    if password:
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        cursor.execute("""
            UPDATE User SET Password=?, First_Name=?, Last_Name=?, Department=?, About=?, Phone=? WHERE User_ID=?
        """, (hashed_password, first_name, last_name, department, about, phone, user_id))
    else:
        cursor.execute("""
            UPDATE User SET First_Name=?, Last_Name=?, Department=?, About=?, Phone=? WHERE User_ID=?
        """, (first_name, last_name, department, about, phone, user_id))

    cursor.execute("""
        UPDATE Scholar SET College=? WHERE User_ID=?
    """, (college, user_id))

    conn.commit()
    conn.close()

    flash('Profile updated successfully!', 'success')
    return redirect(url_for('profile'))

@app.route('/update_profile_supervisor', methods=['POST'])
def update_profile_supervisor():
    if 'email' not in session:
        flash('Please log in to access this page.', 'danger')
        return redirect(url_for('login'))

    email = session['email']
    first_name = request.form['first_name']
    last_name = request.form['last_name']
    department = request.form['department']
    about = request.form['about']
    phone = request.form['phone']
    role = request.form['role']
    password = request.form['password']

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("SELECT User_ID FROM User WHERE Email=?", (email,))
    user_id = cursor.fetchone()['User_ID']

    if password:
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        cursor.execute("""
            UPDATE User SET Password=?, First_Name=?, Last_Name=?, Department=?, About=?, Phone=? WHERE User_ID=?
        """, (hashed_password, first_name, last_name, department, about, phone, user_id))
    else:
        cursor.execute("""
            UPDATE User SET First_Name=?, Last_Name=?, Department=?, About=?, Phone=? WHERE User_ID=?
        """, (first_name, last_name, department, about, phone, user_id))

    cursor.execute("""
        UPDATE Supervisor SET Role=? WHERE User_ID=?
    """, (role, user_id))

    conn.commit()
    conn.close()

    flash('Profile updated successfully!', 'success')
    return redirect(url_for('profile'))


@app.route('/update_paper_status', methods=['POST'])
def update_paper_status():
    if 'email' not in session:
        flash('Please log in to access this page.', 'danger')
        return redirect(url_for('login'))

    paper_id = request.form['paper_id']
    status = request.form['status']
    remarks = request.form['remarks']

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("""
        UPDATE Paper SET Status=?, Remarks=? WHERE Paper_ID=?
    """, (status, remarks, paper_id))

    conn.commit()
    conn.close()

    flash('Paper status updated successfully!', 'success')
    return redirect(url_for('supervisor_dashboard'))

@app.route('/assign_supervisor', methods=['POST'])
def assign_supervisor():
    if 'email' not in session:
        flash('Please log in to access this page.', 'danger')
        return redirect(url_for('login'))

    supervisor_id = request.form['supervisor_id']
    scholar_id = request.form['scholar_id']

    conn = get_db()
    cursor = conn.cursor()

    try:
        cursor.execute("""
            INSERT INTO Supervisor_Scholar (Supervisor_ID, Scholar_ID)
            VALUES (?, ?)
        """, (supervisor_id, scholar_id))
        conn.commit()
        flash('Scholar assigned to supervisor successfully!', 'success')
    except sqlite3.IntegrityError:
        flash('Scholar is already assigned to this supervisor.', 'danger')
    finally:
        conn.close()

    return redirect(url_for('profile'))

if __name__ == '__main__':
    create_db()
    app.run(debug=True)
