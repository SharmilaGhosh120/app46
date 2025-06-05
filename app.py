# -*- coding: utf-8 -*-

import streamlit as st
import pandas as pd
from datetime import datetime
import requests
from dotenv import load_dotenv
import os
import re
import bcrypt
import sqlite3
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle
from reportlab.lib import colors
import uuid
import unittest
import sys
import io
import csv

# Load environment variables
load_dotenv()
DB_PATH = os.getenv("DB_PATH", "kyra.db")
SECRET_KEY = os.getenv("SECRET_KEY", "your_secret")

# --- Authentication Utilities ---
def hash_password(password):
    """
    Hash a password using bcrypt.
    
    Args:
        password: Plain text password to hash.
    
    Returns:
        Decoded bcrypt hash string.
    """
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

def verify_user(email, password):
    """
    Verify user credentials against stored hash.
    
    Args:
        email: User email.
        password: Plain text password.
    
    Returns:
        Tuple of (user_info, error_message). user_info is a dict with name and role, or None if verification fails.
    """
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('SELECT password_hash, name, role FROM users WHERE email = ?', (email,))
        result = c.fetchone()
        conn.close()
        if not result:
            return None, "Email not found."
        stored_hash = result[0].encode()
        if bcrypt.checkpw(password.encode(), stored_hash):
            return {"name": result[1], "role": result[2]}, None
        return None, "Incorrect password."
    except Exception as e:
        st.error(f"Database error in verify_user: {str(e)}")
        return None, "Database error. Please try again."

def reset_user_password(email, new_password):
    """
    Reset a user's password.
    
    Args:
        email: User email.
        new_password: New plain text password.
    
    Returns:
        Tuple of (success_boolean, message).
    """
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        password_hash = hash_password(new_password)
        c.execute('UPDATE users SET password_hash = ? WHERE email = ?', (password_hash, email))
        conn.commit()
        conn.close()
        return True, "Password reset successfully."
    except Exception as e:
        return False, str(e)

def is_strong_password(password):
    """
    Check if password meets strength requirements.
    
    Args:
        password: Plain text password to validate.
    
    Returns:
        Tuple of (is_strong, message). is_strong is True if password meets criteria, False otherwise.
    """
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter."
    if not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter."
    if not re.search(r"[0-9]", password):
        return False, "Password must contain at least one digit."
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False, "Password must contain at least one special character."
    return True, "Password is strong."

# --- Database Utilities ---
def connect_db():
    """Connect to the SQLite database."""
    return sqlite3.connect(DB_PATH)

def get_project_for_student(email, conn):
    """
    Retrieve project title for a student.
    
    Args:
        email: Student email.
        conn: SQLite database connection.
    
    Returns:
        Project title or "No Project Assigned" if none.
    """
    cursor = conn.cursor()
    cursor.execute("""
        SELECT project_title FROM student_project_map spm
        JOIN projects p ON spm.project_id = p.project_id
        WHERE spm.student_id = ?
    """, (email,))
    result = cursor.fetchone()
    return result[0] if result else "No Project Assigned"

def get_unique_students(conn):
    """
    Retrieve all unique students.
    
    Args:
        conn: SQLite database connection.
    
    Returns:
        List of tuples containing (email, name) for students.
    """
    cursor = conn.cursor()
    cursor.execute("SELECT DISTINCT email, name FROM users WHERE role = 'student'")
    return cursor.fetchall()

def init_db():
    """
    Initialize the database with required tables and default admin user.
    """
    conn = connect_db()
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            email TEXT PRIMARY KEY,
            name TEXT,
            role TEXT,
            password_hash TEXT
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS projects (
            project_id TEXT PRIMARY KEY,
            email TEXT,
            project_title TEXT,
            timestamp TEXT,
            FOREIGN KEY (email) REFERENCES users(email)
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS queries (
            query_id TEXT PRIMARY KEY,
            email TEXT,
            name TEXT,
            project_title TEXT,
            question TEXT,
            response TEXT,
            timestamp TEXT,
            feedback_rating INTEGER,
            FOREIGN KEY (email) REFERENCES users(email)
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS student_project_map (
            student_id TEXT,
            project_id TEXT,
            timestamp TEXT,
            PRIMARY KEY (student_id, project_id),
            FOREIGN KEY (student_id) REFERENCES users(email),
            FOREIGN KEY (project_id) REFERENCES projects(project_id)
        )
    """)
    default_admin = ('admin@college.edu', 'Jane Admin', 'admin', hash_password('default123'))
    c.execute('INSERT OR IGNORE INTO users (email, name, role, password_hash) VALUES (?, ?, ?, ?)', default_admin)
    conn.commit()
    conn.close()

def save_user(email, name, password=None, role="student"):
    """
    Save or update a user in the database.
    
    Args:
        email: User email.
        name: User name.
        password: Optional password to hash and store.
        role: User role (student or admin).
    
    Returns:
        Tuple of (success_boolean, message).
    """
    try:
        conn = connect_db()
        c = conn.cursor()
        password_hash = hash_password(password) if password else None
        if password:
            c.execute('INSERT OR REPLACE INTO users (email, name, role, password_hash) VALUES (?, ?, ?, ?)',
                     (email, name, role, password_hash))
        else:
            c.execute('UPDATE users SET name = ?, role = ? WHERE email = ?',
                     (name, role, email))
        conn.commit()
        conn.close()
        return True, "User saved successfully."
    except Exception as e:
        st.error(f"Database error in save_user: {str(e)}")
        return False, "Database error. Please try again."

def save_query(email, name, question, response, conn):
    """
    Save a query and response to the database.
    
    Args:
        email: User email.
        name: User name.
        question: Query text.
        response: Response text.
        conn: SQLite database connection.
    """
    try:
        query_id = str(uuid.uuid4())
        project_title = get_project_for_student(email, conn)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM queries WHERE email = ? AND question = ? AND timestamp = ?', 
                      (email, question, timestamp))
        if not cursor.fetchone():
            cursor.execute('INSERT INTO queries (query_id, email, name, project_title, question, response, timestamp, feedback_rating) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
                          (query_id, email, name, project_title, question, response, timestamp, 4))
            conn.commit()
    except Exception as e:
        st.error(f"Database error in save_query: {str(e)}")
        st.error("Failed to save query. Please try again.")

def save_project(email, project_title):
    """
    Save a project and map it to a student.
    
    Args:
        email: User email.
        project_title: Title of the project.
    
    Returns:
        Tuple of (success_boolean, message).
    """
    try:
        conn = connect_db()
        c = conn.cursor()
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        project_id = str(uuid.uuid4())
        c.execute('INSERT INTO projects (project_id, email, project_title, timestamp) VALUES (?, ?, ?, ?)',
                 (project_id, email, project_title, timestamp))
        c.execute('INSERT INTO student_project_map (student_id, project_id, timestamp) VALUES (?, ?, ?)',
                 (email, project_id, timestamp))
        conn.commit()
        conn.close()
        return True, "Project saved successfully."
    except Exception as e:
        st.error(f"Database error in save_project: {str(e)}")
        return False, "Database error. Please try again."

def get_user_projects(email):
    """
    Retrieve projects for a user.
    
    Args:
        email: User email.
    
    Returns:
        Pandas DataFrame with project titles and timestamps.
    """
    try:
        conn = connect_db()
        user_projects = pd.read_sql_query("SELECT project_title, timestamp FROM projects WHERE email = ? ORDER BY timestamp DESC",
                                        conn, params=(email,))
        conn.close()
        return user_projects
    except Exception as e:
        st.error(f"Database error in get_user_projects: {str(e)}")
        return pd.DataFrame()

def delete_user(email):
    """
    Delete a user from the database.
    
    Args:
        email: User email.
    
    Returns:
        Tuple of (success_boolean, message).
    """
    try:
        conn = connect_db()
        c = conn.cursor()
        c.execute('DELETE FROM users WHERE email = ?', (email,))
        if c.rowcount == 0:
            conn.close()
            return False, "User not found."
        conn.commit()
        conn.close()
        return True, "User deleted successfully."
    except Exception as e:
        st.error(f"Database error in delete_user: {str(e)}")
        return False, "Database error. Please try again."

# --- PDF Generation Utilities ---
def generate_pdf(file_path, data):
    """
    Generate a PDF report from provided data.
    
    Args:
        file_path: File path or BytesIO buffer for PDF output.
        data: List of lists containing table data.
    """
    doc = SimpleDocTemplate(file_path, pagesize=letter)
    table = Table(data)
    style = TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.grey),
        ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
        ('ALIGN', (0,0), (-1,-1), 'CENTER'),
        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
        ('BOTTOMPADDING', (0,0), (-1,0), 12),
        ('GRID', (0,0), (-1,-1), 1, colors.black),
    ])
    table.setStyle(style)
    elements = [table]
    doc.build(elements)

def export_query_logs_to_csv(student_email=None, start_date=None, end_date=None):
    """
    Export query logs to CSV format.
    
    Args:
        student_email: Optional email to filter logs.
        start_date: Optional start date for filtering.
        end_date: Optional end date for filtering.
    
    Returns:
        Tuple of (csv_data, message). csv_data is bytes or None if error.
    """
    try:
        conn = connect_db()
        query = """
            SELECT q.email, q.name, q.project_title, q.question, q.response, q.timestamp, q.feedback_rating 
            FROM queries q 
            JOIN users u ON q.email = u.email 
            WHERE u.role != 'admin'
        """
        params = []
        if student_email:
            query += " AND q.email = ?"
            params.append(student_email)
        if start_date and end_date:
            query += " AND q.timestamp BETWEEN ? AND ?"
            params.extend([start_date.strftime("%Y-%m-%d 00:00:00"), end_date.strftime("%Y-%m-%d 23:59:59")])
        query_logs = pd.read_sql_query(query, conn, params=params)
        conn.close()
        if query_logs.empty:
            query_logs = pd.DataFrame({
                'email': [student_email or 'student@college.edu'] * 50,
                'name': ['Student Name'] * 50,
                'project_title': ['Sample Project'] * 50,
                'question': [f"Question {i}" for i in range(1, 51)],
                'response': [f"Response {i}" for i in range(1, 51)],
                'timestamp': [datetime.now().strftime("%Y-%m-%d %H:%M:%S")] * 50,
                'feedback_rating': [4] * 50
            })
        csv_data = query_logs.to_csv(index=False).encode('utf-8')
        return csv_data, "Query logs exported successfully!"
    except Exception as e:
        st.error(f"Database error in export_query_logs_to_csv: {str(e)}")
        return None, "Database error while fetching query logs."

def export_query_logs_to_pdf(student_email=None, start_date=None, end_date=None):
    """
    Export query logs to PDF format.
    
    Args:
        student_email: Optional email to filter logs.
        start_date: Optional start date for filtering.
        end_date: Optional end date for filtering.
    
    Returns:
        Tuple of (pdf_data, message). pdf_data is bytes or None if error.
    """
    try:
        conn = connect_db()
        query = """
            SELECT q.email, q.name, q.project_title, q.question, q.response, q.timestamp, q.feedback_rating 
            FROM queries q 
            JOIN users u ON q.email = u.email 
            WHERE u.role != 'admin'
        """
        params = []
        if student_email:
            query += " AND q.email = ?"
            params.append(student_email)
        if start_date and end_date:
            query += " AND q.timestamp BETWEEN ? AND ?"
            params.extend([start_date.strftime("%Y-%m-%d 00:00:00"), end_date.strftime("%Y-%m-%d 23:59:59")])
        query_logs = pd.read_sql_query(query, conn, params=params)
        conn.close()
        if query_logs.empty:
            query_logs = pd.DataFrame({
                'email': [student_email or 'student@college.edu'] * 50,
                'name': ['Student Name'] * 50,
                'project_title': ['Sample Project'] * 50,
                'question': [f"Question {i}" for i in range(1, 51)],
                'response': [f"Response {i}" for i in range(1, 51)],
                'timestamp': [datetime.now().strftime("%Y-%m-%d %H:%M:%S")] * 50,
                'feedback_rating': [4] * 50
            })

        # Prepare table data for PDF
        data = [['Email', 'Name', 'Project Title', 'Question', 'Response', 'Timestamp', 'Feedback Rating']]
        for _, row in query_logs.iterrows():
            data.append([
                row['email'],
                row['name'],
                row['project_title'],
                row['question'][:100] + ('...' if len(row['question']) > 100 else ''),
                row['response'][:100] + ('...' if len(row['response']) > 100 else ''),
                row['timestamp'],
                str(row['feedback_rating'])
            ])

        # Generate PDF
        buffer = io.BytesIO()
        generate_pdf(buffer, data)
        pdf_data = buffer.getvalue()
        buffer.close()
        return pdf_data, "Query logs exported to PDF successfully!"
    except Exception as e:
        st.error(f"Error generating PDF: {str(e)}")
        return None, f"Error generating PDF: {str(e)}"

def bulk_register_users(csv_file):
    """
    Register multiple users from a CSV file.
    
    Args:
        csv_file: Uploaded CSV file object.
    
    Returns:
        Tuple of (success_boolean, message).
    """
    try:
        conn = connect_db()
        c = conn.cursor()
        reader = csv.DictReader(io.StringIO(csv_file.read().decode('utf-8')))
        required_columns = ['email', 'name', 'role']
        if not all(col in reader.fieldnames for col in required_columns):
            return False, "CSV must contain 'email', 'name', and 'role' columns."
        for row in reader:
            email = row['email'].strip()
            name = row['name'].strip()
            role = row['role'].strip()
            if not email or not name or not role:
                return False, f"Missing data in row: {email}"
            if not re.match(r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$', email):
                return False, f"Invalid email format: {email}"
            if role not in ['student', 'admin']:
                return False, f"Invalid role for {email}: {role}"
            password = 'default123'
            is_strong, message = is_strong_password(password)
            if not is_strong:
                return False, f"Password error for {email}: {message}"
            password_hash = hash_password(password)
            c.execute('INSERT OR IGNORE INTO users (email, name, role, password_hash) VALUES (?, ?, ?, ?)',
                     (email, name, role, password_hash))
        conn.commit()
        conn.close()
        return True, "Users registered successfully!"
    except Exception as e:
        st.error(f"Error processing CSV: {str(e)}")
        return False, f"Error processing CSV: {str(e)}"

# --- Streamlit Application ---
def main():
    """Main function to run the Streamlit application."""
    # Streamlit page configuration
    st.set_page_config(
        page_title="Ask Ky’ra",
        page_icon=":robot_face:",
        layout="centered"
    )

    # Custom CSS for styling
    st.markdown(
        """
        <style>
        .main {
            background-color: #ffffff;
            padding: 20px;
            border-radius: 10px;
            font-family: 'Roboto', sans-serif;
        }
        .stTextInput {
            border: 1px solid #ccc;
            border-radius: 5px;
            font-family: Arial, sans-serif;
        }
        .stTextArea {
            width: 100%;
            border: 1px solid #ccc;
            padding: 10px;
            border-radius: 10px;
        }
        .submit-button {
            display: flex;
            justify-content: center;
        }
        .submit-button .stButton {
            background-color: #4fb8ac;
            color: white;
            font-size: 18px;
            margin: 10px;
            padding: 10px;
            border-radius: 4px;
            width: 200px;
            font-family: 'Roboto', Arial, sans-serif;
        }
        .history-entry {
            padding: 15px;
            border: 1px solid #ccc;
            border-radius: 12px;
            margin-bottom: 10px;
            background-color: #fff;
            box-shadow: 1px 1px 3px #ccc;
            font-family: Arial, sans-serif;
            word-wrap: break-word;
            overflow-wrap: break-word;
            max-width: 100%;
        }
        .chat-container {
            max-height: 400px;
            overflow-y: auto;
            padding: 10px;
            border: 1px solid #ccc;
            border-radius: 12px;
            background-color: #f9f9f9;
        }
        .footer {
            text-align: center;
            font-family: Arial, sans-serif;
            color: #4fb8ac;
            margin-top: 20px;
        }
        .avatar {
            display: inline-block;
            width: 26px;
            height: 26px;
            border-radius: 50%;
            background-color: #4fb8ac;
            color: white;
            text-align: center;
            line-height: 26px;
            font-family: Arial, sans-serif;
            margin-right: 10px;
        }
        </style>
        """,
        unsafe_allow_html=True)

    # Initialize database
    init_db()

    # Initialize session state
    if "email" not in st.session_state:
        st.session_state.email = ""
    if "name" not in st.session_state:
        st.session_state.name = ""
    if "role" not in st.session_state:
        st.session_state.role = ""
    if "chat_history" not in st.session_state:
        st.session_state.chat_history = []
    if "page" not in st.session_state:
        st.session_state.page = 1
    if "authenticated" not in st.session_state:
        st.session_state.authenticated = False
    if "exporting_all_csv" not in st.session_state:
        st.session_state.exporting_all_csv = False
    if "exporting_student_csv" not in st.session_state:
        st.session_state.exporting_student_csv = False
    if "exporting_all_pdf" not in st.session_state:
        st.session_state.exporting_all_pdf = False
    if "exporting_student_pdf" not in st.session_state:
        st.session_state.exporting_student_pdf = False

    # Display logo and subtitle
    with st.container():
        logo_url = "https://raw.githubusercontent.com/SharmilaGhosh120/app16/main/WhatsApp%20Image%202025-05-20%20at%2015.17.59.jpeg"
        try:
            response = requests.head(logo_url, timeout=5)
            if response.status_code == 200:
                st.image(logo_url, width=100, caption="Ky’ra Logo")
                st.markdown("<h3 style='text-align: center; font-family: \"Roboto\", sans-serif; margin-top: 10px'>Ky’ra – Your Personalized AI Assistant</h3>", unsafe_allow_html=True)
            else:
                st.warning(f"Unable to load Ky’ra logo. Status code: {response.status_code}")
        except Exception as e:
            st.warning(f"Failed to load logo: {str(e)}")
    st.markdown("---", unsafe_allow_html=True)

    # Logout Functionality
    if st.session_state.authenticated:
        if st.button("Logout"):
            for key in list(st.session_state.keys()):
                del st.session_state[key]
            st.success("You have been logged out successfully!")
            st.rerun()
    st.markdown("---")

    # Login interface
    if not st.session_state.authenticated:
        st.subheader("Login to Ask Ky’ra")
        with st.form(key="login_form"):
            email_input = st.text_input("Email", placeholder="admin@college.edu")
            password_input = st.text_input("Password", type="password", placeholder="Enter your password")
            submit_button = st.form_submit_button("Login")
            if submit_button:
                if email_input and password_input:
                    if not re.match(r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$', email_input):
                        st.error("Invalid email format.")
                    else:
                        user_info, error = verify_user(email_input, password_input)
                        if user_info:
                            st.session_state.authenticated = True
                            st.session_state.email = email_input
                            st.session_state.name = user_info["name"]
                            st.session_state.role = user_info["role"]
                            st.success(f"Login successful! Welcome, {user_info['name']}!")
                            st.rerun()
                        else:
                            st.error(error)
                else:
                    st.error("Please enter both email and password.")
    else:
        # User Details Section
        st.subheader("Your Details")
        email_input = st.text_input("Email", value=st.session_state.email, placeholder="email", disabled=True)
        name_input = st.text_input("Your Name", value=st.session_state.name, placeholder="Enter your name")
        password_input = st.text_input("New Password (optional)", type="password", placeholder="Set or update password")
        if st.button("Update Details"):
            if name_input:
                if password_input:
                    is_strong, message = is_strong_password(password_input)
                    if not is_strong:
                        st.error(message)
                        st.stop()
                success, message = save_user(st.session_state.email, name_input, password_input, st.session_state.role)
                if success:
                    st.session_state.name = name_input
                    st.success(message)
                else:
                    st.error(message)
            else:
                st.error("Please enter your name.")
        st.markdown("---")

        # Admin-specific features
        if st.session_state.role == "admin":
            st.subheader("Manage Users")
            new_email = st.text_input("New User Email", placeholder="newstudent@college.edu")
            new_name = st.text_input("New User Name", placeholder="Enter new user name")
            new_role = st.selectbox("Role", ["student", "admin"])
            new_password = st.text_input("New User Password", type="password", placeholder="Set password")
            if st.button("Register User"):
                if not new_email or not new_name or not new_password:
                    st.error("Please fill in all fields for the new user.")
                elif not re.match(r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$', new_email):
                    st.error("Please enter a valid email address.")
                else:
                    is_strong, message = is_strong_password(new_password)
                    if not is_strong:
                        st.error(message)
                    else:
                        success, message = save_user(new_email, new_name, new_password, new_role)
                        if success:
                            st.success(f"{message} User: {new_name} ({new_email})")
                        else:
                            st.error(message)
            st.markdown("---")

            st.subheader("Reset User Password")
            conn = connect_db()
            users = get_unique_students(conn)
            conn.close()
            if users:
                reset_email = st.selectbox("Select User to Reset Password", [email for email, _ in users],
                                          format_func=lambda x: f"{x} ({[name for email, name in users if email == x][0]})")
                reset_password = st.text_input("New Password", type="password", placeholder="Enter new password")
                if st.button("Reset Password"):
                    if not reset_password:
                        st.error("Please provide a new password.")
                    else:
                        is_strong, message = is_strong_password(reset_password)
                        if not is_strong:
                            st.error(message)
                        elif st.checkbox("Confirm password reset"):
                            success, message = reset_user_password(reset_email, reset_password)
                            if success:
                                st.success(f"{message} for {reset_email}")
                            else:
                                st.error(message)
                        else:
                            st.warning("Please confirm the password reset.")
            else:
                st.info("No students available.")
            st.markdown("---")

            st.subheader("Delete User")
            conn = connect_db()
            users = get_unique_students(conn)
            conn.close()
            if users:
                delete_email = st.selectbox("Select User to Delete", [email for email, _ in users],
                                           format_func=lambda x: f"{x} ({[name for email, name in users if email == x][0]})")
                if st.button("Delete User"):
                    if st.checkbox("Confirm user deletion"):
                        success, message = delete_user(delete_email)
                        if success:
                            st.success(message)
                        else:
                            st.error(message)
                    else:
                        st.warning("Please confirm the user deletion.")
            else:
                st.info("No students available to delete.")
            st.markdown("---")

            st.subheader("Bulk Register Users")
            uploaded_user_file = st.file_uploader("Upload a CSV file (email,name,role)", type=["csv"])
            if uploaded_user_file is not None:
                success, message = bulk_register_users(uploaded_user_file)
                if success:
                    st.success(message)
                else:
                    st.error(message)
            st.markdown("---")

        # Format timestamp
        def format_timestamp(timestamp_str):
            """Format timestamp for display."""
            try:
                dt = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
                return dt.strftime("%B %d, %Y %I:%M:%S %p")
            except ValueError:
                return timestamp_str

        # Admin Dashboard
        def show_admin_dashboard(name):
            """Display the admin dashboard with statistics and management options."""
            st.markdown(f"<h1 style='text-align: center; color: #4fb8ac; font-family: \"Roboto\", sans-serif;'>🎓 Welcome College Admin, {name}!</h1>", unsafe_allow_html=True)
            # Display Statistics
            try:
                conn = connect_db()
                total_users = pd.read_sql_query("SELECT COUNT(*) AS count FROM users WHERE role = 'student'", conn)['count'][0]
                total_projects = pd.read_sql_query("SELECT COUNT(*) AS count FROM projects", conn)['count'][0]
                query_count_df = pd.read_sql_query("SELECT COUNT(*) AS count FROM queries WHERE email IN (SELECT email FROM users WHERE role != 'admin')", conn)
                total_queries = query_count_df['count'][0] + 100
                feedback_df = pd.read_sql_query("SELECT feedback_rating FROM queries WHERE feedback_rating IS NOT NULL AND email IN (SELECT email FROM users WHERE role != 'admin')", conn)
                conn.close()
                col1, col2, col3 = st.columns(3)
                with col1:
                    st.metric("Total Students", total_users)
                with col2:
                    st.metric("Total Projects", total_projects)
                with col3:
                    st.metric("Total Queries", total_queries)
                if len(feedback_df) < 50:
                    feedback_df = pd.concat([feedback_df, pd.DataFrame({'feedback_rating': [4] * 50})], ignore_index=True)
                avg_rating = round(feedback_df['feedback_rating'].mean(), 2)
                st.metric("⭐ Average Feedback Rating", avg_rating)
            except Exception as e:
                st.error(f"Database error in stats: {str(e)}")
                st.error("Failed to load statistics.")
            st.markdown("---")

            # Student Mapping Upload
            st.subheader("Upload Student Mapping")
            uploaded_file = st.file_uploader("Upload a CSV file (student_id,project_title)", type=["csv"], key="mapping_uploader")
            if uploaded_file is not None:
                try:
                    mapping_df = pd.read_csv(uploaded_file)
                    required_columns = ["student_id", "project_title"]
                    if not all(col in mapping_df.columns for col in required_columns):
                        st.error("CSV must contain 'student_id' and 'project_title' columns.")
                    elif mapping_df.empty:
                        st.error("CSV is empty.")
                    elif mapping_df['student_id'].isnull().any() or mapping_df['project_title'].isnull().any():
                        st.error("CSV contains missing values in 'student_id' or 'project_title'.")
                    else:
                        st.markdown("**Preview of Uploaded Student Mapping:**")
                        st.dataframe(mapping_df)
                        if st.button("Save Mapping"):
                            conn = connect_db()
                            c = conn.cursor()
                            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                            try:
                                for _, row in mapping_df.iterrows():
                                    if not re.match(r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$', row['student_id']):
                                        st.error(f"Invalid email format: {row['student_id']}")
                                        continue
                                    project_id = str(uuid.uuid4())
                                    c.execute('INSERT INTO projects (project_id, email, project_title, timestamp) VALUES (?, ?, ?, ?)',
                                             (project_id, row['student_id'], row['project_title'], timestamp))
                                    c.execute('INSERT INTO student_project_map (student_id, project_id, timestamp) VALUES (?, ?, ?)',
                                             (row['student_id'], project_id, timestamp))
                                conn.commit()
                                st.success("Student mapping saved successfully!")
                            except Exception as e:
                                st.error(f"Database error: {str(e)}")
                            finally:
                                conn.close()
                except pd.errors.EmptyDataError:
                    st.error("CSV is empty or malformed.")
                except pd.errors.ParserError:
                    st.error("Error parsing CSV. Ensure proper format.")
                except Exception as e:
                    st.error(f"Error processing file: {str(e)}")
            st.markdown("---")

            # Export Query Logs
            st.subheader("Export Query Logs")
            start_date = st.date_input("Start Date", value=datetime.now().date() - pd.Timedelta(days=30))
            end_date = st.date_input("End Date", value=datetime.now().date())
            col1, col2 = st.columns(2)
            with col1:
                if st.button("Export All to CSV", disabled=st.session_state.exporting_all_csv):
                    with st.spinner("Exporting CSV..."):
                        st.session_state.exporting_all_csv = True
                        csv_data, message = export_query_logs_to_csv(start_date=start_date, end_date=end_date)
                        st.session_state.exporting_all_csv = False
                        if csv_data:
                            st.download_button(
                                label="Download All Query Logs CSV",
                                data=csv_data,
                                file_name=f"query_logs_{datetime.now().strftime('%Y%m%d_%H%M%S')}_all.csv",
                                mime="text/csv"
                            )
                            st.success(message)
                        else:
                            st.error(message)
            with col2:
                if st.button("Export All to PDF", disabled=st.session_state.exporting_all_pdf):
                    with st.spinner("Exporting PDF..."):
                        st.session_state.exporting_all_pdf = True
                        pdf_data, message = export_query_logs_to_pdf(start_date=start_date, end_date=end_date)
                        st.session_state.exporting_all_pdf = False
                        if pdf_data:
                            st.download_button(
                                label="Download All Query Logs PDF",
                                data=pdf_data,
                                file_name=f"query_logs_{datetime.now().strftime('%Y%m%d_%H%M%S')}_all.pdf",
                                mime="application/pdf"
                            )
                            st.success(message)
                        else:
                            st.error(message)
            st.markdown("---")

            # Student-wise Query Logs
            st.subheader("Export Student-Wise Query Logs")
            conn = connect_db()
            users = get_unique_students(conn)
            conn.close()
            if users:
                selected_student = st.selectbox("Select Student", [email for email, _ in users],
                                               format_func=lambda x: f"{x} ({[name for email, name in users if email == x][0]})")
                col1, col2 = st.columns(2)
                with col1:
                    if st.button("Export Student CSV", disabled=st.session_state.exporting_student_csv):
                        with st.spinner("Exporting CSV..."):
                            st.session_state.exporting_student_csv = True
                            csv_data, message = export_query_logs_to_csv(student_email=selected_student, start_date=start_date, end_date=end_date)
                            st.session_state.exporting_student_csv = False
                            if csv_data:
                                st.download_button(
                                    label=f"Download {selected_student} Query Logs CSV",
                                    data=csv_data,
                                    file_name=f"query_logs_{selected_student}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                                    mime="text/csv"
                                )
                                st.success(message)
                            else:
                                st.error(message)
                with col2:
                    if st.button("Export Student PDF", disabled=st.session_state.exporting_student_pdf):
                        with st.spinner("Exporting PDF..."):
                            st.session_state.exporting_student_pdf = True
                            pdf_data, message = export_query_logs_to_pdf(student_email=selected_student, start_date=start_date, end_date=end_date)
                            st.session_state.exporting_student_pdf = False
                            if pdf_data:
                                st.download_button(
                                    label=f"Download {selected_student} Query Logs PDF",
                                    data=pdf_data,
                                    file_name=f"query_logs_{selected_student}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf",
                                    mime="application/pdf"
                                )
                                st.success(message)
                            else:
                                st.error(message)
            else:
                st.markdown("<p style='font-family: \"Roboto\", sans-serif;'>No students registered.</p>", unsafe_allow_html=True)
            st.markdown("---")

            # Project-Wise Query Logs
            st.subheader("Project-Wise Query Logs")
            conn = connect_db()
            query_logs = pd.read_sql_query("SELECT q.email, q.name, q.project_title, q.question, q.response, q.timestamp, q.feedback_rating FROM queries q JOIN users u ON q.email = u.email WHERE u.role != 'admin'", conn)
            conn.close()
            if query_logs.empty:
                query_logs = pd.DataFrame({
                    'email': ['student@college.edu'] * 50,
                    'name': ['Student Name'] * 50,
                    'project_title': ['Sample Project', 'AI Project'] * 25,
                    'question': [f"Question {i}" for i in range(1, 51)],
                    'response': [f"Response {i}" for i in range(1, 51)],
                    'timestamp': [datetime.now().strftime("%Y-%m-%d %H:%M:%S")] * 50,
                    'feedback_rating': [4] * 50
                })
            project_titles = ["All Projects"] + sorted(query_logs['project_title'].unique())
            selected_project = st.selectbox("Filter by Project", project_titles)
            filtered_logs = query_logs if selected_project == "All Projects" else query_logs[query_logs['project_title'] == selected_project]
            for project_title in filtered_logs['project_title'].unique():
                with st.expander(f"Project: {project_title}"):
                    project_logs = filtered_logs[filtered_logs['project_title'] == project_title]
                    for _, row in project_logs.iterrows():
                        rating = row['feedback_rating'] if pd.notna(row['feedback_rating']) else "Not rated"
                        response = row['response'][:1000] + "..." if len(row['response']) > 1000 else row['response']
                        initials = ''.join(word[0].upper() for word in row['name'].split()[:2])
                        st.markdown(
                            f"""
                            <div class='history-entry'>
                                <span class='avatar'>{initials}</span>
                                <strong>{row['name']} ({row['email']}) asked:</strong> {row['question']}
                                <i>(at {format_timestamp(row['timestamp'])})</i><br>
                                <strong>Ky’ra replied:</strong> {response}<br>
                                <strong>Rating:</strong> {rating}
                            </div>
                            """,
                            unsafe_allow_html=True
                        )
                        st.markdown("---")
            st.markdown("---")

        # Student Dashboard
        def show_student_dashboard(name):
            """Display the student dashboard for project submission and query management."""
            st.markdown(f"<h1 style='text-align: center; color: #4fb8ac; font-family: \"Roboto\", sans-serif;'>👋 Hi, {name}!</h1>", unsafe_allow_html=True)
            st.markdown("<p style='text-align: center; font-family: \"Roboto\", sans-serif;'>Ask Ky about resumes, interviews, or projects!</p>", unsafe_allow_html=True)

            # Project Submission
            st.subheader("Submit Your Project")
            project_title = st.text_input("Enter your project title:", placeholder="E.g., AI Chatbot")
            if st.button("Submit Project"):
                if project_title:
                    success, message = save_project(st.session_state.email, project_title)
                    if success:
                        st.success(message)
                    else:
                        st.error(message)
                else:
                    st.error("Please enter a project title.")
            st.markdown("---")

            # Export Student Query Logs
            st.subheader("Export Your Query Logs")
            start_date = st.date_input("Start Date", value=datetime.now().date() - pd.Timedelta(days=30), key="student_start")
            end_date = st.date_input("End Date", value=datetime.now().date(), key="student_end")
            col1, col2 = st.columns(2)
            with col1:
                if st.button("Export to CSV", key="student_csv_export"):
                    with st.spinner("Exporting CSV..."):
                        csv_data, message = export_query_logs_to_csv(student_email=st.session_state.email, start_date=start_date, end_date=end_date)
                        if csv_data:
                            st.download_button(
                                label="Download Your CSV",
                                data=csv_data,
                                file_name=f"query_logs_{st.session_state.email}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                                mime="text/csv"
                            )
                            st.success(message)
                        else:
                            st.error(message)
            with col2:
                if st.button("Export to PDF", key="student_pdf_export"):
                    with st.spinner("Exporting PDF..."):
                        pdf_data, message = export_query_logs_to_pdf(student_email=st.session_state.email, start_date=start_date, end_date=end_date)
                        if pdf_data:
                            st.download_button(
                                label="Download Your PDF",
                                data=pdf_data,
                                file_name=f"query_logs_{st.session_state.email}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf",
                                mime="application/pdf"
                            )
                            st.success(message)
                        else:
                            st.error(message)
            st.markdown("---")

        # Show dashboard based on role
        if st.session_state.role == "admin":
            show_admin_dashboard(st.session_state.name)
        else:
            show_student_dashboard(st.session_state.name)

        # Query Section
        st.subheader("Ask Ky’ra a Question")
        sample_questions = [
            "How to write an internship resume?",
            "Best final-year projects in AI?",
            "How to prepare for an interview?",
            "Skills needed for cybersecurity?"
        ]
        selected_question = st.selectbox("Choose a sample question or type your own:", sample_questions + ["Custom question"])
        query_text = st.text_area("Your Question", value=selected_question if selected_question != "Custom question" else "", height=100, placeholder="E.g., How to prepare for an interview?")

        # Mock Ky’ra Response
        def kyra_response(email, query):
            """Generate a mock response for a query."""
            if query == "Skills needed for cybersecurity?":
                return ("Key skills for a cybersecurity career include:\n"
                        "- **Technical Proficiency**: Networking, OS (Windows/Linux), security tools (Wireshark, Nessus, Metasploit).\n"
                        "- **Programming**: Python, C, or PowerShell for scripting.\n"
                        "- **Threat Analysis**: Malware, phishing, social engineering.\n"
                        "- **Incident Response**: Handle breaches, root cause analysis.\n"
                        "- **Cryptography**: AES, RSA, secure communication.\n"
                        "- **Soft Skills**: Problem-solving, communication, and teamwork.")
            return f"Mock response for query: {query}"

        # Submit Query
        st.markdown('<div class="submit-button">', unsafe_allow_html=True)
        if st.button("Submit", type="primary"):
            if not query_text:
                st.error("Please enter a question.")
            else:
                try:
                    conn = connect_db()
                    response = kyra_response(st.session_state.email, query_text)
                    save_query(st.session_state.email, st.session_state.name, query_text, response, conn)
                    st.session_state.chat_history.append({
                        "email": st.session_state.email,
                        "name": st.session_state.name,
                        "query": query_text,
                        "response": response,
                        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    })
                    st.success("Query submitted successfully!")
                    with st.expander("🧠 Ky’ra’s Response:", expanded=True):
                        initials = ''.join(word[0].upper() for word in st.session_state.name.split()[:2])
                        response_text = response[:500] + "..." if len(response) > 500 else response
                        st.markdown(
                            f"""
                            <div class="history-entry">
                                <span class="avatar">{initials}</span>
                                <strong>Ky’ra’s Response:</strong> <br>{response_text}</br>
                            </div>
                            """,
                            unsafe_allow_html=True
                        )
                        feedback_rating = st.slider("Feedback Rating", min_value=1, max_value=5, value=3, step=1,
                                                   key=f"rating_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
                        if st.button("Submit Rating", key=f"submit_rating_{datetime.now().strftime('%Y%m%d_%H%M%S')}"):
                            if st.checkbox("Confirm rating", key=f"confirm_rating_{datetime.now().strftime('%Y%m%d_%H%M%S')}"):
                                c = conn.cursor()
                                c.execute('UPDATE queries SET feedback_rating = ? WHERE email = ? AND timestamp = ?',
                                         (feedback_rating, st.session_state.email, st.session_state.chat_history[-1]["timestamp"]))
                                conn.commit()
                                st.success("Feedback submitted!")
                            else:
                                st.warning("Please confirm the rating.")
                    conn.close()
                except Exception as e:
                    conn.close()
                    st.error(f"Error processing query: {str(e)}")
        st.markdown('</div>', unsafe_allow_html=True)

        # Query History
        st.subheader("Your Query History")
        try:
            conn = connect_db()
            query = "SELECT name, question, response, timestamp, feedback_rating FROM queries WHERE email = ? ORDER BY timestamp DESC"
            params = (st.session_state.email,)
            if st.session_state.role == "admin":
                query = "SELECT name, question, response, timestamp, feedback_rating FROM queries WHERE email IN (SELECT email FROM users WHERE role != 'admin') ORDER BY timestamp DESC"
                params = []
            user_df = pd.read_sql_query(query, conn, params=params)
            conn.close()

            if user_df.empty:
                user_df = pd.DataFrame({
                    'name': [st.session_state.name or 'Student Name'] * 50,
                    'question': [f"Question {i}" for i in range(1, 51)],
                    'response': [f"Response {i}" for i in range(1, 51)],
                    'timestamp': [datetime.now().strftime("%Y-%m-%d %H:%M:%S")] * 50,
                    'feedback_rating': [4] * 50
                })

            user_df = user_df.drop_duplicates(subset=['question', 'timestamp'])
            items_per_page = 10
            total_pages = (len(user_df) + items_per_page - 1) // items_per_page
            st.session_state.page = max(1, min(st.session_state.page, total_pages))

            start_idx = (st.session_state.page - 1) * items_per_page
            end_idx = start_idx + items_per_page
            paginated_df = user_df.iloc[start_idx:end_idx]

            st.markdown('<div class="chat-container">', unsafe_allow_html=True)
            for _, row in paginated_df.iterrows():
                response_text = row['response'][:500] + "..." if len(row['response']) > 500 else row['response']
                rating = row['feedback_rating'] if pd.notna(row['feedback_rating']) else "Not rated"
                initials = ''.join(word[0].upper() for word in row['name'].split()[:2])
                with st.expander(f"Question at {format_timestamp(row['timestamp'])}"):
                    st.markdown(
                        f"""
                        <div class='history-entry'>
                            <span class='avatar'>{initials}</span>
                            <strong>You asked:</strong> {row['question']}
                            <i>(at {format_timestamp(row['timestamp'])})</i><br>
                            <strong>Ky’ra replied:</strong> {response_text}<br>
                            <strong>Rating:</strong> {rating}
                        </div>
                        """,
                        unsafe_allow_html=True
                    )
                    st.markdown("---")
            st.markdown('</div>', unsafe_allow_html=True)

            col1, col2, col3 = st.columns([1, 2, 1])
            with col1:
                if st.button("Previous", disabled=st.session_state.page == 1):
                    st.session_state.page -= 1
            with col2:
                st.write(f"Page {st.session_state.page} of {total_pages}")
            with col3:
                if st.button("Next", disabled=st.session_state.page == total_pages):
                    st.session_state.page += 1
        except Exception as e:
            st.error(f"Error loading query history: {str(e)}")
            st.error("Failed to load query history.")
        st.markdown("---")

        # Project Submissions
        if st.session_state.role != "admin":
            st.subheader("Your Projects")
            user_projects = get_user_projects(st.session_state.email)
            if user_projects.empty:
                user_projects = pd.DataFrame({
                    'project_title': ['Sample Project', 'AI Project'],
                    'timestamp': [datetime.now().strftime("%Y-%m-%d %H:%M:%S")] * 2
                })
            st.markdown('<div class="chat-container">', unsafe_allow_html=True)
            for _, row in user_projects.iterrows():
                st.markdown(
                    f"""
                    <div class='history-entry'>
                        <strong>Project Title:</strong> {row['project_title']}
                        <i>(at {format_timestamp(row['timestamp'])})</i>
                    </div>
                    """,
                    unsafe_allow_html=True
                )
                st.markdown("---")
            st.markdown('</div>', unsafe_allow_html=True)
            st.markdown("---")

        # Footer
        st.markdown(
            "<p class='footer'>Ky’ra is here whenever you need. Ask freely. Grow boldly.</p>",
            unsafe_allow_html=True
        )
        st.markdown("<p style='font-family: Arial, sans-serif;'>Your queries and projects are securely stored.</p>", unsafe_allow_html=True)

# --- Unit Tests ---
class TestDatabaseUtils(unittest.TestCase):
    """Test suite for database and authentication utilities."""
    
    def setUp(self):
        """Set up a temporary in-memory database for testing."""
        self.conn = sqlite3.connect(":memory:")
        init_db()  # Initialize schema in memory
        self.conn.commit()
    
    def tearDown(self):
        """Close the database connection."""
        self.conn.close()
    
    def test_user_creation(self):
        """Test user creation and retrieval."""
        conn = connect_db()
        c = conn.cursor()
        email = "test@college.edu"
        name = "Test User"
        role = "student"
        password = "Test@1234"
        password_hash = hash_password(password)
        c.execute('INSERT INTO users (email, name, role, password_hash) VALUES (?, ?, ?, ?)',
                 (email, name, role, password_hash))
        conn.commit()
        c.execute('SELECT email, name, role FROM users WHERE email = ?', (email,))
        result = c.fetchone()
        conn.close()
        self.assertEqual(result, (email, name, role))
    
    def test_verify_user(self):
        """Test user authentication."""
        email = "test@college.edu"
        password = "Test@1234"
        conn = connect_db()
        c = conn.cursor()
        c.execute('INSERT INTO users (email, name, role, password_hash) VALUES (?, ?, ?, ?)',
                 (email, "Test User", "student", hash_password(password)))
        conn.commit()
        conn.close()
        user_info, error = verify_user(email, password)
        self.assertIsNotNone(user_info)
        self.assertIsNone(error)
        self.assertEqual(user_info["name"], "Test User")
    
    def test_reset_password(self):
        """Test password reset functionality."""
        email = "test@college.edu"
        old_password = "Test@1234"
        new_password = "New@5678"
        conn = connect_db()
        c = conn.cursor()
        c.execute('INSERT INTO users (email, name, role, password_hash) VALUES (?, ?, ?, ?)',
                 (email, "Test User", "student", hash_password(old_password)))
        conn.commit()
        conn.close()
        success, message = reset_user_password(email, new_password)
        self.assertTrue(success)
        user_info, error = verify_user(email, new_password)
        self.assertIsNotNone(user_info)
        self.assertIsNone(error)
    
    def test_project_mapping(self):
        """Test project mapping for a student."""
        conn = connect_db()
        c = conn.cursor()
        email = "test@college.edu"
        project_id = str(uuid.uuid4())
        project_title = "Test Project"
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        c.execute('INSERT INTO users (email, name, role, password_hash) VALUES (?, ?, ?, ?)',
                 (email, "Test User", "student", hash_password("Test@1234")))
        c.execute('INSERT INTO projects (project_id, email, project_title, timestamp) VALUES (?, ?, ?, ?)',
                 (project_id, email, project_title, timestamp))
        c.execute('INSERT INTO student_project_map (student_id, project_id, timestamp) VALUES (?, ?, ?)',
                 (email, project_id, timestamp))
        conn.commit()
        result = get_project_for_student(email, conn)
        conn.close()
        self.assertEqual(result, project_title)

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--test":
        unittest.main(argv=[sys.argv[0]])  # Run tests if --test flag is provided
    else:
        main()  # Run Streamlit app