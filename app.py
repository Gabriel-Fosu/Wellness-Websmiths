#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Wellness Websmiths Healthcare App
Look for keywords in user symptoms
If present print out the possible sickness and suggest solution to it
Book appointments with doctors
Gives health tips
"""

from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from flask_dance.contrib.google import make_google_blueprint, google
import requests
from datetime import date
from collections import Counter
import sqlite3
import os
from dotenv import load_dotenv
import re
import csv
import urllib.parse

# -----------------------------
# Setup
# -----------------------------
load_dotenv()

app = Flask(__name__)
app.secret_key = "your_secret_key"  # change to something secure

os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'  # allow http for dev

# -----------------------------
# Google OAuth setup
# -----------------------------
app.config["GOOGLE_OAUTH_CLIENT_ID"] = "your_client_id_here"
app.config["GOOGLE_OAUTH_CLIENT_SECRET"] = "your_client_secret_here"
google_bp = make_google_blueprint(
    client_id=app.config["GOOGLE_OAUTH_CLIENT_ID"],
    client_secret=app.config["GOOGLE_OAUTH_CLIENT_SECRET"],
    scope=[
        "openid",
        "https://www.googleapis.com/auth/userinfo.email",
        "https://www.googleapis.com/auth/userinfo.profile",
    ],
)
app.register_blueprint(google_bp, url_prefix="/login")


# -----------------------------
# Password strength checker
# -----------------------------
def is_strong_password(password):
    """Check if password is strong enough"""
    if (len(password) < 8 or
        not re.search(r"[A-Z]", password) or
        not re.search(r"[a-z]", password) or
        not re.search(r"[0-9]", password) or
        not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password)):
        return False
    return True


# -----------------------------
# Database setup
# -----------------------------
def init_db():
    conn = sqlite3.connect("database.db")
    c = conn.cursor()

    # Users table
    c.execute('''CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    full_name TEXT NOT NULL,
                    email TEXT UNIQUE NOT NULL,
                    phone TEXT,
                    password TEXT NOT NULL
                )''')

    # Appointments table
    c.execute('''CREATE TABLE IF NOT EXISTS appointments (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    doctor TEXT,
                    date TEXT,
                    name TEXT
                )''')

    conn.commit()
    conn.close()

init_db()


# -----------------------------
# Routes
# -----------------------------
@app.route("/")
def home():
    if "user_id" in session:
        return render_template("dashboard.html")
    return render_template("index.html")


# Register
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        email = request.form["email"]
        full_name = request.form["full_name"]
        phone = request.form["phone"]
        password = request.form["password"]
        confirm_password = request.form["confirm_password"]

        # ✅ check passwords match
        if password != confirm_password:
            flash("Passwords do not match!", "danger")
            return redirect(url_for("register"))

        # ✅ check password strength
        if not is_strong_password(password):
            flash("Password must be at least 8 characters, include uppercase, lowercase, number, and symbol.", "danger")
            return redirect(url_for("register"))

        # Securely hash password
        hashed_pw = generate_password_hash(password, method="pbkdf2:sha256")

        try:
            conn = sqlite3.connect("database.db")
            c = conn.cursor()
            c.execute("""
                INSERT INTO users (email, full_name, phone, password)
                VALUES (?, ?, ?, ?)
            """, (email, full_name, phone, hashed_pw))
            conn.commit()
            conn.close()

            flash("Registration successful! Please log in.", "success")
            return redirect(url_for("login"))

        except sqlite3.IntegrityError:
            flash("Email already exists. Try another one.", "danger")

    return render_template("register.html")


# Login
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]

        conn = sqlite3.connect("database.db")
        c = conn.cursor()
        c.execute("SELECT id, password, full_name FROM users WHERE email=?", (email,))
        user = c.fetchone()
        conn.close()

        if user and check_password_hash(user[1], password):
            session["user_id"] = user[0]
            session["full_name"] = user[2]
            flash("Login successful!", "success")
            return redirect(url_for("home"))
        else:
            flash("Invalid email or password.", "danger")
    return render_template("login.html")


# Logout
@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("home"))


# Google Auth callback
@app.route("/google-auth")
def google_auth_callback():
    if not google.authorized:
        return redirect(url_for("google.login"))

    resp = google.get("/oauth2/v2/userinfo")
    user_info = resp.json()

    email = user_info["email"]
    full_name = user_info.get("name", "Google User")

    conn = sqlite3.connect("database.db")
    c = conn.cursor()
    c.execute("SELECT id FROM users WHERE email=?", (email,))
    user = c.fetchone()

    if not user:
        c.execute("INSERT INTO users (email, full_name, phone, password) VALUES (?, ?, ?, ?)",
                  (email, full_name, "N/A", ""))
        conn.commit()
        user_id = c.lastrowid
    else:
        user_id = user[0]
    conn.close()

    session["user_id"] = user_id
    session["full_name"] = full_name
    flash("Logged in with Google!", "success")
    return redirect(url_for("home"))


# Dashboard
@app.route("/dashboard", methods=["GET", "POST"])
def dashboard():
    if "user_id" not in session:
        return redirect(url_for("login"))

    user_id = session["user_id"]
    username = session.get("full_name")

    conn = sqlite3.connect("database.db")
    c = conn.cursor()
    c.execute("SELECT doctor, date, name FROM appointments WHERE user_id=?", (user_id,))
    appointments = c.fetchall()
    conn.close()

    total_appointments = len(appointments)
    today_iso = date.today().isoformat()
    upcoming_appointments = [a for a in appointments if a[1] and a[1] >= today_iso]

    months = [a[1][:7] for a in appointments if a[1] and len(a[1]) >= 7]
    monthly_count = Counter(months)
    labels = sorted(monthly_count.keys())
    values = [monthly_count[m] for m in labels]

    return render_template(
        "dashboard.html",
        username=username,
        appointments=appointments,
        total_appointments=total_appointments,
        upcoming_appointments=upcoming_appointments,
        chart_labels=labels,
        chart_values=values
    )


# Symptom Checker
@app.route("/diagnosis", methods=["GET", "POST"])
def diagnosis():
    result = None
    recommendation = None
    if request.method == "POST":
        symptoms = request.form.get("symptoms").lower()

        # Extended keyword-based diagnosis
        if "fever" in symptoms or "chills" in symptoms or "sweating" in symptoms:
            result = "Possible Malaria"
            recommendation = "Seek medical attention and request a malaria test immediately."
        elif "fever" in symptoms or "cough" in symptoms and "difficulty breathing" in symptoms:
            result = "Possible Pneumonia"
            recommendation = "Consult a doctor immediately for chest X-ray and antibiotics."
        elif "wheezing" in symptoms or "shortness of breath" in symptoms:
            result = "Possible Asthma"
            recommendation = "Use prescribed inhaler and avoid triggers. Seek urgent care if severe."
        elif "fever" in symptoms or "cough" in symptoms and "loss of taste" in symptoms:
            result = "Possible COVID-19"
            recommendation = "Get tested for COVID-19 and self-isolate. Seek medical help if symptoms worsen."
        elif "fatigue" in symptoms or "weight loss" in symptoms and "increased thirst" in symptoms:
            result = "Possible Diabetes"
            recommendation = "Consult a doctor for blood sugar tests and lifestyle management."
        elif "chest pain" in symptoms or "shortness of breath" in symptoms:
            result = "Possible Heart Problem"
            recommendation = "Seek immediate emergency care."
        elif "headache" in symptoms or "nausea" in symptoms or "sensitivity to light" in symptoms:
            result = "Possible Migraine"
            recommendation = "Rest in a quiet, dark room. Seek medical care if frequent."
        elif "sore throat" in symptoms and "runny nose" in symptoms:
            result = "Possible Common Cold"
            recommendation = "Rest, drink warm fluids, and use over-the-counter remedies."
        elif "fever" in symptoms and "rash" in symptoms:
            result = "Possible Measles"
            recommendation = "Seek medical care. Isolate to prevent spreading."
        elif "fever" in symptoms and "stiff neck" in symptoms and "headache" in symptoms:
            result = "Possible Meningitis"
            recommendation = "Seek immediate medical care. This may be life-threatening."
        elif "diarrhea" in symptoms or "vomiting" in symptoms or "stomach pain" in symptoms:
            result = "Possible Food Poisoning"
            recommendation = "Drink oral rehydration solution. Seek medical care if severe."
        elif "painful urination" in symptoms or "frequent urination" in symptoms:
            result = "Possible Urinary Tract Infection (UTI)"
            recommendation = "Consult a doctor for urine tests and antibiotics."
        elif "joint pain" in symptoms or "swelling" in symptoms:
            result = "Possible Arthritis"
            recommendation = "Consult a doctor for diagnosis and pain management."
        elif "persistent cough" in symptoms or "blood in sputum" in symptoms:
            result = "Possible Tuberculosis (TB)"
            recommendation = "Visit a hospital for TB testing immediately."
        elif "fatigue" in symptoms and "pale skin" in symptoms:
            result = "Possible Anemia"
            recommendation = "Get a blood test. Increase iron-rich foods in your diet."
        else:
            result = "No specific diagnosis found"
            recommendation = "Please consult a healthcare professional for accurate diagnosis."

    return render_template("diagnosis.html", result=result, recommendation=recommendation)


# Doctors page
@app.route('/doctors')
def doctors():
    selected_region = request.args.get('region', '').lower()
    doctors_list = []

    with open('static/ghana_doctors.csv', newline='', encoding='utf-8') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            if selected_region and row['region'].lower() != selected_region:
                continue
            # Generate avatar URL based on doctor name
            name_for_avatar = urllib.parse.quote(row['name'])
            row['avatar_url'] = f"https://ui-avatars.com/api/?name={name_for_avatar}&background=0D8ABC&color=fff&size=200"
            doctors_list.append(row)

    return render_template('doctors.html', doctors=doctors_list, selected_region=selected_region)


# Appointment Booking
@app.route("/appointment", methods=["GET", "POST"])
def appointment():
    if "user_id" not in session:
        return redirect(url_for("login"))

    # Get the doctor name from query parameters
    doctor_name = request.args.get("doctor_name", "")
    current_date = date.today().isoformat()

    if request.method == "POST":
        name = request.form["name"]
        date_selected = request.form["date"]
        doctor_selected = request.form["doctor"]

        conn = sqlite3.connect("database.db")
        c = conn.cursor()
        c.execute(
            "INSERT INTO appointments (user_id, doctor, date, name) VALUES (?, ?, ?, ?)",
            (session["user_id"], doctor_selected, date_selected, name)
        )
        conn.commit()
        conn.close()

        flash(f"Appointment booked with {doctor_selected} for {name} on {date_selected}", "success")
        return redirect(url_for("dashboard"))

    return render_template("appointment.html", doctor=doctor_name, current_date=current_date)


# Health Tips Page
@app.route("/tips")
def tips():
    if "user_id" not in session:
        return redirect(url_for("login"))
    tips_list = [
        "Drink at least 8 glasses of water daily.",
        "Exercise regularly for at least 30 minutes.",
        "Eat a balanced diet rich in fruits and vegetables.",
        "Get 7-8 hours of sleep every night."
    ]
    return render_template("tips.html", tips=tips_list)


# Profile
@app.route("/profile")
def profile():
    if "user_id" not in session:
        return redirect(url_for("login"))
    return render_template("profile.html", username=session.get("full_name"))


# Account (Profile + Change Password)
@app.route("/account", methods=["GET", "POST"])
def account():
    if request.method == "POST":
        full_name = request.form["full_name"]
        phone = request.form["phone"]
        email = request.form["email"]

        conn = sqlite3.connect("database.db")
        c = conn.cursor()

        # ✅ Update profile details
        c.execute("""
            UPDATE users 
            SET full_name = ?, phone = ?, email = ?
            WHERE id = ?
        """, (full_name, phone, email, session["user_id"]))
        conn.commit()

        # ✅ Password change request
        old_password = request.form.get("old_password")
        new_password = request.form.get("new_password")
        confirm_new_password = request.form.get("confirm_new_password")

        if old_password and new_password and confirm_new_password:
            # Get stored hashed password
            c.execute("SELECT password FROM users WHERE id = ?", (session["user_id"],))
            stored_password = c.fetchone()[0]

            # Check old password matches
            if not check_password_hash(stored_password, old_password):
                conn.close()
                flash("Old password is incorrect!", "danger")
                return redirect(url_for("account"))

            # Check new passwords match
            if new_password != confirm_new_password:
                conn.close()
                flash("New passwords do not match!", "danger")
                return redirect(url_for("account"))

            # Check password strength
            if not is_strong_password(new_password):
                conn.close()
                flash("Password must be at least 8 chars, include uppercase, lowercase, number, and symbol.", "danger")
                return redirect(url_for("account"))

            # Save new hashed password
            hashed_pw = generate_password_hash(new_password, method="pbkdf2:sha256")
            c.execute("UPDATE users SET password = ? WHERE id = ?", (hashed_pw, session["user_id"]))
            conn.commit()
            flash("Password updated successfully!", "success")

        conn.close()
        flash("Account updated successfully!", "success")
        return redirect(url_for("account"))

    # Fetch user details
    conn = sqlite3.connect("database.db")
    c = conn.cursor()
    c.execute("SELECT full_name, phone, email FROM users WHERE id = ?", (session["user_id"],))
    user = c.fetchone()
    conn.close()

    return render_template("account.html", user=user)


if __name__ == "__main__":
    app.run(debug=True)
