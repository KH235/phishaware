import ipaddress
import json
import os
import re
from urllib.parse import urlsplit
from flask_wtf.csrf import CSRFProtect

from dotenv import load_dotenv
from flask import Flask, jsonify, redirect, render_template, request, url_for
from flask_login import (
    LoginManager,
    UserMixin,
    current_user,
    login_required,
    login_user,
    logout_user,
)
from mysql.connector import Error
from werkzeug.security import check_password_hash, generate_password_hash

from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from db import get_db_connection

load_dotenv()

app = Flask(__name__)

limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=[],
    storage_uri=os.getenv("RATELIMIT_STORAGE_URI", "memory://"),

)

app.config['SECRET_KEY'] = os.environ['SECRET_KEY']

app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = os.getenv(
    'SESSION_COOKIE_SECURE', 'false'
).lower() == 'true'

# Protect POST, PUT, PATCH and DELETE requests against CSRF
csrf = CSRFProtect(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'



class User(UserMixin):
    def __init__(self, user_id, username, email, is_admin=False):
        self.id = str(user_id)
        self.username = username
        self.email = email
        self.is_admin = bool(is_admin)


@login_manager.user_loader
def load_user(user_id):
    try:
        user_id = int(user_id)
    except (TypeError, ValueError):
        return None

    connection = None
    cursor = None
    try:
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)
        cursor.execute(
            'SELECT user_id, username, email, is_admin FROM users WHERE user_id = %s',
            (user_id,),
        )
        row = cursor.fetchone()
        return User(
    row['user_id'],
    row['username'],
    row['email'],
    row['is_admin']
) if row else None
    except Error:
        app.logger.exception('Failed to load user from database')
        return None
    finally:
        if cursor is not None:
            cursor.close()
        if connection is not None:
            connection.close()


@login_manager.unauthorized_handler
def unauthorized():
    if request.path.startswith('/api/'):
        return jsonify(error='Please log in to save scans.'), 401
    return redirect(url_for('login', next=request.path))


DEMO_REPORTS = [
    {'title': 'Impersonated account verification page', 'url': 'https://account-check.example', 'risk': 'HIGH', 'detail': 'Example community warning — demonstration data only.', 'time': 'DEMO'},
    {'title': 'Suspicious giveaway message', 'url': 'https://prize-notice.example', 'risk': 'MEDIUM', 'detail': 'Example community warning — demonstration data only.', 'time': 'DEMO'},
    {'title': 'Fake delivery notification', 'url': 'https://parcel-alert.example', 'risk': 'HIGH', 'detail': 'Example community warning — demonstration data only.', 'time': 'DEMO'},
]




@app.get('/')
def home():
    connection = None
    cursor = None
    threats = []
    community_posts = []
    comments_by_post = {}
    incident_reports = []
    verification_requests = []
    cyber_lessons = []
    quiz_questions = []
    quiz_history = []
    quiz_chart_data = []
    quiz_stats = {
    "total_attempts": 0,
    "highest_percentage": 0,
    "average_percentage": 0
}

    try:
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)

        # MODULE 2 — LOAD THREAT INTELLIGENCE
        cursor.execute(
            """
            SELECT
                t.threat_id,
                t.url,
                t.threat_type,
                t.risk_level,
                t.description,
                t.created_at,
                t.reported_by AS reported_by_id,
                u.username AS reported_by
            FROM threat_intelligence AS t
            LEFT JOIN users AS u
                ON t.reported_by = u.user_id
            ORDER BY t.created_at DESC, t.threat_id DESC
            LIMIT 50
            """
        )

        threats = cursor.fetchall()

        # MODULE 3 — LOAD COMMUNITY POSTS
        cursor.execute(
            """
            SELECT
                p.post_id,
                p.user_id,
                p.title,
                p.category,
                p.content,
                p.created_at,
                p.updated_at,
                u.username AS author
            FROM community_posts AS p
            LEFT JOIN users AS u
                ON p.user_id = u.user_id
            ORDER BY p.created_at DESC, p.post_id DESC
            LIMIT 50
            """
        )

        community_posts = cursor.fetchall()


        # MODULE 4 — Load comments for community posts
        cursor.execute("""
            SELECT
                c.comment_id,
                c.post_id,
                c.user_id,
                c.content,
                c.created_at,
                c.updated_at,
                u.username AS author
            FROM community_comments AS c
            LEFT JOIN users AS u ON c.user_id = u.user_id
            ORDER BY c.created_at ASC, c.comment_id ASC
        """)

        all_comments = cursor.fetchall()

        comments_by_post = {}

        for comment in all_comments:
            post_id = comment["post_id"]
            comments_by_post.setdefault(post_id, []).append(comment)


        # ==========================================
        # MODULE 5 — LOAD PUBLIC INCIDENT REPORTS
        # ==========================================

        cursor.execute("""
            SELECT
                i.incident_id,
                i.user_id,
                i.title,
                i.incident_type,
                i.description,
                i.incident_date,
                i.status,
                i.created_at,
                i.updated_at,
                u.username AS reported_by
            FROM incident_reports AS i
            LEFT JOIN users AS u ON i.user_id = u.user_id
            ORDER BY i.created_at DESC, i.incident_id DESC
            LIMIT 50
        """)

        incident_reports = cursor.fetchall()

        # ==========================================
        # MODULE 6 — LOAD VERIFICATION REQUESTS
        # ==========================================

        cursor.execute(
            """
            SELECT
                v.verification_id,
                v.user_id,
                v.suspicious_url,
                v.description,
                v.verification_status,
                v.submitted_at,
                v.updated_at,
                u.username AS submitted_by
            FROM threat_verifications AS v
            LEFT JOIN users AS u
                ON v.user_id = u.user_id
            ORDER BY v.submitted_at DESC, v.verification_id DESC
            LIMIT 50
            """
        )

        verification_requests = cursor.fetchall()


        # ==========================================
        # MODULE 7 — LOAD CYBER LEARNING LESSONS
        # ==========================================

        cursor.execute(
            """
            SELECT
                lesson_id,
                title,
                category,
                content,
                created_at,
                updated_at
            FROM cyber_lessons
            ORDER BY created_at DESC, lesson_id DESC
            LIMIT 50
            """
        )

        cyber_lessons = cursor.fetchall()


        # ==========================================
        # MODULE 8 — LOAD SECURITY QUIZ QUESTIONS
        # ==========================================

        cursor.execute("""
            SELECT
                question_id,
                question_text,
                option_a,
                option_b,
                option_c,
                option_d,
                correct_answer,
                explanation,
                created_at,
                updated_at
            FROM quiz_questions
            ORDER BY question_id ASC
            LIMIT 50
        """)

        quiz_questions = cursor.fetchall()



        # MODULE 8 — LOAD PERSONAL QUIZ HISTORY
        if current_user.is_authenticated:
            history_connection = None
            history_cursor = None

            try:
                history_connection = get_db_connection()
                history_cursor = history_connection.cursor(dictionary=True)

                history_cursor.execute("""
                    SELECT
                        score_id,
                        score,
                        total_questions,
                        percentage,
                        completed_at
                    FROM quiz_scores
                    WHERE user_id = %s
                    ORDER BY completed_at DESC, score_id DESC
                    LIMIT 20
                """, (current_user.id,))

                quiz_history = history_cursor.fetchall()


                # MODULE 8 — QUIZ PERFORMANCE CHART DATA
                history_cursor.execute("""
                    SELECT
                        score_id,
                        percentage,
                        completed_at
                    FROM (
                        SELECT
                            score_id,
                            percentage,
                            completed_at
                        FROM quiz_scores
                        WHERE user_id = %s
                        ORDER BY completed_at DESC, score_id DESC
                        LIMIT 10
                    ) AS recent_attempts
                    ORDER BY completed_at ASC, score_id ASC
                """, (current_user.id,))

                chart_rows = history_cursor.fetchall()

                quiz_chart_data = [
                    {
                        "attempt": index + 1,
                        "percentage": float(row["percentage"])
                    }
                    for index, row in enumerate(chart_rows)
                ]



                # MODULE 8 — QUIZ PROGRESS STATISTICS
                history_cursor.execute("""
                    SELECT
                        COUNT(*) AS total_attempts,
                        COALESCE(MAX(percentage), 0) AS highest_percentage,
                        COALESCE(AVG(percentage), 0) AS average_percentage
                    FROM quiz_scores
                    WHERE user_id = %s
                """, (current_user.id,))

                stats_row = history_cursor.fetchone()

                if stats_row:
                    quiz_stats = {
                        "total_attempts": stats_row["total_attempts"],
                        "highest_percentage": round(
                            float(stats_row["highest_percentage"]), 1
                        ),
                        "average_percentage": round(
                            float(stats_row["average_percentage"]), 1
                        )
                    }

            except Error:
                app.logger.exception("Failed to load quiz history")

            finally:
                if history_cursor is not None:
                    history_cursor.close()

                if history_connection is not None and history_connection.is_connected():
                    history_connection.close()




    except Error:
         app.logger.exception("Failed to load dashboard records")
    finally:
        if cursor is not None:
             cursor.close()

        if connection is not None and connection.is_connected():
             connection.close()

    return render_template(
          'index.html',
           reports=DEMO_REPORTS,
           threats=threats,
           community_posts=community_posts,
           comments_by_post=comments_by_post,
           incident_reports=incident_reports,
           verification_requests=verification_requests,
           cyber_lessons=cyber_lessons,
           quiz_questions=quiz_questions,
           quiz_history=quiz_history,
           quiz_stats=quiz_stats,
           quiz_chart_data=quiz_chart_data,
        )



@app.post('/api/scan')
def scan():
    payload = request.get_json(silent=True) or {}
    raw = str(payload.get('url', '')).strip()
    if not raw or len(raw) > 2048:
        return jsonify(error='Enter a URL of up to 2048 characters.'), 400
    if any(c.isspace() for c in raw):
        return jsonify(error='URL must not contain spaces.'), 400

    candidate = raw if '://' in raw else 'https://' + raw
    try:
        parts = urlsplit(candidate)
        host = parts.hostname
        if parts.scheme not in ('http', 'https') or not host or parts.username or parts.password:
            raise ValueError()
        if not re.fullmatch(r'[A-Za-z0-9.\-:\[\]]+', parts.netloc):
            raise ValueError()
        if host == 'localhost' or host.endswith('.local'):
            raise ValueError()
    except (ValueError, TypeError):
        return jsonify(error='Enter a valid public HTTP or HTTPS URL.'), 400

    score, reasons = 0, []

    def add(points, message):
        nonlocal score
        score += points
        reasons.append(message)

    if parts.scheme == 'http':
        add(15, 'Uses HTTP rather than HTTPS.')
    try:
        ipaddress.ip_address(host)
        add(30, 'Uses an IP address rather than a domain name.')
    except ValueError:
        pass
    if len(candidate) > 100:
        add(15, 'URL is unusually long.')
    if host.count('.') >= 3:
        add(15, 'Contains several subdomains.')
    if host.count('-') >= 3:
        add(15, 'Domain contains many hyphens.')
    if re.search(r'(verify|urgent|password|secure-login|account-update|confirm)', candidate, re.I):
        add(20, 'Contains keywords sometimes used in phishing lures.')
    if '@' in parts.path or '%40' in candidate.lower():
        add(10, 'Contains an encoded or unusual @ character.')

    score = min(score, 100)
    level = 'HIGH' if score >= 60 else 'MEDIUM' if score >= 30 else 'LOW'
    return jsonify(
        url=candidate,
        score=score,
        level=level,
        indicators=reasons or ['No configured lexical warning signs were found.'],
        disclaimer='Educational heuristic only. A LOW score does not mean the site is safe. No live reputation check was performed.',
    )


@app.post('/api/scans')
@login_required
def save_scan():
    payload = request.get_json(silent=True) or {}
    raw_url = payload.get('url', '')
    if not isinstance(raw_url, str):
        return jsonify(error='URL must be text.'), 400

    # Reuse the scanner logic without creating a second HTTP request.
# The original browser request has already passed CSRF validation.
    with app.test_request_context(
        '/api/scan',
        method='POST',
        json={'url': raw_url}
    ):
        scan_response = scan()

    if isinstance(scan_response, tuple):
        response, status = scan_response
        if status != 200:
            return response, status
        scan_response = response
    if scan_response.status_code != 200:
        return scan_response
    result = scan_response.get_json()

    connection = None
    cursor = None
    try:
        connection = get_db_connection()
        cursor = connection.cursor()
        cursor.execute(
    """
    INSERT INTO url_scans
        (user_id, url, risk_score, risk_level, indicators)
    VALUES
        (%s, %s, %s, %s, %s)
    """,
    (
        int(current_user.id),
        result["url"],
        result["score"],
        result["level"],
        json.dumps(result["indicators"]),
    ),
)
        connection.commit()
        return jsonify(**result, message='Scan saved successfully.', scan_id=cursor.lastrowid), 201
    except Error:
        if connection is not None:
            connection.rollback()
        app.logger.exception('Failed to save URL scan')
        return jsonify(error='Unable to save scan.'), 500
    finally:
        if cursor is not None:
            cursor.close()
        if connection is not None and connection.is_connected():
            connection.close()

@app.get('/scans')
@login_required
def scan_history():
    connection = None
    cursor = None

    try:
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)

        cursor.execute(
            """
            SELECT scan_id, url, risk_score, risk_level, scan_notes, scanned_at
            FROM url_scans
            WHERE user_id = %s
            ORDER BY scanned_at DESC, scan_id DESC
            LIMIT 100
            """,
            (int(current_user.id),)
        )

        return render_template(
            'scan_history.html',
            scans=cursor.fetchall()
        )

    except Error:
        app.logger.exception('Failed to load scan history')
        return 'Unable to load scan history.', 500

    finally:
        if cursor is not None:
            cursor.close()

        if connection is not None and connection.is_connected():
            connection.close()


@app.post('/scans/<int:scan_id>/notes')
@login_required
def update_scan_notes(scan_id):
    notes = request.form.get('scan_notes', '').strip()
    if len(notes) > 1000:
        return 'Notes must be 1000 characters or fewer.', 400

    connection = None
    cursor = None
    try:
        connection = get_db_connection()
        cursor = connection.cursor()

        cursor.execute(
            'UPDATE url_scans SET scan_notes = %s WHERE scan_id = %s AND user_id = %s',
            (notes, scan_id, current_user.id),
        )

        connection.commit()
        return redirect(url_for('scan_history'))
    except Error:
        if connection is not None:
            connection.rollback()
        app.logger.exception('Failed to update scan notes')
        return 'Unable to update scan notes.', 500
    finally:
        if cursor is not None:
            cursor.close()
        if connection is not None and connection.is_connected():
            connection.close()


@app.post('/scans/<int:scan_id>/delete')
@login_required
def delete_scan(scan_id):
    connection = None
    cursor = None
    try:
        connection = get_db_connection()
        cursor = connection.cursor()

        cursor.execute(
            'DELETE FROM url_scans WHERE scan_id = %s AND user_id = %s',
            (scan_id, current_user.id),
        )

        connection.commit()
        return redirect(url_for('scan_history'))
    except Error:
        if connection is not None:
            connection.rollback()
        app.logger.exception('Failed to delete scan')
        return 'Unable to delete scan.', 500
    finally:
        if cursor is not None:
            cursor.close()
        if connection is not None and connection.is_connected():
            connection.close()
@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("home"))

    error = None

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        if not username or not email or not password:
            error = "Please fill in all fields."

        elif len(username) > 50 or len(email) > 255:
            error = "Username or email is too long."

        elif len(password) < 8:
            error = "Password must contain at least 8 characters."

        elif password != confirm_password:
            error = "Passwords do not match."

        else:
            conn = None
            cursor = None

            try:
                conn = get_db_connection()
                cursor = conn.cursor()

                cursor.execute(
                    """
                    SELECT user_id
                    FROM users
                    WHERE username = %s OR email = %s
                    """,
                    (username, email)
                )

                if cursor.fetchone():
                    error = "Username or email is already registered."

                else:
                    password_hash = generate_password_hash(password)

                    cursor.execute(
                        """
                        INSERT INTO users (username, email, password_hash)
                        VALUES (%s, %s, %s)
                        """,
                        (username, email, password_hash)
                    )

                    conn.commit()

                    return redirect(url_for("login"))

            except Exception as e:
                     app.logger.exception("Registration failed")
                     error = "Registration failed. Please try again."

            finally:
                if cursor is not None:
                    cursor.close()

                if conn is not None:
                    conn.close()

    return render_template("register.html", error=error)

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute", methods=["POST"])
def login():

    if current_user.is_authenticated:
        return redirect(url_for('home'))

    error = None
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        if not username or not password:
            error = 'Please enter your username and password.'
        else:
            connection = None
            cursor = None
            try:
                connection = get_db_connection()
                cursor = connection.cursor(dictionary=True)
                cursor.execute(
                    'SELECT user_id, username, email, password_hash FROM users WHERE username = %s',
                    (username,),
                )
                row = cursor.fetchone()
                if row and check_password_hash(row['password_hash'], password):
                    login_user(User(row['user_id'], row['username'], row['email']))
                    return redirect(url_for('home'))
                error = 'Invalid username or password.'
            except Error:
                app.logger.exception('Login database error')
                error = 'Login is temporarily unavailable.'
            finally:
                if cursor is not None:
                    cursor.close()
                if connection is not None:
                    connection.close()
    return render_template('login.html', error=error)

@app.post("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("home"))



# ==========================================
# MODULE 2 — THREAT INTELLIGENCE DATABASE
# CREATE: Add a new threat
# ==========================================

@app.post("/threats/add")
@login_required
def add_threat():
    url = request.form.get("url", "").strip()
    threat_type = request.form.get("threat_type", "").strip()
    risk_level = request.form.get("risk_level", "").strip().upper()
    description = request.form.get("description", "").strip()

    if (
        not url
        or len(url) > 2048
        or not threat_type
        or len(threat_type) > 100
        or risk_level not in ("LOW", "MEDIUM", "HIGH")
    ):
        return "Please enter valid threat information.", 400

    # Validate the URL format without visiting the website.
    try:
        parts = urlsplit(url)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            return "Please enter a valid HTTP or HTTPS URL.", 400
    except ValueError:
        return "Please enter a valid URL.", 400

    connection = None
    cursor = None

    try:
        connection = get_db_connection()
        cursor = connection.cursor()

        cursor.execute(
            """
            INSERT INTO threat_intelligence
                (url, threat_type, risk_level, description, reported_by)
            VALUES (%s, %s, %s, %s, %s)
            """,
            (
                url,
                threat_type,
                risk_level,
                description,
                int(current_user.id),
            ),
        )

        connection.commit()

        return redirect(url_for("home") + "#intel")

    except Error:
        if connection is not None:
            connection.rollback()

        app.logger.exception("Failed to add threat")
        return "Unable to add threat. Please try again.", 500

    finally:
        if cursor is not None:
            cursor.close()

        if connection is not None and connection.is_connected():
            connection.close()


# MODULE 2 — EDIT THREAT REPORT

@app.post("/threats/<int:threat_id>/edit")
@login_required
def edit_threat(threat_id):
    url = request.form.get("url", "").strip()
    threat_type = request.form.get("threat_type", "").strip()
    risk_level = request.form.get("risk_level", "").strip().upper()
    description = request.form.get("description", "").strip()

    if (
        not url
        or len(url) > 2048
        or not threat_type
        or len(threat_type) > 100
        or risk_level not in ("LOW", "MEDIUM", "HIGH")
    ):
        return "Please enter valid threat information.", 400

    try:
        parts = urlsplit(url)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            return "Please enter a valid HTTP or HTTPS URL.", 400
    except ValueError:
        return "Please enter a valid URL.", 400

    connection = None
    cursor = None

    try:
        connection = get_db_connection()
        cursor = connection.cursor()

                # Check that the report exists and belongs to this user.
        cursor.execute(
            """
            SELECT threat_id
            FROM threat_intelligence
            WHERE threat_id = %s AND reported_by = %s
            """,
            (threat_id, int(current_user.id)),
        )

        if cursor.fetchone() is None:
            return "Threat report not found or permission denied.", 404

        cursor.execute(
            """
            UPDATE threat_intelligence
            SET url = %s,
                threat_type = %s,
                risk_level = %s,
                description = %s
            WHERE threat_id = %s
              AND reported_by = %s
            """,
            (
                url,
                threat_type,
                risk_level,
                description,
                threat_id,
                int(current_user.id),
            ),
        )

        connection.commit()

        return redirect(url_for("home") + "#intel")

    except Error:
        if connection is not None:
            connection.rollback()

        app.logger.exception("Failed to edit threat")
        return "Unable to edit threat. Please try again.", 500

    finally:
        if cursor is not None:
            cursor.close()

        if connection is not None and connection.is_connected():
            connection.close()


# MODULE 2 — DELETE THREAT REPORT

@app.post("/threats/<int:threat_id>/delete")
@login_required
def delete_threat(threat_id):
    connection = None
    cursor = None

    try:
        connection = get_db_connection()
        cursor = connection.cursor()

        cursor.execute(
            """
            DELETE FROM threat_intelligence
            WHERE threat_id = %s
              AND reported_by = %s
            """,
            (threat_id, int(current_user.id)),
        )

        deleted_count = cursor.rowcount
        connection.commit()

        if deleted_count == 0:
            return "Threat report not found or permission denied.", 404

        return redirect(url_for("home") + "#intel")

    except Error:
        if connection is not None:
            connection.rollback()

        app.logger.exception("Failed to delete threat")
        return "Unable to delete threat. Please try again.", 500

    finally:
        if cursor is not None:
            cursor.close()

        if connection is not None and connection.is_connected():
            connection.close()


# ==========================================
# MODULE 3 — CREATE COMMUNITY POST
# ==========================================

@app.post("/community/posts/add")
@login_required
def add_community_post():
    title = request.form.get("title", "").strip()
    category = request.form.get("category", "").strip()
    content = request.form.get("content", "").strip()

    allowed_categories = (
        "Phishing Alert",
        "Scam Warning",
        "Malware Alert",
        "Security Tips",
        "General Discussion",
    )

    if not title or len(title) > 200:
        return "Please enter a valid post title (maximum 200 characters).", 400

    if category not in allowed_categories:
        return "Please select a valid post category.", 400

    if not content or len(content) > 10000:
        return "Post content must contain between 1 and 10000 characters.", 400

    connection = None
    cursor = None

    try:
        connection = get_db_connection()
        cursor = connection.cursor()

        cursor.execute(
            """
            INSERT INTO community_posts
                (user_id, title, category, content)
            VALUES (%s, %s, %s, %s)
            """,
            (
                int(current_user.id),
                title,
                category,
                content,
            ),
        )

        connection.commit()

        return redirect(url_for("home") + "#community")

    except Error:
        if connection is not None:
            connection.rollback()

        app.logger.exception("Failed to publish community post")
        return "Unable to publish your post. Please try again.", 500

    finally:
        if cursor is not None:
            cursor.close()

        if connection is not None and connection.is_connected():
            connection.close()


# ==========================================
# MODULE 3 — EDIT COMMUNITY POST
# ==========================================

@app.post("/community/posts/<int:post_id>/edit")
@login_required
def edit_community_post(post_id):
    title = request.form.get("title", "").strip()
    category = request.form.get("category", "").strip()
    content = request.form.get("content", "").strip()

    allowed_categories = (
        "Phishing Alert",
        "Scam Warning",
        "Malware Alert",
        "Security Tips",
        "General Discussion",
    )

    if not title or len(title) > 200:
        return "Please enter a valid post title (maximum 200 characters).", 400

    if category not in allowed_categories:
        return "Please select a valid post category.", 400

    if not content or len(content) > 10000:
        return "Post content must contain between 1 and 10000 characters.", 400

    connection = None
    cursor = None

    try:
        connection = get_db_connection()
        cursor = connection.cursor()

        # Check ownership before editing.
        cursor.execute(
            """
            SELECT post_id
            FROM community_posts
            WHERE post_id = %s AND user_id = %s
            """,
            (post_id, int(current_user.id)),
        )

        if cursor.fetchone() is None:
            return "Post not found or permission denied.", 404

        cursor.execute(
            """
            UPDATE community_posts
            SET title = %s,
                category = %s,
                content = %s
            WHERE post_id = %s AND user_id = %s
            """,
            (
                title,
                category,
                content,
                post_id,
                int(current_user.id),
            ),
        )

        connection.commit()

        return redirect(url_for("home") + "#community")

    except Error:
        if connection is not None:
            connection.rollback()

        app.logger.exception("Failed to edit community post")
        return "Unable to update your post. Please try again.", 500

    finally:
        if cursor is not None:
            cursor.close()

        if connection is not None and connection.is_connected():
            connection.close()


# ==========================================
# MODULE 3 — DELETE COMMUNITY POST
# ==========================================

@app.post("/community/posts/<int:post_id>/delete")
@login_required
def delete_community_post(post_id):
    connection = None
    cursor = None

    try:
        connection = get_db_connection()
        cursor = connection.cursor()

        # Only the post owner can delete it.
        cursor.execute(
            """
            SELECT post_id
            FROM community_posts
            WHERE post_id = %s AND user_id = %s
            """,
            (post_id, int(current_user.id)),
        )

        if cursor.fetchone() is None:
            return "Post not found or permission denied.", 404

        cursor.execute(
            """
            DELETE FROM community_posts
            WHERE post_id = %s AND user_id = %s
            """,
            (post_id, int(current_user.id)),
        )

        connection.commit()

        return redirect(url_for("home") + "#community")

    except Error:
        if connection is not None:
            connection.rollback()

        app.logger.exception("Failed to delete community post")
        return "Unable to delete your post. Please try again.", 500

    finally:
        if cursor is not None:
            cursor.close()

        if connection is not None and connection.is_connected():
            connection.close()


# ==========================================
# MODULE 4 — ADD COMMUNITY COMMENT
# ==========================================

@app.post("/community/posts/<int:post_id>/comments/add")
@login_required
def add_community_comment(post_id):
    content = request.form.get("content", "").strip()

    if not content or len(content) > 2000:
        return "Comment must contain between 1 and 2000 characters.", 400

    connection = None
    cursor = None

    try:
        connection = get_db_connection()
        cursor = connection.cursor()

        # Check that the community post exists.
        cursor.execute(
            """
            SELECT post_id
            FROM community_posts
            WHERE post_id = %s
            """,
            (post_id,),
        )

        if cursor.fetchone() is None:
            return "Community post not found.", 404

        # Save the comment.
        cursor.execute(
            """
            INSERT INTO community_comments
                (post_id, user_id, content)
            VALUES (%s, %s, %s)
            """,
            (
                post_id,
                int(current_user.id),
                content,
            ),
        )

        connection.commit()

        return redirect(url_for("home") + "#community")

    except Error:
        if connection is not None:
            connection.rollback()

        app.logger.exception("Failed to add community comment")
        return "Unable to post your comment. Please try again.", 500

    finally:
        if cursor is not None:
            cursor.close()

        if connection is not None and connection.is_connected():
            connection.close()


# ==========================================
# MODULE 4 — EDIT COMMUNITY COMMENT
# ==========================================

@app.post("/community/comments/<int:comment_id>/edit")
@login_required
def edit_community_comment(comment_id):
    content = request.form.get("content", "").strip()

    if not content or len(content) > 2000:
        return "Comment must contain between 1 and 2000 characters.", 400

    connection = None
    cursor = None

    try:
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)

        cursor.execute(
            """
            SELECT user_id
            FROM community_comments
            WHERE comment_id = %s
            """,
            (comment_id,),
        )

        comment = cursor.fetchone()

        if comment is None:
            return "Comment not found.", 404

        if int(comment["user_id"]) != int(current_user.id):
            return "You can only edit your own comments.", 403

        cursor.execute(
            """
            UPDATE community_comments
            SET content = %s
            WHERE comment_id = %s AND user_id = %s
            """,
            (content, comment_id, int(current_user.id)),
        )

        connection.commit()

        return redirect(url_for("home") + "#community")

    except Error:
        if connection is not None:
            connection.rollback()

        app.logger.exception("Failed to edit community comment")
        return "Unable to update your comment. Please try again.", 500

    finally:
        if cursor is not None:
            cursor.close()

        if connection is not None and connection.is_connected():
            connection.close()


# ==========================================
# MODULE 4 — DELETE COMMUNITY COMMENT
# ==========================================

@app.post("/community/comments/<int:comment_id>/delete")
@login_required
def delete_community_comment(comment_id):
    connection = None
    cursor = None

    try:
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)

        # Check who owns the comment.
        cursor.execute(
            """
            SELECT user_id
            FROM community_comments
            WHERE comment_id = %s
            """,
            (comment_id,),
        )

        comment = cursor.fetchone()

        if comment is None:
            return "Comment not found.", 404

        if int(comment["user_id"]) != int(current_user.id):
            return "You can only delete your own comments.", 403

        # Delete only this comment.
        cursor.execute(
            """
            DELETE FROM community_comments
            WHERE comment_id = %s AND user_id = %s
            """,
            (comment_id, int(current_user.id)),
        )

        connection.commit()

        return redirect(url_for("home") + "#community")

    except Error:
        if connection is not None:
            connection.rollback()

        app.logger.exception("Failed to delete community comment")
        return "Unable to delete your comment. Please try again.", 500

    finally:
        if cursor is not None:
            cursor.close()

        if connection is not None and connection.is_connected():
            connection.close()


# ==========================================
# MODULE 5 — ADD INCIDENT REPORT
# ==========================================

@app.post("/incidents/add")
@login_required
def add_incident():
    title = request.form.get("title", "").strip()
    incident_type = request.form.get("incident_type", "").strip()
    description = request.form.get("description", "").strip()
    incident_date = request.form.get("incident_date", "").strip()

    valid_types = {
        "Phishing",
        "Online Scam",
        "Account Compromise",
        "Malware",
        "Identity Theft",
        "Other"
    }

    if not title or len(title) > 200:
        return "Title must contain between 1 and 200 characters.", 400

    if incident_type not in valid_types:
        return "Please select a valid incident type.", 400

    if not description:
        return "Incident description is required.", 400

    try:
        from datetime import date
        parsed_date = date.fromisoformat(incident_date)

        if parsed_date > date.today():
            return "Incident date cannot be in the future.", 400

    except ValueError:
        return "Please enter a valid incident date.", 400

    connection = None
    cursor = None

    try:
        connection = get_db_connection()
        cursor = connection.cursor()

        cursor.execute(
            """
            INSERT INTO incident_reports
                (user_id, title, incident_type, description, incident_date)
            VALUES (%s, %s, %s, %s, %s)
            """,
            (
                int(current_user.id),
                title,
                incident_type,
                description,
                incident_date
            )
        )

        connection.commit()

        return redirect(url_for("home") + "#incident-reports")

    except Error:
        if connection is not None:
            connection.rollback()

        app.logger.exception("Failed to submit incident report")
        return "Unable to submit incident report. Please try again.", 500

    finally:
        if cursor is not None:
            cursor.close()

        if connection is not None and connection.is_connected():
            connection.close()


# ==========================================
# MODULE 5 — EDIT INCIDENT REPORT
# ==========================================

@app.post("/incidents/<int:incident_id>/edit")
@login_required
def edit_incident(incident_id):
    title = request.form.get("title", "").strip()
    incident_type = request.form.get("incident_type", "").strip()
    description = request.form.get("description", "").strip()
    incident_date = request.form.get("incident_date", "").strip()

    valid_types = {
        "Phishing",
        "Online Scam",
        "Account Compromise",
        "Malware",
        "Identity Theft",
        "Other"
    }

    if not title or len(title) > 200:
        return "Title must contain between 1 and 200 characters.", 400

    if incident_type not in valid_types:
        return "Please select a valid incident type.", 400

    if not description:
        return "Incident description is required.", 400

    try:
        from datetime import date
        parsed_date = date.fromisoformat(incident_date)

        if parsed_date > date.today():
            return "Incident date cannot be in the future.", 400
    except ValueError:
        return "Please enter a valid incident date.", 400

    connection = None
    cursor = None

    try:
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)

        cursor.execute(
            "SELECT user_id FROM incident_reports WHERE incident_id = %s",
            (incident_id,)
        )

        incident = cursor.fetchone()

        if incident is None:
            return "Incident report not found.", 404

        if int(incident["user_id"]) != int(current_user.id):
            return "You can only edit your own incident reports.", 403

        cursor.execute(
            """
            UPDATE incident_reports
            SET title = %s,
                incident_type = %s,
                description = %s,
                incident_date = %s
            WHERE incident_id = %s AND user_id = %s
            """,
            (
                title,
                incident_type,
                description,
                incident_date,
                incident_id,
                int(current_user.id)
            )
        )

        connection.commit()
        return redirect(url_for("home") + "#incident-reports")

    except Error:
        if connection is not None:
            connection.rollback()

        app.logger.exception("Failed to edit incident report")
        return "Unable to update incident report. Please try again.", 500

    finally:
        if cursor is not None:
            cursor.close()

        if connection is not None and connection.is_connected():
            connection.close()


# ==========================================
# MODULE 5 — DELETE INCIDENT REPORT
# ==========================================

@app.post("/incidents/<int:incident_id>/delete")
@login_required
def delete_incident(incident_id):
    connection = None
    cursor = None

    try:
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)

        # Check whether the incident exists and who owns it.
        cursor.execute(
            """
            SELECT user_id
            FROM incident_reports
            WHERE incident_id = %s
            """,
            (incident_id,)
        )

        incident = cursor.fetchone()

        if incident is None:
            return "Incident report not found.", 404

        if int(incident["user_id"]) != int(current_user.id):
            return "You can only delete your own incident reports.", 403

        # Delete only the selected incident.
        cursor.execute(
            """
            DELETE FROM incident_reports
            WHERE incident_id = %s AND user_id = %s
            """,
            (incident_id, int(current_user.id))
        )

        connection.commit()

        return redirect(url_for("home") + "#incident-reports")

    except Error:
        if connection is not None:
            connection.rollback()

        app.logger.exception("Failed to delete incident report")
        return "Unable to delete incident report. Please try again.", 500

    finally:
        if cursor is not None:
            cursor.close()

        if connection is not None and connection.is_connected():
            connection.close()


# ==========================================
# MODULE 6 — SUBMIT THREAT VERIFICATION
# ==========================================

@app.post("/verification/submit")
@login_required
def submit_verification():
    suspicious_url = request.form.get("suspicious_url", "").strip()
    description = request.form.get("description", "").strip()

    # Validate the submitted information.
    if not suspicious_url or len(suspicious_url) > 2048:
        return "URL must contain between 1 and 2048 characters.", 400

    if not (
        suspicious_url.lower().startswith("http://")
        or suspicious_url.lower().startswith("https://")
    ):
        return "Please enter a URL starting with http:// or https://", 400

    if not description:
        return "Please explain why this URL is suspicious.", 400

    connection = None
    cursor = None

    try:
        connection = get_db_connection()
        cursor = connection.cursor()

        cursor.execute(
            """
            INSERT INTO threat_verifications
                (user_id, suspicious_url, description)
            VALUES (%s, %s, %s)
            """,
            (
                int(current_user.id),
                suspicious_url,
                description
            )
        )

        connection.commit()

        return redirect(url_for("home") + "#threat-verification")

    except Error:
        if connection is not None:
            connection.rollback()

        app.logger.exception(
            "Failed to submit threat verification request"
        )

        return "Unable to submit verification request. Please try again.", 500

    finally:
        if cursor is not None:
            cursor.close()

        if connection is not None and connection.is_connected():
            connection.close()


# ==========================================
# MODULE 6 — EDIT VERIFICATION REQUEST
# ==========================================

@app.post("/verification/<int:verification_id>/edit")
@login_required
def edit_verification(verification_id):
    suspicious_url = request.form.get("suspicious_url", "").strip()
    description = request.form.get("description", "").strip()

    # Validate the updated information.
    if not suspicious_url or len(suspicious_url) > 2048:
        return "URL must contain between 1 and 2048 characters.", 400

    if not (
        suspicious_url.lower().startswith("http://")
        or suspicious_url.lower().startswith("https://")
    ):
        return "Please enter a URL starting with http:// or https://", 400

    if not description:
        return "Please explain why this URL is suspicious.", 400

    connection = None
    cursor = None

    try:
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)

        # Check ownership and verification status.
        cursor.execute(
            """
            SELECT user_id, verification_status
            FROM threat_verifications
            WHERE verification_id = %s
            """,
            (verification_id,)
        )

        verification = cursor.fetchone()

        if verification is None:
            return "Verification request not found.", 404

        if int(verification["user_id"]) != int(current_user.id):
            return "You can only edit your own verification requests.", 403

        if verification["verification_status"] != "Pending":
            return "Only pending verification requests can be edited.", 403

        # Update the request only if it is still pending.
        cursor.execute(
            """
            UPDATE threat_verifications
            SET suspicious_url = %s,
                description = %s
            WHERE verification_id = %s
              AND user_id = %s
              AND verification_status = 'Pending'
            """,
            (
                suspicious_url,
                description,
                verification_id,
                int(current_user.id)
            )
        )

        connection.commit()

        return redirect(url_for("home") + "#threat-verification")

    except Error:
        if connection is not None:
            connection.rollback()

        app.logger.exception("Failed to edit verification request")

        return "Unable to update verification request. Please try again.", 500

    finally:
        if cursor is not None:
            cursor.close()

        if connection is not None and connection.is_connected():
            connection.close()


# ==========================================
# MODULE 6 — DELETE VERIFICATION REQUEST
# ==========================================

@app.post("/verification/<int:verification_id>/delete")
@login_required
def delete_verification(verification_id):
    connection = None
    cursor = None

    try:
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)

        # Check that the request exists and belongs to this user.
        cursor.execute(
            """
            SELECT user_id, verification_status
            FROM threat_verifications
            WHERE verification_id = %s
            """,
            (verification_id,)
        )

        verification = cursor.fetchone()

        if verification is None:
            return "Verification request not found.", 404

        if int(verification["user_id"]) != int(current_user.id):
            return "You can only delete your own verification requests.", 403

        if verification["verification_status"] != "Pending":
            return "Only pending verification requests can be deleted.", 403

        # Delete only this user's pending request.
        cursor.execute(
            """
            DELETE FROM threat_verifications
            WHERE verification_id = %s
              AND user_id = %s
              AND verification_status = 'Pending'
            """,
            (verification_id, int(current_user.id))
        )

        connection.commit()

        return redirect(url_for("home") + "#threat-verification")

    except Error:
        if connection is not None:
            connection.rollback()

        app.logger.exception("Failed to delete verification request")
        return "Unable to delete verification request. Please try again.", 500

    finally:
        if cursor is not None:
            cursor.close()

        if connection is not None and connection.is_connected():
            connection.close()


# ==========================================
# MODULE 6 — ADMIN VERIFICATION DECISION
# ==========================================

@app.post("/verification/<int:verification_id>/review")
@login_required
def review_verification(verification_id):

    # Only administrators can review verification requests.
    if not current_user.is_admin:
        return "Administrator access required.", 403

    decision = request.form.get("decision", "").strip()

    valid_decisions = {"Verified Threat", "Safe"}

    if decision not in valid_decisions:
        return "Invalid verification decision.", 400

    connection = None
    cursor = None

    try:
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)

        # Lock the request while checking its current status.
        cursor.execute(
            """
            SELECT verification_status
            FROM threat_verifications
            WHERE verification_id = %s
            FOR UPDATE
            """,
            (verification_id,)
        )

        verification = cursor.fetchone()

        if verification is None:
            connection.rollback()
            return "Verification request not found.", 404

        if verification["verification_status"] != "Pending":
            connection.rollback()
            return "This request has already been reviewed.", 409

        # Record the administrator's decision.
        cursor.execute(
            """
            UPDATE threat_verifications
            SET verification_status = %s
            WHERE verification_id = %s
              AND verification_status = 'Pending'
            """,
            (decision, verification_id)
        )

        connection.commit()

        return redirect(url_for("home") + "#threat-verification")

    except Error:
        if connection is not None:
            connection.rollback()

        app.logger.exception(
            "Failed to review threat verification request"
        )

        return "Unable to review verification request. Please try again.", 500

    finally:
        if cursor is not None:
            cursor.close()

        if connection is not None and connection.is_connected():
            connection.close()


# ==========================================
# MODULE 7 — ADMIN ADD CYBER LESSON
# ==========================================

@app.post("/learning/add")
@login_required
def add_cyber_lesson():

    # Only administrators can publish lessons.
    if not current_user.is_admin:
        return "Administrator access required.", 403

    title = request.form.get("title", "").strip()
    category = request.form.get("category", "").strip()
    content = request.form.get("content", "").strip()

    valid_categories = {
        "Phishing Awareness",
        "Online Scams",
        "Password Security",
        "Social Engineering",
        "Malware Protection",
        "Safe Browsing"
    }

    # Validate the lesson information.
    if not title or len(title) > 200:
        return "Lesson title must contain between 1 and 200 characters.", 400

    if category not in valid_categories:
        return "Please select a valid lesson category.", 400

    if not content:
        return "Lesson content is required.", 400

    connection = None
    cursor = None

    try:
        connection = get_db_connection()
        cursor = connection.cursor()

        cursor.execute(
            """
            INSERT INTO cyber_lessons
                (title, category, content)
            VALUES (%s, %s, %s)
            """,
            (title, category, content)
        )

        connection.commit()

        return redirect(url_for("home") + "#cyber-learning")

    except Error:
        if connection is not None:
            connection.rollback()

        app.logger.exception("Failed to add cyber learning lesson")
        return "Unable to publish lesson. Please try again.", 500

    finally:
        if cursor is not None:
            cursor.close()

        if connection is not None and connection.is_connected():
            connection.close()


# ==========================================
# MODULE 7 — ADMIN EDIT CYBER LESSON
# ==========================================

@app.post("/learning/<int:lesson_id>/edit")
@login_required
def edit_cyber_lesson(lesson_id):

    if not current_user.is_admin:
        return "Administrator access required.", 403

    title = request.form.get("title", "").strip()
    category = request.form.get("category", "").strip()
    content = request.form.get("content", "").strip()

    valid_categories = {
        "Phishing Awareness",
        "Online Scams",
        "Password Security",
        "Social Engineering",
        "Malware Protection",
        "Safe Browsing"
    }

    if not title or len(title) > 200:
        return "Lesson title must contain between 1 and 200 characters.", 400

    if category not in valid_categories:
        return "Please select a valid lesson category.", 400

    if not content:
        return "Lesson content is required.", 400

    connection = None
    cursor = None

    try:
        connection = get_db_connection()
        cursor = connection.cursor()

        cursor.execute(
            """
            UPDATE cyber_lessons
            SET title = %s,
                category = %s,
                content = %s
            WHERE lesson_id = %s
            """,
            (title, category, content, lesson_id)
        )


        connection.commit()

        return redirect(url_for("home") + "#cyber-learning")

    except Error:
        if connection is not None:
            connection.rollback()

        app.logger.exception("Failed to edit cyber learning lesson")
        return "Unable to update lesson. Please try again.", 500

    finally:
        if cursor is not None:
            cursor.close()

        if connection is not None and connection.is_connected():
            connection.close()


# ==========================================
# MODULE 7 — ADMIN DELETE CYBER LESSON
# ==========================================

@app.post("/learning/<int:lesson_id>/delete")
@login_required
def delete_cyber_lesson(lesson_id):

    # Only administrators can delete lessons.
    if not current_user.is_admin:
        return "Administrator access required.", 403

    connection = None
    cursor = None

    try:
        connection = get_db_connection()
        cursor = connection.cursor()

        cursor.execute(
            """
            DELETE FROM cyber_lessons
            WHERE lesson_id = %s
            """,
            (lesson_id,)
        )

        if cursor.rowcount == 0:
            connection.rollback()
            return "Lesson not found.", 404

        connection.commit()

        return redirect(url_for("home") + "#cyber-learning")

    except Error:
        if connection is not None:
            connection.rollback()

        app.logger.exception("Failed to delete cyber learning lesson")
        return "Unable to delete lesson. Please try again.", 500

    finally:
        if cursor is not None:
            cursor.close()

        if connection is not None and connection.is_connected():
            connection.close()



# ==========================================
# MODULE 8 — ADMIN ADD QUIZ QUESTION
# ==========================================

@app.post("/quiz/questions/add")
@login_required
def add_quiz_question():

    if not current_user.is_admin:
        return "Administrator access required.", 403

    question_text = request.form.get("question_text", "").strip()

    option_a = request.form.get("option_a", "").strip()
    option_b = request.form.get("option_b", "").strip()
    option_c = request.form.get("option_c", "").strip()
    option_d = request.form.get("option_d", "").strip()

    correct_answer = request.form.get("correct_answer", "").strip().upper()
    explanation = request.form.get("explanation", "").strip()

    options = [option_a, option_b, option_c, option_d]

    if not question_text:
        return "Question text is required.", 400

    if any(not option or len(option) > 500 for option in options):
        return "Each answer option must contain between 1 and 500 characters.", 400

    if correct_answer not in {"A", "B", "C", "D"}:
        return "Please select a valid correct answer.", 400

    if not explanation:
        return "An explanation is required.", 400

    connection = None
    cursor = None

    try:
        connection = get_db_connection()
        cursor = connection.cursor()

        cursor.execute(
            """
            INSERT INTO quiz_questions (
                question_text,
                option_a,
                option_b,
                option_c,
                option_d,
                correct_answer,
                explanation
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            """,
            (
                question_text,
                option_a,
                option_b,
                option_c,
                option_d,
                correct_answer,
                explanation
            )
        )

        connection.commit()

        return redirect(url_for("home") + "#security-quiz")

    except Error:
        if connection is not None:
            connection.rollback()

        app.logger.exception("Failed to add security quiz question")
        return "Unable to publish quiz question. Please try again.", 500

    finally:
        if cursor is not None:
            cursor.close()

        if connection is not None and connection.is_connected():
            connection.close()


# ==========================================
# MODULE 8 — ADMIN EDIT QUIZ QUESTION
# ==========================================

@app.post("/quiz/questions/<int:question_id>/edit")
@login_required
def edit_quiz_question(question_id):

    if not current_user.is_admin:
        return "Administrator access required.", 403

    question_text = request.form.get("question_text", "").strip()

    option_a = request.form.get("option_a", "").strip()
    option_b = request.form.get("option_b", "").strip()
    option_c = request.form.get("option_c", "").strip()
    option_d = request.form.get("option_d", "").strip()

    correct_answer = request.form.get("correct_answer", "").strip().upper()
    explanation = request.form.get("explanation", "").strip()

    options = [option_a, option_b, option_c, option_d]

    if not question_text:
        return "Question text is required.", 400

    if any(not option or len(option) > 500 for option in options):
        return "Each answer option must contain between 1 and 500 characters.", 400

    if correct_answer not in {"A", "B", "C", "D"}:
        return "Please select a valid correct answer.", 400

    if not explanation:
        return "An answer explanation is required.", 400

    connection = None
    cursor = None

    try:
        connection = get_db_connection()
        cursor = connection.cursor()

        cursor.execute(
            """
            UPDATE quiz_questions
            SET
                question_text = %s,
                option_a = %s,
                option_b = %s,
                option_c = %s,
                option_d = %s,
                correct_answer = %s,
                explanation = %s
            WHERE question_id = %s
            """,
            (
                question_text,
                option_a,
                option_b,
                option_c,
                option_d,
                correct_answer,
                explanation,
                question_id
            )
        )

        connection.commit()

        return redirect(url_for("home") + "#security-quiz")

    except Error:
        if connection is not None:
            connection.rollback()

        app.logger.exception("Failed to edit security quiz question")
        return "Unable to update quiz question. Please try again.", 500

    finally:
        if cursor is not None:
            cursor.close()

        if connection is not None and connection.is_connected():
            connection.close()


# ==========================================
# MODULE 8 — ADMIN DELETE QUIZ QUESTION
# ==========================================

@app.post("/quiz/questions/<int:question_id>/delete")
@login_required
def delete_quiz_question(question_id):

    # Only administrators can delete quiz questions.
    if not current_user.is_admin:
        return "Administrator access required.", 403

    connection = None
    cursor = None

    try:
        connection = get_db_connection()
        cursor = connection.cursor()

        cursor.execute(
            """
            DELETE FROM quiz_questions
            WHERE question_id = %s
            """,
            (question_id,)
        )

        if cursor.rowcount == 0:
            connection.rollback()
            return "Quiz question not found.", 404

        connection.commit()

        return redirect(url_for("home") + "#security-quiz")

    except Error:
        if connection is not None:
            connection.rollback()

        app.logger.exception("Failed to delete security quiz question")
        return "Unable to delete quiz question. Please try again.", 500

    finally:
        if cursor is not None:
            cursor.close()

        if connection is not None and connection.is_connected():
            connection.close()


# ==========================================
# MODULE 8 — SECURITY QUIZ SCORING
# ==========================================

@app.post("/quiz/submit")
def submit_security_quiz():
    connection = None
    cursor = None

    try:
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)

        cursor.execute("""
            SELECT question_id, correct_answer, explanation
            FROM quiz_questions
            ORDER BY question_id ASC
            LIMIT 50
        """)

        questions = cursor.fetchall()

        if not questions:
            return jsonify({
                "success": False,
                "message": "No quiz questions are available."
            }), 400

        submitted_answers = request.get_json(silent=True)

        if not isinstance(submitted_answers, dict):
            return jsonify({
                "success": False,
                "message": "Invalid quiz submission."
            }), 400

        answers = submitted_answers.get("answers")

        if not isinstance(answers, dict):
            return jsonify({
                "success": False,
                "message": "Invalid quiz answers."
            }), 400

        score = 0
        results = []

        for question in questions:
            question_id = question["question_id"]
            selected = answers.get(str(question_id), "")

            if selected not in ("A", "B", "C", "D"):
                selected = None

            correct = question["correct_answer"]
            is_correct = selected == correct

            if is_correct:
                score += 1

            results.append({
                "question_id": question_id,
                "selected_answer": selected,
                "correct_answer": correct,
                "is_correct": is_correct,
                "explanation": question["explanation"]
            })

        total = len(questions)
        percentage = round((score / total) * 100)


        # Save quiz score history for logged-in users
        if current_user.is_authenticated:
            cursor.execute("""
                INSERT INTO quiz_scores
                    (user_id, score, total_questions, percentage)
                VALUES (%s, %s, %s, %s)
            """, (
                current_user.id,
                score,
                total,
                percentage
            ))

            connection.commit()


        return jsonify({
            "success": True,
            "score": score,
            "total": total,
            "percentage": percentage,
            "results": results
        })

    except Error:
        app.logger.exception("Failed to score security quiz")
        return jsonify({
            "success": False,
            "message": "Unable to score quiz. Please try again."
        }), 500

    finally:
        if cursor is not None:
            cursor.close()

        if connection is not None and connection.is_connected():
            connection.close()


if __name__ == '__main__':
    app.run(debug=False)
