import ipaddress
import json
import os
import re
from datetime import date
from urllib.parse import urlsplit
from flask_wtf.csrf import CSRFProtect

from dotenv import load_dotenv
from flask import Flask, flash, jsonify, redirect, render_template, request, url_for
from flask_login import (
    LoginManager,
    UserMixin,
    current_user,
    login_required,
    login_user,
    logout_user,
)
from psycopg2 import Error, errors
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
    directory_entries = []
    directory_pending = []
    community_posts = []
    comments_by_post = {}
    verification_requests = []
    spot_scenarios = []
    spot_history = []
    spot_last = {}
    spot_stats = {"total": 0, "correct": 0, "accuracy": 0}
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

        # MODULE 2 — LOAD OFFICIAL SITE DIRECTORY
        # Everyone sees approved entries.
        cursor.execute(
            """
            SELECT site_id, brand, domain, category, contact
            FROM official_sites
            WHERE status = 'Approved'
            ORDER BY LOWER(brand) ASC, site_id ASC
            LIMIT 500
            """
        )

        directory_entries = cursor.fetchall()

        # Admins see every pending suggestion; users see only their own.
        if current_user.is_authenticated:
            if current_user.is_admin:
                cursor.execute(
                    """
                    SELECT
                        s.site_id, s.brand, s.domain, s.category,
                        s.contact, s.created_at,
                        u.username AS suggested_by_name
                    FROM official_sites AS s
                    LEFT JOIN users AS u ON u.user_id = s.suggested_by
                    WHERE s.status = 'Pending'
                    ORDER BY s.created_at ASC, s.site_id ASC
                    LIMIT 200
                    """
                )
            else:
                cursor.execute(
                    """
                    SELECT
                        site_id, brand, domain, category,
                        contact, created_at
                    FROM official_sites
                    WHERE status = 'Pending' AND suggested_by = %s
                    ORDER BY created_at DESC, site_id DESC
                    LIMIT 50
                    """,
                    (int(current_user.id),),
                )

            directory_pending = cursor.fetchall()

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
                p.incident_date,
                p.is_anonymous,
                CASE WHEN p.is_anonymous THEN NULL
                     ELSE u.username END AS author
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
        # MODULE 5 — LOAD SPOT THE PHISH SCENARIOS
        # ==========================================
        # Only admins receive the answer key. For everyone else the
        # answer and the red-flag explanation stay on the server until
        # the scenario has been answered.

        if current_user.is_authenticated and current_user.is_admin:
            scenario_columns = """
                scenario_id, title, scenario_type, sender, subject, body,
                is_phishing, red_flags, created_at, updated_at
            """
        else:
            scenario_columns = """
                scenario_id, title, scenario_type, sender, subject, body
            """

        cursor.execute(f"""
            SELECT {scenario_columns}
            FROM spot_phish_scenarios
            ORDER BY scenario_id ASC
            LIMIT 100
        """)

        spot_scenarios = cursor.fetchall()

        if current_user.is_authenticated:
            cursor.execute("""
                SELECT
                    a.answer_id,
                    a.scenario_id,
                    a.user_answer,
                    a.is_correct,
                    a.answered_at,
                    s.title,
                    s.scenario_type
                FROM spot_phish_answers AS a
                JOIN spot_phish_scenarios AS s
                    ON s.scenario_id = a.scenario_id
                WHERE a.user_id = %s
                ORDER BY a.answered_at DESC, a.answer_id DESC
                LIMIT 20
            """, (current_user.id,))

            spot_history = cursor.fetchall()

            cursor.execute("""
                SELECT DISTINCT ON (scenario_id)
                    scenario_id, is_correct
                FROM spot_phish_answers
                WHERE user_id = %s
                ORDER BY scenario_id, answered_at DESC, answer_id DESC
            """, (current_user.id,))

            spot_last = {
                row["scenario_id"]: row["is_correct"]
                for row in cursor.fetchall()
            }

            cursor.execute("""
                SELECT
                    COUNT(*) AS total,
                    COUNT(*) FILTER (WHERE is_correct) AS correct
                FROM spot_phish_answers
                WHERE user_id = %s
            """, (current_user.id,))

            stats_row = cursor.fetchone()

            if stats_row and stats_row["total"]:
                spot_stats = {
                    "total": stats_row["total"],
                    "correct": stats_row["correct"],
                    "accuracy": round(
                        stats_row["correct"] * 100 / stats_row["total"]
                    ),
                }

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
           directory_entries=directory_entries,
           directory_pending=directory_pending,
           site_categories=SITE_CATEGORIES,
           community_posts=community_posts,
           comments_by_post=comments_by_post,
           spot_scenarios=spot_scenarios,
           spot_history=spot_history,
           spot_last=spot_last,
           spot_stats=spot_stats,
           now_date=date.today().isoformat(),
           post_categories=POST_CATEGORIES,
           incident_category=INCIDENT_CATEGORY,
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
    RETURNING scan_id
    """,
    (
        int(current_user.id),
        result["url"],
        result["score"],
        result["level"],
        json.dumps(result["indicators"]),
    ),
)
        new_scan_id = cursor.fetchone()[0]
        connection.commit()
        return jsonify(**result, message='Scan saved successfully.', scan_id=new_scan_id), 201
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
# ACCOUNT — PROFILE, EMAIL, PASSWORD, DELETE
# ==========================================

EMAIL_PATTERN = re.compile(r'^[^@\s]+@[^@\s]+\.[^@\s]+$')

PROFILE_STAT_TABLES = (
    ('posts', 'community_posts'),
    ('comments', 'community_comments'),
    ('spot_answers', 'spot_phish_answers'),
    ('verifications', 'threat_verifications'),
    ('scans', 'url_scans'),
    ('quiz_attempts', 'quiz_scores'),
)


def delete_user_and_data(cursor, user_id):
    """
    Delete a user and everything they own.
    The caller must commit (or roll back) the transaction.
    """
    # Comments on this user's posts are removed automatically
    # (ON DELETE CASCADE on community_comments.post_id).
    cursor.execute('DELETE FROM community_comments WHERE user_id = %s', (user_id,))
    cursor.execute('DELETE FROM community_posts WHERE user_id = %s', (user_id,))
    cursor.execute('DELETE FROM spot_phish_answers WHERE user_id = %s', (user_id,))
    cursor.execute('DELETE FROM threat_verifications WHERE user_id = %s', (user_id,))
    cursor.execute('DELETE FROM quiz_scores WHERE user_id = %s', (user_id,))
    cursor.execute('DELETE FROM url_scans WHERE user_id = %s', (user_id,))

    # Pending suggestions are removed; approved entries stay in the
    # directory but lose their suggester.
    cursor.execute(
        "DELETE FROM official_sites WHERE suggested_by = %s AND status = 'Pending'",
        (user_id,),
    )
    cursor.execute(
        'UPDATE official_sites SET suggested_by = NULL WHERE suggested_by = %s',
        (user_id,),
    )
    cursor.execute('DELETE FROM users WHERE user_id = %s', (user_id,))


def count_admins(cursor):
    cursor.execute('SELECT COUNT(*) FROM users WHERE is_admin = 1')
    return cursor.fetchone()[0]


@app.get('/profile')
@login_required
def profile():
    connection = None
    cursor = None
    try:
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True, buffered=True)
        user_id = int(current_user.id)

        cursor.execute(
            """
            SELECT user_id, username, email, created_at, is_admin
            FROM users
            WHERE user_id = %s
            """,
            (user_id,),
        )
        account = cursor.fetchone()

        if account is None:
            logout_user()
            return redirect(url_for('login'))

        stats = {}
        for key, table in PROFILE_STAT_TABLES:
            cursor.execute(
                f'SELECT COUNT(*) AS n FROM {table} WHERE user_id = %s',
                (user_id,),
            )
            stats[key] = cursor.fetchone()['n']

        return render_template('profile.html', account=account, stats=stats)

    except Error:
        app.logger.exception('Failed to load profile')
        return 'Unable to load your profile.', 500

    finally:
        if cursor is not None:
            cursor.close()
        if connection is not None and connection.is_connected():
            connection.close()


@app.post('/profile/email')
@login_required
@limiter.limit('5 per minute')
def change_email():
    new_email = request.form.get('email', '').strip().lower()
    password = request.form.get('current_password', '')

    if not new_email or not password:
        flash('Enter a new email and your current password.', 'error')
        return redirect(url_for('profile'))

    if len(new_email) > 255 or not EMAIL_PATTERN.match(new_email):
        flash('Enter a valid email address (255 characters or fewer).', 'error')
        return redirect(url_for('profile'))

    connection = None
    cursor = None
    try:
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True, buffered=True)
        user_id = int(current_user.id)

        cursor.execute(
            'SELECT password_hash FROM users WHERE user_id = %s', (user_id,)
        )
        row = cursor.fetchone()
        if row is None or not check_password_hash(row['password_hash'], password):
            flash('Current password is incorrect.', 'error')
            return redirect(url_for('profile'))

        cursor.execute(
            'SELECT user_id FROM users WHERE email = %s AND user_id <> %s',
            (new_email, user_id),
        )
        if cursor.fetchone():
            flash('That email is already used by another account.', 'error')
            return redirect(url_for('profile'))

        cursor.execute(
            'UPDATE users SET email = %s WHERE user_id = %s', (new_email, user_id)
        )
        connection.commit()
        flash('Email updated.', 'success')
        return redirect(url_for('profile'))

    except Error:
        if connection is not None:
            connection.rollback()
        app.logger.exception('Failed to change email')
        flash('Could not update your email. Please try again.', 'error')
        return redirect(url_for('profile'))

    finally:
        if cursor is not None:
            cursor.close()
        if connection is not None and connection.is_connected():
            connection.close()


@app.post('/profile/password')
@login_required
@limiter.limit('5 per minute')
def change_password():
    current_password = request.form.get('current_password', '')
    new_password = request.form.get('new_password', '')
    confirm_password = request.form.get('confirm_password', '')

    if not current_password or not new_password:
        flash('Fill in all password fields.', 'error')
        return redirect(url_for('profile'))

    if len(new_password) < 8:
        flash('New password must contain at least 8 characters.', 'error')
        return redirect(url_for('profile'))

    if new_password != confirm_password:
        flash('New passwords do not match.', 'error')
        return redirect(url_for('profile'))

    if new_password == current_password:
        flash('Choose a password different from your current one.', 'error')
        return redirect(url_for('profile'))

    connection = None
    cursor = None
    try:
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True, buffered=True)
        user_id = int(current_user.id)

        cursor.execute(
            'SELECT password_hash FROM users WHERE user_id = %s', (user_id,)
        )
        row = cursor.fetchone()
        if row is None or not check_password_hash(
            row['password_hash'], current_password
        ):
            flash('Current password is incorrect.', 'error')
            return redirect(url_for('profile'))

        cursor.execute(
            'UPDATE users SET password_hash = %s WHERE user_id = %s',
            (generate_password_hash(new_password), user_id),
        )
        connection.commit()
        flash('Password updated.', 'success')
        return redirect(url_for('profile'))

    except Error:
        if connection is not None:
            connection.rollback()
        app.logger.exception('Failed to change password')
        flash('Could not update your password. Please try again.', 'error')
        return redirect(url_for('profile'))

    finally:
        if cursor is not None:
            cursor.close()
        if connection is not None and connection.is_connected():
            connection.close()


@app.post('/profile/delete')
@login_required
@limiter.limit('5 per minute')
def delete_own_account():
    password = request.form.get('password', '')

    if not password:
        flash('Enter your password to delete your account.', 'error')
        return redirect(url_for('profile'))

    connection = None
    cursor = None
    try:
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True, buffered=True)
        user_id = int(current_user.id)

        cursor.execute(
            'SELECT password_hash, is_admin FROM users WHERE user_id = %s',
            (user_id,),
        )
        row = cursor.fetchone()
        if row is None or not check_password_hash(row['password_hash'], password):
            flash('Password is incorrect. Your account was not deleted.', 'error')
            return redirect(url_for('profile'))

        # Never leave the site without an administrator.
        if row['is_admin']:
            plain_cursor = connection.cursor(buffered=True)
            try:
                if count_admins(plain_cursor) <= 1:
                    flash(
                        'You are the only administrator. Make another '
                        'account an administrator before deleting this one.',
                        'error',
                    )
                    return redirect(url_for('profile'))
            finally:
                plain_cursor.close()

        delete_cursor = connection.cursor(buffered=True)
        try:
            delete_user_and_data(delete_cursor, user_id)
        finally:
            delete_cursor.close()
        connection.commit()

        logout_user()
        return redirect(url_for('home'))

    except Error:
        if connection is not None:
            connection.rollback()
        app.logger.exception('Failed to delete account')
        flash('Could not delete your account. Please try again.', 'error')
        return redirect(url_for('profile'))

    finally:
        if cursor is not None:
            cursor.close()
        if connection is not None and connection.is_connected():
            connection.close()


# ==========================================
# ADMIN — VIEW AND DELETE USERS
# ==========================================

@app.get('/admin/users')
@login_required
def admin_users():
    if not current_user.is_admin:
        return 'Administrator access required.', 403

    connection = None
    cursor = None
    try:
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True, buffered=True)

        cursor.execute(
            """
            SELECT
                u.user_id,
                u.username,
                u.email,
                u.created_at,
                u.is_admin,
                (SELECT COUNT(*) FROM community_posts p
                    WHERE p.user_id = u.user_id) AS post_count,
                (SELECT COUNT(*) FROM community_comments c
                    WHERE c.user_id = u.user_id) AS comment_count,
                (SELECT COUNT(*) FROM url_scans s
                    WHERE s.user_id = u.user_id) AS scan_count
            FROM users AS u
            ORDER BY u.created_at DESC, u.user_id DESC
            """
        )
        return render_template('admin_users.html', users=cursor.fetchall())

    except Error:
        app.logger.exception('Failed to load user list')
        return 'Unable to load users.', 500

    finally:
        if cursor is not None:
            cursor.close()
        if connection is not None and connection.is_connected():
            connection.close()


@app.post('/admin/users/<int:user_id>/delete')
@login_required
def admin_delete_user(user_id):
    if not current_user.is_admin:
        return 'Administrator access required.', 403

    if user_id == int(current_user.id):
        flash('Use your Profile page to delete your own account.', 'error')
        return redirect(url_for('admin_users'))

    connection = None
    cursor = None
    try:
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True, buffered=True)

        cursor.execute(
            'SELECT username, is_admin FROM users WHERE user_id = %s', (user_id,)
        )
        target = cursor.fetchone()

        if target is None:
            flash('That user no longer exists.', 'error')
            return redirect(url_for('admin_users'))

        if target['is_admin']:
            flash(
                'Administrator accounts cannot be deleted here. '
                'Remove admin rights first.',
                'error',
            )
            return redirect(url_for('admin_users'))

        delete_cursor = connection.cursor(buffered=True)
        try:
            delete_user_and_data(delete_cursor, user_id)
        finally:
            delete_cursor.close()
        connection.commit()

        flash(f"Deleted account “{target['username']}”.", 'success')
        return redirect(url_for('admin_users'))

    except Error:
        if connection is not None:
            connection.rollback()
        app.logger.exception('Failed to delete user')
        flash('Could not delete that account. Please try again.', 'error')
        return redirect(url_for('admin_users'))

    finally:
        if cursor is not None:
            cursor.close()
        if connection is not None and connection.is_connected():
            connection.close()


# ==========================================
# MODULE 2 — OFFICIAL SITE DIRECTORY
# ==========================================

SITE_CATEGORIES = ("Bank", "E-Wallet", "Delivery", "Government", "Other")

DOMAIN_PATTERN = re.compile(
    r"^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z](?:[a-z0-9-]{0,61}[a-z0-9])$"
)


def normalize_domain(raw):
    """
    Turn "https://www.Example.com/login" into "example.com".
    Returns None when the value is not a valid domain name.
    """
    value = (raw or "").strip().lower()

    if not value or len(value) > 300:
        return None

    if "://" not in value:
        value = "http://" + value

    try:
        host = urlsplit(value).hostname
    except ValueError:
        return None

    if not host:
        return None

    host = host.rstrip(".")

    if host.startswith("www."):
        host = host[4:]

    return host if DOMAIN_PATTERN.match(host) else None


def read_site_form():
    """Validate the directory form. Returns (data, error)."""
    brand = request.form.get("brand", "").strip()
    category = request.form.get("category", "").strip()
    contact = request.form.get("contact", "").strip()
    domain = normalize_domain(request.form.get("domain", ""))

    if not brand or len(brand) > 120:
        return None, "Brand name must contain between 1 and 120 characters."

    if domain is None:
        return None, "Please enter a valid domain name, e.g. example.com.my"

    if category not in SITE_CATEGORIES:
        return None, "Please select a valid category."

    if len(contact) > 255:
        return None, "Official contact must be 255 characters or fewer."

    return {
        "brand": brand,
        "domain": domain,
        "category": category,
        "contact": contact,
    }, None


def run_site_write(sql, params, error_label, success_endpoint_hash="#site-directory",
                   not_found_message=None):
    """
    Small helper used by the directory routes: run one write query,
    commit, and redirect back to the directory.
    """
    connection = None
    cursor = None

    try:
        connection = get_db_connection()
        cursor = connection.cursor()
        cursor.execute(sql, params)
        affected = cursor.rowcount
        connection.commit()

        if affected == 0 and not_found_message:
            return not_found_message, 404

        return redirect(url_for("home") + success_endpoint_hash)

    except errors.UniqueViolation:
        if connection is not None:
            connection.rollback()

        return (
            "That domain is already in the directory or waiting for approval.",
            409,
        )

    except Error:
        if connection is not None:
            connection.rollback()

        app.logger.exception(error_label)
        return "Something went wrong. Please try again.", 500

    finally:
        if cursor is not None:
            cursor.close()

        if connection is not None and connection.is_connected():
            connection.close()


# ---- CREATE: admin adds an approved entry ----

@app.post("/directory/add")
@login_required
def add_official_site():
    if not current_user.is_admin:
        return "Administrator access required.", 403

    data, error = read_site_form()

    if error:
        return error, 400

    return run_site_write(
        """
        INSERT INTO official_sites
            (brand, domain, category, contact, status, suggested_by)
        VALUES (%s, %s, %s, %s, 'Approved', NULL)
        """,
        (data["brand"], data["domain"], data["category"], data["contact"]),
        "Failed to add official site",
    )


# ---- CREATE: any logged-in user suggests a missing brand (pending) ----

@app.post("/directory/suggest")
@login_required
@limiter.limit("10 per hour")
def suggest_official_site():
    data, error = read_site_form()

    if error:
        return error, 400

    return run_site_write(
        """
        INSERT INTO official_sites
            (brand, domain, category, contact, status, suggested_by)
        VALUES (%s, %s, %s, %s, 'Pending', %s)
        """,
        (
            data["brand"],
            data["domain"],
            data["category"],
            data["contact"],
            int(current_user.id),
        ),
        "Failed to save site suggestion",
    )


# ---- UPDATE: admin edits an entry ----

@app.post("/directory/<int:site_id>/edit")
@login_required
def edit_official_site(site_id):
    if not current_user.is_admin:
        return "Administrator access required.", 403

    data, error = read_site_form()

    if error:
        return error, 400

    return run_site_write(
        """
        UPDATE official_sites
        SET brand = %s,
            domain = %s,
            category = %s,
            contact = %s,
            updated_at = NOW()
        WHERE site_id = %s
        """,
        (
            data["brand"],
            data["domain"],
            data["category"],
            data["contact"],
            site_id,
        ),
        "Failed to edit official site",
        not_found_message="Entry not found.",
    )


# ---- UPDATE: admin approves a pending suggestion ----

@app.post("/directory/<int:site_id>/approve")
@login_required
def approve_official_site(site_id):
    if not current_user.is_admin:
        return "Administrator access required.", 403

    return run_site_write(
        """
        UPDATE official_sites
        SET status = 'Approved', updated_at = NOW()
        WHERE site_id = %s AND status = 'Pending'
        """,
        (site_id,),
        "Failed to approve official site",
        not_found_message="Pending suggestion not found.",
    )


# ---- DELETE: admin deletes any entry (or rejects a suggestion) ----

@app.post("/directory/<int:site_id>/delete")
@login_required
def delete_official_site(site_id):
    if not current_user.is_admin:
        return "Administrator access required.", 403

    return run_site_write(
        "DELETE FROM official_sites WHERE site_id = %s",
        (site_id,),
        "Failed to delete official site",
        not_found_message="Entry not found.",
    )


# ---- DELETE: a user withdraws their own PENDING suggestion ----

@app.post("/directory/<int:site_id>/withdraw")
@login_required
def withdraw_official_site(site_id):
    return run_site_write(
        """
        DELETE FROM official_sites
        WHERE site_id = %s
          AND suggested_by = %s
          AND status = 'Pending'
        """,
        (site_id, int(current_user.id)),
        "Failed to withdraw site suggestion",
        not_found_message="Suggestion not found, or it has already been approved.",
    )


# ==========================================
# COMMUNITY & INCIDENT POSTS — SHARED HELPERS
# ==========================================

INCIDENT_CATEGORY = "I experienced an incident"

POST_CATEGORIES = (
    "Phishing Alert",
    "Scam Warning",
    "Malware Alert",
    "Security Tips",
    "General Discussion",
    INCIDENT_CATEGORY,
)


def read_post_form():
    """
    Validate the post form shared by "create" and "edit".
    Returns (data, error). `error` is None when the form is valid.
    """
    title = request.form.get("title", "").strip()
    category = request.form.get("category", "").strip()
    content = request.form.get("content", "").strip()
    incident_date_raw = request.form.get("incident_date", "").strip()
    is_anonymous = request.form.get("is_anonymous") == "on"

    if not title or len(title) > 200:
        return None, "Please enter a valid post title (maximum 200 characters)."

    if category not in POST_CATEGORIES:
        return None, "Please select a valid post category."

    if not content or len(content) > 10000:
        return None, "Post content must contain between 1 and 10000 characters."

    incident_date = None

    # The incident date only applies to incident posts, and it is optional.
    if category == INCIDENT_CATEGORY and incident_date_raw:
        try:
            incident_date = date.fromisoformat(incident_date_raw)
        except ValueError:
            return None, "Please enter a valid incident date."

        if incident_date > date.today():
            return None, "The incident date cannot be in the future."

    return {
        "title": title,
        "category": category,
        "content": content,
        "incident_date": incident_date,
        "is_anonymous": is_anonymous,
    }, None


# ==========================================
# MODULE 3 — CREATE POST (community + incident)
# ==========================================

@app.post("/community/posts/add")
@login_required
def add_community_post():
    data, error = read_post_form()

    if error:
        return error, 400

    connection = None
    cursor = None

    try:
        connection = get_db_connection()
        cursor = connection.cursor()

        cursor.execute(
            """
            INSERT INTO community_posts
                (user_id, title, category, content,
                 incident_date, is_anonymous)
            VALUES (%s, %s, %s, %s, %s, %s)
            """,
            (
                int(current_user.id),
                data["title"],
                data["category"],
                data["content"],
                data["incident_date"],
                data["is_anonymous"],
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
# MODULE 3 — EDIT POST
# ==========================================

@app.post("/community/posts/<int:post_id>/edit")
@login_required
def edit_community_post(post_id):
    data, error = read_post_form()

    if error:
        return error, 400

    connection = None
    cursor = None

    try:
        connection = get_db_connection()
        cursor = connection.cursor()

        # Only the owner can edit; rowcount tells us whether it matched.
        cursor.execute(
            """
            UPDATE community_posts
            SET title = %s,
                category = %s,
                content = %s,
                incident_date = %s,
                is_anonymous = %s,
                updated_at = NOW()
            WHERE post_id = %s AND user_id = %s
            """,
            (
                data["title"],
                data["category"],
                data["content"],
                data["incident_date"],
                data["is_anonymous"],
                post_id,
                int(current_user.id),
            ),
        )

        updated = cursor.rowcount
        connection.commit()

        if updated == 0:
            return "Post not found or permission denied.", 404

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
# MODULE 5 — SPOT THE PHISH
# ==========================================

SPOT_TYPES = ("Email", "SMS", "Login Page")


def read_scenario_form():
    """Validate the admin scenario form. Returns (data, error)."""
    title = request.form.get("title", "").strip()
    scenario_type = request.form.get("scenario_type", "").strip()
    sender = request.form.get("sender", "").strip()
    subject = request.form.get("subject", "").strip()
    body = request.form.get("body", "").strip()
    verdict = request.form.get("verdict", "").strip()
    red_flags = request.form.get("red_flags", "").strip()

    if not title or len(title) > 200:
        return None, "Title must contain between 1 and 200 characters."

    if scenario_type not in SPOT_TYPES:
        return None, "Please select a valid scenario type."

    if not sender or len(sender) > 255:
        return None, "Sender / address must contain between 1 and 255 characters."

    if len(subject) > 255:
        return None, "Subject must be 255 characters or fewer."

    if not body or len(body) > 5000:
        return None, "Message content must contain between 1 and 5000 characters."

    if verdict not in ("phishing", "legit"):
        return None, "Please choose whether this scenario is phishing or legitimate."

    if not red_flags or len(red_flags) > 3000:
        return None, "Please explain the red flags (maximum 3000 characters)."

    return {
        "title": title,
        "scenario_type": scenario_type,
        "sender": sender,
        # Only emails have a subject line.
        "subject": subject if scenario_type == "Email" else "",
        "body": body,
        "is_phishing": verdict == "phishing",
        "red_flags": red_flags,
    }, None


# ---- CREATE (admin) ----

@app.post("/spot-the-phish/scenarios/add")
@login_required
def add_spot_scenario():
    if not current_user.is_admin:
        return "Administrator access required.", 403

    data, error = read_scenario_form()

    if error:
        return error, 400

    connection = None
    cursor = None

    try:
        connection = get_db_connection()
        cursor = connection.cursor()

        cursor.execute(
            """
            INSERT INTO spot_phish_scenarios
                (title, scenario_type, sender, subject, body,
                 is_phishing, red_flags)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            """,
            (
                data["title"],
                data["scenario_type"],
                data["sender"],
                data["subject"],
                data["body"],
                data["is_phishing"],
                data["red_flags"],
            ),
        )

        connection.commit()

        return redirect(url_for("home") + "#spot-the-phish")

    except Error:
        if connection is not None:
            connection.rollback()

        app.logger.exception("Failed to add Spot the Phish scenario")
        return "Unable to add the scenario. Please try again.", 500

    finally:
        if cursor is not None:
            cursor.close()

        if connection is not None and connection.is_connected():
            connection.close()


# ---- UPDATE (admin) ----

@app.post("/spot-the-phish/scenarios/<int:scenario_id>/edit")
@login_required
def edit_spot_scenario(scenario_id):
    if not current_user.is_admin:
        return "Administrator access required.", 403

    data, error = read_scenario_form()

    if error:
        return error, 400

    connection = None
    cursor = None

    try:
        connection = get_db_connection()
        cursor = connection.cursor()

        cursor.execute(
            """
            UPDATE spot_phish_scenarios
            SET title = %s,
                scenario_type = %s,
                sender = %s,
                subject = %s,
                body = %s,
                is_phishing = %s,
                red_flags = %s,
                updated_at = NOW()
            WHERE scenario_id = %s
            """,
            (
                data["title"],
                data["scenario_type"],
                data["sender"],
                data["subject"],
                data["body"],
                data["is_phishing"],
                data["red_flags"],
                scenario_id,
            ),
        )

        updated = cursor.rowcount
        connection.commit()

        if updated == 0:
            return "Scenario not found.", 404

        return redirect(url_for("home") + "#spot-the-phish")

    except Error:
        if connection is not None:
            connection.rollback()

        app.logger.exception("Failed to edit Spot the Phish scenario")
        return "Unable to update the scenario. Please try again.", 500

    finally:
        if cursor is not None:
            cursor.close()

        if connection is not None and connection.is_connected():
            connection.close()


# ---- DELETE (admin) ----

@app.post("/spot-the-phish/scenarios/<int:scenario_id>/delete")
@login_required
def delete_spot_scenario(scenario_id):
    if not current_user.is_admin:
        return "Administrator access required.", 403

    connection = None
    cursor = None

    try:
        connection = get_db_connection()
        cursor = connection.cursor()

        # Answer records for this scenario are removed too
        # (ON DELETE CASCADE on spot_phish_answers.scenario_id).
        cursor.execute(
            "DELETE FROM spot_phish_scenarios WHERE scenario_id = %s",
            (scenario_id,),
        )

        deleted = cursor.rowcount
        connection.commit()

        if deleted == 0:
            return "Scenario not found.", 404

        return redirect(url_for("home") + "#spot-the-phish")

    except Error:
        if connection is not None:
            connection.rollback()

        app.logger.exception("Failed to delete Spot the Phish scenario")
        return "Unable to delete the scenario. Please try again.", 500

    finally:
        if cursor is not None:
            cursor.close()

        if connection is not None and connection.is_connected():
            connection.close()


# ---- CREATE answer record (any user) ----

@app.post("/spot-the-phish/scenarios/<int:scenario_id>/answer")
@limiter.limit("60 per minute")
def answer_spot_scenario(scenario_id):
    payload = request.get_json(silent=True)

    if not isinstance(payload, dict) or payload.get("answer") not in (
        "phishing",
        "legit",
    ):
        return jsonify(success=False, message="Invalid answer."), 400

    said_phishing = payload["answer"] == "phishing"

    connection = None
    cursor = None

    try:
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)

        cursor.execute(
            """
            SELECT is_phishing, red_flags
            FROM spot_phish_scenarios
            WHERE scenario_id = %s
            """,
            (scenario_id,),
        )

        scenario = cursor.fetchone()

        if scenario is None:
            return jsonify(success=False, message="Scenario not found."), 404

        is_correct = bool(scenario["is_phishing"]) == said_phishing
        saved = False

        # Only logged-in users get a saved history.
        if current_user.is_authenticated:
            cursor.execute(
                """
                INSERT INTO spot_phish_answers
                    (user_id, scenario_id, user_answer, is_correct)
                VALUES (%s, %s, %s, %s)
                """,
                (
                    int(current_user.id),
                    scenario_id,
                    said_phishing,
                    is_correct,
                ),
            )
            connection.commit()
            saved = True

        return jsonify(
            success=True,
            correct=is_correct,
            is_phishing=bool(scenario["is_phishing"]),
            red_flags=[
                line.strip()
                for line in scenario["red_flags"].splitlines()
                if line.strip()
            ],
            saved=saved,
        )

    except Error:
        if connection is not None:
            connection.rollback()

        app.logger.exception("Failed to record Spot the Phish answer")
        return jsonify(
            success=False,
            message="Unable to check your answer. Please try again.",
        ), 500

    finally:
        if cursor is not None:
            cursor.close()

        if connection is not None and connection.is_connected():
            connection.close()


# ---- DELETE own history (any logged-in user) ----

@app.post("/spot-the-phish/history/clear")
@login_required
def clear_spot_history():
    connection = None
    cursor = None

    try:
        connection = get_db_connection()
        cursor = connection.cursor()

        cursor.execute(
            "DELETE FROM spot_phish_answers WHERE user_id = %s",
            (int(current_user.id),),
        )

        connection.commit()

        return redirect(url_for("home") + "#spot-the-phish")

    except Error:
        if connection is not None:
            connection.rollback()

        app.logger.exception("Failed to clear Spot the Phish history")
        return "Unable to clear your history. Please try again.", 500

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
