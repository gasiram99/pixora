
import hashlib
import hmac
import os
import secrets
import smtplib
import ssl
import uuid
from datetime import datetime, timedelta
from email.message import EmailMessage
from functools import wraps
from pathlib import Path
from urllib.parse import urlsplit

import mysql.connector
from dotenv import load_dotenv
from flask import (
    Flask, render_template, request, redirect,
    url_for, flash, session, abort, jsonify
)
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import generate_password_hash, check_password_hash
from PIL import Image, ImageOps, UnidentifiedImageError

load_dotenv()

app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("FLASK_SECRET_KEY") or os.getenv("SECRET_KEY")

if not app.config["SECRET_KEY"]:
    raise RuntimeError("Set SECRET_KEY or FLASK_SECRET_KEY in your .env file.")

app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024
app.config["REEL_MAX_UPLOAD_BYTES"] = 25 * 1024 * 1024
app.config["UPLOAD_FOLDER"] = str(
    Path(app.root_path) / "static" / "uploads"
)
app.config["REEL_UPLOAD_FOLDER"] = str(
    Path(app.config["UPLOAD_FOLDER"]) / "reels"
)
app.config["STORY_UPLOAD_FOLDER"] = str(
    Path(app.config["UPLOAD_FOLDER"]) / "stories"
)
app.config["STORY_MAX_UPLOAD_BYTES"] = 25 * 1024 * 1024

os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
os.makedirs(app.config["REEL_UPLOAD_FOLDER"], exist_ok=True)
os.makedirs(app.config["STORY_UPLOAD_FOLDER"], exist_ok=True)


@app.before_request
def set_media_upload_limit():
    if request.endpoint == "reels":
        request.max_content_length = app.config["REEL_MAX_UPLOAD_BYTES"] + 1024 * 1024
    elif request.endpoint == "stories":
        request.max_content_length = app.config["STORY_MAX_UPLOAD_BYTES"] + 1024 * 1024


CSRFProtect(app)

ALLOWED_EXTENSIONS = {"jpg", "jpeg", "png", "webp"}
ALLOWED_REEL_EXTENSIONS = {"mp4", "webm"}


@app.errorhandler(413)
def handle_upload_too_large(error):
    if request.endpoint == "reels":
        flash("Videos must be 25 MB or smaller.", "error")
        return redirect(url_for("reels"))
    if request.endpoint == "stories":
        flash("Story media must be 25 MB or smaller.", "error")
        return redirect(url_for("feed"))
    return error


# ---------------- DATABASE ----------------

def get_db_connection():
    return mysql.connector.connect(
        host=os.getenv("DB_HOST", "127.0.0.1"),
        port=int(os.getenv("DB_PORT", "3306")),
        user=os.getenv("DB_USER", "root"),
        password=os.getenv("DB_PASSWORD", ""),
        database=os.getenv("DB_NAME", "instagram_clone"),
    )


def get_media_file_path(base_directory, filename):
    if not filename:
        return None
    safe_name = os.path.basename(str(filename))
    if not safe_name:
        return None
    return os.path.join(base_directory, safe_name)


@app.context_processor
def inject_unread_notification_count():
    user_id = session.get("user_id")
    if not user_id:
        return {"unread_notification_count": 0}

    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "SELECT COUNT(*) FROM notifications WHERE recipient_id=%s AND is_read=0",
            (user_id,),
        )
        return {"unread_notification_count": cursor.fetchone()[0]}
    finally:
        cursor.close()
        conn.close()


# ---------------- AUTHENTICATION ----------------

def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("user_id"):
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


@app.route("/")
def home():
    return render_template("home.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip().lower()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if not 3 <= len(username) <= 30:
            flash("Username must contain 3–30 characters.")
            return render_template("register.html")

        if not email or len(email) > 254:
            flash("Enter a valid email address.")
            return render_template("register.html")

        if len(password) < 10 or len(password) > 128:
            flash("Password must contain 10–128 characters.")
            return render_template("register.html")

        code = f"{secrets.randbelow(1_000_000):06d}"
        code_hash = hmac.new(
            app.config["SECRET_KEY"].encode(),
            code.encode(),
            hashlib.sha256,
        ).hexdigest()
        conn = get_db_connection()
        cursor = conn.cursor()

        try:
            cursor.execute(
                """
                INSERT INTO users
                    (username, email, password_hash, is_verified)
                VALUES (%s, %s, %s, 0)
                """,
                (username, email, generate_password_hash(password)),
            )
            cursor.execute(
                "DELETE FROM otp_codes WHERE email=%s AND purpose='register'",
                (email,),
            )
            cursor.execute(
                """
                INSERT INTO otp_codes (email, purpose, code_hash, expires_at)
                VALUES (%s, 'register', %s, %s)
                """,
                (email, code_hash, datetime.now() + timedelta(minutes=10)),
            )
            conn.commit()
            session["pending_verification_email"] = email

        except mysql.connector.IntegrityError:
            conn.rollback()
            flash("That username or email is already registered.")
            return render_template("register.html")

        finally:
            cursor.close()
            conn.close()

        try:
            send_verification_email(email, code)
            session["otp_last_sent_at"] = datetime.now().timestamp()
            flash("A verification code has been sent to your email.")
        except (OSError, RuntimeError, smtplib.SMTPException):
            app.logger.exception("Unable to send registration verification email")
            flash("Your account is pending verification. Use Resend Code to try again.")
        return redirect(url_for("verify_otp"))

    return render_template("register.html")


def send_verification_email(email, code):
    host = os.getenv("SMTP_HOST")
    username = os.getenv("SMTP_USERNAME")
    password = os.getenv("SMTP_PASSWORD")
    from_email = os.getenv("SMTP_FROM_EMAIL") or username

    if not host or not username or not password or not from_email:
        raise RuntimeError("SMTP settings are incomplete.")

    message = EmailMessage()
    message["Subject"] = "Your Pixora verification code"
    message["From"] = from_email
    message["To"] = email
    message.set_content(
        f"Your Pixora verification code is {code}. "
        "It expires in 10 minutes."
    )

    with smtplib.SMTP(
        host,
        int(os.getenv("SMTP_PORT", "587")),
        timeout=10,
    ) as smtp:
        smtp.starttls(context=ssl.create_default_context())
        smtp.login(username, password)
        smtp.send_message(message)


def send_password_reset_email(email, code):
    host = os.getenv("SMTP_HOST")
    username = os.getenv("SMTP_USERNAME")
    password = os.getenv("SMTP_PASSWORD")
    from_email = os.getenv("SMTP_FROM_EMAIL") or username

    if not host or not username or not password or not from_email:
        raise RuntimeError("SMTP settings are incomplete.")

    message = EmailMessage()
    message["Subject"] = "Reset your Pixora password"
    message["From"] = from_email
    message["To"] = email
    message.set_content(
        f"Your Pixora password reset code is {code}. "
        "It expires in 10 minutes. If you did not request this, you can ignore this email."
    )

    with smtplib.SMTP(
        host,
        int(os.getenv("SMTP_PORT", "587")),
        timeout=10,
    ) as smtp:
        smtp.starttls(context=ssl.create_default_context())
        smtp.login(username, password)
        smtp.send_message(message)


@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        last_sent_at = session.get("password_reset_last_sent_at", 0)
        seconds_since_last_send = datetime.now().timestamp() - last_sent_at

        if seconds_since_last_send < 60:
            flash("Please wait before requesting another reset code.", "error")
            return render_template("forgot_password.html", email=email)

        if email and len(email) <= 254:
            conn = get_db_connection()
            cursor = conn.cursor(dictionary=True)
            try:
                cursor.execute(
                    "SELECT email FROM users WHERE email=%s AND is_verified=1",
                    (email,),
                )
                user = cursor.fetchone()
                if user:
                    code = f"{secrets.randbelow(1_000_000):06d}"
                    code_hash = hmac.new(
                        app.config["SECRET_KEY"].encode(),
                        code.encode(),
                        hashlib.sha256,
                    ).hexdigest()
                    cursor.execute(
                        "DELETE FROM otp_codes WHERE email=%s AND purpose='password_reset'",
                        (email,),
                    )
                    cursor.execute(
                        """
                        INSERT INTO otp_codes (email, purpose, code_hash, expires_at)
                        VALUES (%s, 'password_reset', %s, %s)
                        """,
                        (email, code_hash, datetime.now() + timedelta(minutes=10)),
                    )
                    conn.commit()
            except Exception:
                conn.rollback()
                raise
            finally:
                cursor.close()
                conn.close()

            session["password_reset_email"] = email
            session["password_reset_last_sent_at"] = datetime.now().timestamp()

            if user:
                try:
                    send_password_reset_email(email, code)
                except (OSError, RuntimeError, smtplib.SMTPException):
                    app.logger.exception("Unable to send password reset email")

        flash(
            "If a verified account matches that email, you will receive a reset code shortly.",
            "success",
        )
        return redirect(url_for("reset_password"))

    return render_template("forgot_password.html")


@app.route("/reset-password", methods=["GET", "POST"])
def reset_password():
    email = session.get("password_reset_email")
    if not email:
        flash("Request a password reset code first.", "error")
        return redirect(url_for("forgot_password"))

    if request.method == "POST":
        code = request.form.get("otp", "").strip()
        new_password = request.form.get("new_password", "")
        confirm_password = request.form.get("confirm_password", "")

        if len(code) != 6 or not code.isdigit():
            flash("Enter the six-digit reset code.", "error")
            return render_template("reset_password.html")
        if not 10 <= len(new_password) <= 128:
            flash("New password must contain 10–128 characters.", "error")
            return render_template("reset_password.html")
        if new_password != confirm_password:
            flash("The new passwords do not match.", "error")
            return render_template("reset_password.html")

        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        try:
            cursor.execute(
                """
                SELECT id, code_hash, expires_at, attempts
                FROM otp_codes
                WHERE email=%s AND purpose='password_reset'
                ORDER BY created_at DESC
                LIMIT 1
                """,
                (email,),
            )
            otp_record = cursor.fetchone()

            if not otp_record:
                flash("No reset code was found. Request a new code.", "error")
            elif otp_record["attempts"] >= 5:
                flash("Too many incorrect attempts. Request a new code.", "error")
            elif otp_record["expires_at"] <= datetime.now():
                cursor.execute("DELETE FROM otp_codes WHERE id=%s", (otp_record["id"],))
                conn.commit()
                flash("That code has expired. Request a new code.", "error")
            else:
                expected_hash = hmac.new(
                    app.config["SECRET_KEY"].encode(),
                    code.encode(),
                    hashlib.sha256,
                ).hexdigest()
                if not hmac.compare_digest(expected_hash, otp_record["code_hash"]):
                    cursor.execute(
                        "UPDATE otp_codes SET attempts=attempts+1 WHERE id=%s",
                        (otp_record["id"],),
                    )
                    conn.commit()
                    flash("Incorrect reset code.", "error")
                else:
                    cursor.execute(
                        """
                        UPDATE users
                        SET password_hash=%s
                        WHERE email=%s AND is_verified=1
                        """,
                        (generate_password_hash(new_password), email),
                    )
                    cursor.execute(
                        "DELETE FROM otp_codes WHERE email=%s AND purpose='password_reset'",
                        (email,),
                    )
                    conn.commit()
                    session.pop("password_reset_email", None)
                    session.pop("password_reset_last_sent_at", None)
                    flash("Password reset. You can now log in.", "success")
                    return redirect(url_for("login"))
        except Exception:
            conn.rollback()
            raise
        finally:
            cursor.close()
            conn.close()

    return render_template("reset_password.html")


@app.route("/verify-otp", methods=["GET", "POST"])
def verify_otp():
    email = session.get("pending_verification_email")
    if not email:
        flash("Register an account before verifying your email.")
        return redirect(url_for("register"))

    if request.method == "POST":
        if request.form.get("action") == "resend":
            last_sent = session.get("otp_last_sent_at", 0)
            seconds_since_last_send = datetime.now().timestamp() - last_sent
            if seconds_since_last_send < 60:
                flash("Please wait before requesting another code.")
                return render_template("verify_otp.html")

            code = f"{secrets.randbelow(1_000_000):06d}"
            code_hash = hmac.new(
                app.config["SECRET_KEY"].encode(),
                code.encode(),
                hashlib.sha256,
            ).hexdigest()
            conn = get_db_connection()
            cursor = conn.cursor()
            try:
                cursor.execute(
                    "DELETE FROM otp_codes WHERE email=%s AND purpose='register'",
                    (email,),
                )
                cursor.execute(
                    """
                    INSERT INTO otp_codes (email, purpose, code_hash, expires_at)
                    VALUES (%s, 'register', %s, %s)
                    """,
                    (email, code_hash, datetime.now() + timedelta(minutes=10)),
                )
                conn.commit()
            except Exception:
                conn.rollback()
                raise
            finally:
                cursor.close()
                conn.close()

            try:
                send_verification_email(email, code)
                session["otp_last_sent_at"] = datetime.now().timestamp()
                flash("A new verification code has been sent.")
            except (OSError, RuntimeError, smtplib.SMTPException):
                app.logger.exception("Unable to resend registration verification email")
                flash("Could not send the code. Please try again later.")
            return render_template("verify_otp.html")

        code = request.form.get("otp", "").strip()
        if len(code) != 6 or not code.isdigit():
            flash("Enter the six-digit verification code.")
            return render_template("verify_otp.html")

        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        try:
            cursor.execute(
                """
                SELECT id, code_hash, expires_at, attempts
                FROM otp_codes
                WHERE email=%s AND purpose='register'
                ORDER BY created_at DESC
                LIMIT 1
                """,
                (email,),
            )
            otp_record = cursor.fetchone()

            if not otp_record:
                flash("No verification code was found. Request a new code.")
            elif otp_record["attempts"] >= 5:
                flash("Too many incorrect attempts. Request a new code.")
            elif otp_record["expires_at"] <= datetime.now():
                cursor.execute("DELETE FROM otp_codes WHERE id=%s", (otp_record["id"],))
                conn.commit()
                flash("That code has expired. Request a new code.")
            else:
                expected_hash = hmac.new(
                    app.config["SECRET_KEY"].encode(),
                    code.encode(),
                    hashlib.sha256,
                ).hexdigest()
                if not hmac.compare_digest(expected_hash, otp_record["code_hash"]):
                    cursor.execute(
                        "UPDATE otp_codes SET attempts=attempts+1 WHERE id=%s",
                        (otp_record["id"],),
                    )
                    conn.commit()
                    flash("Incorrect verification code.")
                else:
                    cursor.execute(
                        "UPDATE users SET is_verified=1 WHERE email=%s",
                        (email,),
                    )
                    cursor.execute(
                        "DELETE FROM otp_codes WHERE email=%s AND purpose='register'",
                        (email,),
                    )
                    conn.commit()
                    session.pop("pending_verification_email", None)
                    session.pop("otp_last_sent_at", None)
                    flash("Email verified. You can now log in.", "success")
                    return redirect(url_for("login"))
        except Exception:
            conn.rollback()
            raise
        finally:
            cursor.close()
            conn.close()

    return render_template("verify_otp.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        try:
            cursor.execute(
                """
                SELECT id, username, password_hash, is_verified
                FROM users
                WHERE email = %s
                """,
                (email,),
            )
            user = cursor.fetchone()
        finally:
            cursor.close()
            conn.close()

        if (
            user
            and user["is_verified"]
            and check_password_hash(user["password_hash"], password)
        ):
            session.clear()
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            return redirect(url_for("feed"))

        flash("Invalid email or password.", "error")

    return render_template("login.html")


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/settings/username", methods=["GET", "POST"])
@login_required
def change_username():
    if request.method == "POST":
        username = request.form.get("username", "").strip().lower()
        current_password = request.form.get("current_password", "")

        if not 3 <= len(username) <= 30:
            flash("Username must contain 3–30 characters.", "error")
            return render_template("change_username.html")

        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        try:
            cursor.execute(
                "SELECT username, password_hash FROM users WHERE id=%s",
                (session["user_id"],),
            )
            user = cursor.fetchone()
            if not user:
                abort(404)
            if not check_password_hash(user["password_hash"], current_password):
                flash("Your current password is incorrect.", "error")
                return render_template("change_username.html")
            if username == user["username"].lower():
                flash("Choose a different username.", "error")
                return render_template("change_username.html")

            try:
                cursor.execute(
                    "UPDATE users SET username=%s WHERE id=%s",
                    (username, session["user_id"]),
                )
                conn.commit()
            except mysql.connector.IntegrityError:
                conn.rollback()
                flash("That username is already taken.", "error")
                return render_template("change_username.html")
        finally:
            cursor.close()
            conn.close()

        session["username"] = username
        flash("Username updated.", "success")
        return redirect(url_for("change_username"))

    return render_template("change_username.html")


@app.route("/settings/password", methods=["GET", "POST"])
@login_required
def change_password():
    if request.method == "POST":
        current_password = request.form.get("current_password", "")
        new_password = request.form.get("new_password", "")
        confirm_password = request.form.get("confirm_password", "")

        if not 10 <= len(new_password) <= 128:
            flash("New password must contain 10–128 characters.", "error")
            return render_template("change_password.html")
        if new_password != confirm_password:
            flash("The new passwords do not match.", "error")
            return render_template("change_password.html")

        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        try:
            cursor.execute(
                "SELECT password_hash FROM users WHERE id=%s",
                (session["user_id"],),
            )
            user = cursor.fetchone()
            if not user:
                abort(404)
            if not check_password_hash(user["password_hash"], current_password):
                flash("Your current password is incorrect.", "error")
                return render_template("change_password.html")
            if check_password_hash(user["password_hash"], new_password):
                flash("Choose a password different from your current one.", "error")
                return render_template("change_password.html")

            cursor.execute(
                "UPDATE users SET password_hash=%s WHERE id=%s",
                (generate_password_hash(new_password), session["user_id"]),
            )
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            cursor.close()
            conn.close()

        flash("Password updated.", "success")
        return redirect(url_for("change_password"))

    return render_template("change_password.html")


# ---------------- FEED ----------------

@app.route("/feed")
@login_required
def feed():
    user_id = session["user_id"]
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        cursor.execute(
            "SELECT id, username, profile_image FROM users WHERE id=%s",
            (user_id,),
        )
        current_user = cursor.fetchone()
        if not current_user:
            session.clear()
            return redirect(url_for("login"))

        cursor.execute(
            """
            SELECT p.id, p.user_id, p.image_filename, p.caption,
                   p.created_at, u.username,
                   (SELECT COUNT(*) FROM likes l
                    WHERE l.post_id = p.id) AS like_count,
                   (SELECT COUNT(*) FROM likes l
                    WHERE l.post_id = p.id
                    AND l.user_id = %s) AS liked_by_me,
                   EXISTS (
                       SELECT 1
                       FROM follows f
                       WHERE f.follower_id = %s
                         AND f.followed_id = p.user_id
                   ) AS followed_by_me
            FROM posts p
            JOIN users u ON u.id = p.user_id
            ORDER BY p.created_at DESC
            LIMIT 100
            """,
            (user_id, user_id),
        )
        posts = cursor.fetchall()

        for post in posts:
            cursor.execute(
                """
                SELECT c.comment_text, c.created_at, u.username
                FROM comments c
                JOIN users u ON u.id = c.user_id
                WHERE c.post_id = %s
                ORDER BY c.created_at ASC
                LIMIT 20
                """,
                (post["id"],),
            )
            post["comments"] = cursor.fetchall()

        cursor.execute(
            """
            SELECT r.id, r.video_filename, r.caption, u.username
            FROM reels r
            JOIN users u ON u.id = r.user_id
            WHERE u.is_verified=1
            ORDER BY r.created_at DESC, r.id DESC
            LIMIT 6
            """
        )
        reel_items = cursor.fetchall()

        cursor.execute(
            """
            SELECT s.id, s.user_id, s.media_path, s.media_type, s.caption,
                   s.overlay_text, s.created_at, s.expires_at,
                   u.username, u.profile_image,
                   EXISTS(
                       SELECT 1 FROM story_views sv
                       WHERE sv.story_id=s.id AND sv.viewer_id=%s
                   ) AS viewed_by_me
            FROM stories s
            JOIN users u ON u.id=s.user_id
            WHERE s.expires_at > NOW()
              AND u.is_verified=1
              AND (
                  s.user_id=%s
                  OR EXISTS(
                      SELECT 1 FROM follows f
                      WHERE f.follower_id=%s AND f.followed_id=s.user_id
                  )
              )
            ORDER BY CASE WHEN s.user_id=%s THEN 0 ELSE 1 END,
                     s.created_at ASC, s.id ASC
            LIMIT 200
            """,
            (user_id, user_id, user_id, user_id),
        )
        active_stories = cursor.fetchall()

    finally:
        cursor.close()
        conn.close()

    story_groups_by_user = {}
    for story in active_stories:
        group = story_groups_by_user.get(story["user_id"])
        if group is None:
            group = {
                "user_id": story["user_id"],
                "username": story["username"],
                "profile_image": story["profile_image"],
                "profile_image_url": (
                    url_for(
                        "static",
                        filename="uploads/" + story["profile_image"],
                    )
                    if story["profile_image"] else None
                ),
                "is_own": story["user_id"] == user_id,
                "has_unseen": False,
                "stories": [],
            }
            story_groups_by_user[story["user_id"]] = group

        story["media_url"] = url_for(
            "static",
            filename=f"uploads/stories/{os.path.basename(story['media_path'])}",
        )
        story["viewed_by_me"] = bool(story["viewed_by_me"])
        story["is_own"] = story["user_id"] == user_id
        story["created_at_label"] = story["created_at"].strftime("%I:%M %p")
        story["created_at"] = story["created_at"].isoformat()
        story["expires_at_iso"] = story["expires_at"].isoformat()
        story["expires_at"] = story["expires_at"].isoformat()
        group["stories"].append(story)
        if not story["viewed_by_me"] and not group["is_own"]:
            group["has_unseen"] = True

    return render_template(
        "feed.html",
        posts=posts,
        reels=reel_items,
        current_user=current_user,
        story_groups=list(story_groups_by_user.values()),
    )


# ---------------- STORIES ----------------

@app.route("/stories", methods=["POST"])
@login_required
def stories():
    uploaded = request.files.get("media")
    caption = request.form.get("caption", "").strip()
    overlay_text = request.form.get("overlay_text", "").strip()

    if not uploaded or not uploaded.filename:
        flash("Choose a photo or video for your story.", "error")
        return redirect(url_for("feed"))
    if len(caption) > 300 or len(overlay_text) > 140:
        flash("Story captions are limited to 300 characters and overlays to 140.", "error")
        return redirect(url_for("feed"))

    extension = uploaded.filename.rsplit(".", 1)[-1].lower()
    if "." not in uploaded.filename or (
        extension not in ALLOWED_EXTENSIONS | ALLOWED_REEL_EXTENSIONS
    ):
        flash("Choose a JPG, PNG, WebP, MP4, or WebM file.", "error")
        return redirect(url_for("feed"))

    uploaded.stream.seek(0, os.SEEK_END)
    upload_size = uploaded.stream.tell()
    uploaded.stream.seek(0)
    if upload_size > app.config["STORY_MAX_UPLOAD_BYTES"]:
        flash("Story media must be 25 MB or smaller.", "error")
        return redirect(url_for("feed"))

    is_image = extension in ALLOWED_EXTENSIONS
    if is_image:
        filename = f"{uuid.uuid4().hex}.jpg"
        filepath = os.path.join(app.config["STORY_UPLOAD_FOLDER"], filename)
        try:
            with Image.open(uploaded.stream) as image:
                image.verify()
            uploaded.stream.seek(0)
            with Image.open(uploaded.stream) as image:
                image = ImageOps.exif_transpose(image).convert("RGB")
                image.thumbnail((1600, 2400))
                image.save(filepath, "JPEG", quality=88, optimize=True)
        except (
            UnidentifiedImageError,
            Image.DecompressionBombError,
            OSError,
            ValueError,
        ):
            try:
                os.remove(filepath)
            except FileNotFoundError:
                pass
            except OSError:
                app.logger.exception("Unable to clean up an invalid story image.")
            flash("The selected file is not a valid image.", "error")
            return redirect(url_for("feed"))
        media_type = "image"
    else:
        signature = uploaded.stream.read(12)
        uploaded.stream.seek(0)
        is_mp4 = extension == "mp4" and signature[4:8] == b"ftyp"
        is_webm = extension == "webm" and signature.startswith(b"\x1aE\xdf\xa3")
        if not is_mp4 and not is_webm:
            flash("The selected file is not a valid MP4 or WebM video.", "error")
            return redirect(url_for("feed"))

        filename = f"{uuid.uuid4().hex}.{extension}"
        filepath = os.path.join(app.config["STORY_UPLOAD_FOLDER"], filename)
        uploaded.save(filepath)
        media_type = "video"

    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            """
            INSERT INTO stories
                (user_id, media_path, media_type, caption, overlay_text, expires_at)
            VALUES (%s, %s, %s, %s, %s, DATE_ADD(NOW(), INTERVAL 24 HOUR))
            """,
            (session["user_id"], filename, media_type, caption, overlay_text),
        )
        conn.commit()
    except Exception:
        conn.rollback()
        if os.path.exists(filepath):
            os.remove(filepath)
        raise
    finally:
        cursor.close()
        conn.close()

    flash("Your story is live for 24 hours.", "success")
    return redirect(url_for("feed"))


@app.route("/story/<int:story_id>/view", methods=["POST"])
@login_required
def view_story(story_id):
    user_id = session["user_id"]
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute(
            """
            SELECT s.id, s.user_id
            FROM stories s
            JOIN users u ON u.id=s.user_id
            WHERE s.id=%s
              AND s.expires_at > NOW()
              AND u.is_verified=1
              AND (
                  s.user_id=%s
                  OR EXISTS(
                      SELECT 1 FROM follows f
                      WHERE f.follower_id=%s AND f.followed_id=s.user_id
                  )
              )
            """,
            (story_id, user_id, user_id),
        )
        story = cursor.fetchone()
        if not story:
            abort(404)

        if story["user_id"] != user_id:
            cursor.execute(
                """
                INSERT IGNORE INTO story_views (story_id, viewer_id)
                VALUES (%s, %s)
                """,
                (story_id, user_id),
            )
            conn.commit()

        cursor.execute(
            "SELECT COUNT(*) AS viewer_count FROM story_views WHERE story_id=%s",
            (story_id,),
        )
        viewer_count = cursor.fetchone()["viewer_count"]
        return jsonify({"viewed": True, "viewer_count": viewer_count})
    except Exception:
        conn.rollback()
        raise
    finally:
        cursor.close()
        conn.close()


@app.route("/story/<int:story_id>/viewers")
@login_required
def story_viewers(story_id):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute(
            "SELECT user_id FROM stories WHERE id=%s AND expires_at > NOW()",
            (story_id,),
        )
        story = cursor.fetchone()
        if not story:
            abort(404)
        if story["user_id"] != session["user_id"]:
            abort(403)

        cursor.execute(
            """
            SELECT u.username, u.profile_image, sv.viewed_at
            FROM story_views sv
            JOIN users u ON u.id=sv.viewer_id
            WHERE sv.story_id=%s
            ORDER BY sv.viewed_at DESC
            LIMIT 200
            """,
            (story_id,),
        )
        viewers = cursor.fetchall()
        return jsonify({
            "viewers": [
                {
                    "username": viewer["username"],
                    "profile_image": (
                        url_for("static", filename="uploads/" + viewer["profile_image"])
                        if viewer["profile_image"] else None
                    ),
                    "viewed_at": viewer["viewed_at"].strftime("%b %d, %I:%M %p"),
                }
                for viewer in viewers
            ]
        })
    finally:
        cursor.close()
        conn.close()


@app.route("/story/<int:story_id>/delete", methods=["POST"])
@login_required
def delete_story(story_id):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute(
            "SELECT user_id, media_path FROM stories WHERE id=%s",
            (story_id,),
        )
        story = cursor.fetchone()
        if not story:
            abort(404)
        if story["user_id"] != session["user_id"]:
            abort(403)

        cursor.execute("DELETE FROM stories WHERE id=%s", (story_id,))
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        cursor.close()
        conn.close()

    filepath = get_media_file_path(app.config["STORY_UPLOAD_FOLDER"], story.get("media_path"))
    if filepath is not None:
        try:
            os.remove(filepath)
        except FileNotFoundError:
            pass
        except OSError:
            app.logger.exception("Unable to remove media for deleted story %s", story_id)
            flash("Story deleted, but its media file could not be removed.", "error")
            return redirect(url_for("feed"))

    flash("Story deleted.", "success")
    return redirect(url_for("feed"))


@app.route("/story/<int:story_id>/reply", methods=["POST"])
@login_required
def reply_to_story(story_id):
    message_text = request.form.get("message_text", "").strip()
    if not message_text or len(message_text) > 2000:
        return jsonify({"error": "Replies must contain 1–2000 characters."}), 400

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute(
            """
            SELECT s.user_id, u.username
            FROM stories s
            JOIN users u ON u.id=s.user_id
            WHERE s.id=%s AND s.expires_at > NOW() AND u.is_verified=1
              AND (
                  s.user_id=%s
                  OR EXISTS(
                      SELECT 1 FROM follows f
                      WHERE f.follower_id=%s AND f.followed_id=s.user_id
                  )
              )
            """,
            (story_id, session["user_id"], session["user_id"]),
        )
        story = cursor.fetchone()
        if not story:
            return jsonify({"error": "This story has expired or is unavailable."}), 404
        if story["user_id"] == session["user_id"]:
            return jsonify({"error": "You cannot reply to your own story."}), 400

        cursor.execute(
            """
            INSERT INTO direct_messages (sender_id, recipient_id, message_text)
            VALUES (%s, %s, %s)
            """,
            (session["user_id"], story["user_id"], message_text),
        )
        message_id = cursor.lastrowid
        cursor.execute(
            """
            INSERT INTO notifications
                (recipient_id, actor_id, notification_type, message_id)
            VALUES (%s, %s, 'message', %s)
            """,
            (story["user_id"], session["user_id"], message_id),
        )
        conn.commit()
        return jsonify({"sent": True, "message": "Reply sent."})
    except Exception:
        conn.rollback()
        raise
    finally:
        cursor.close()
        conn.close()


# ---------------- CREATE POST ----------------

@app.route("/create-post", methods=["GET", "POST"])
@login_required
def create_post():
    if request.method == "POST":
        uploaded = request.files.get("image")
        caption = request.form.get("caption", "").strip()

        if not uploaded or not uploaded.filename:
            flash("Select an image first.")
            return render_template("create_post.html")

        extension = uploaded.filename.rsplit(".", 1)[-1].lower()

        if "." not in uploaded.filename or extension not in ALLOWED_EXTENSIONS:
            flash("Use a JPG, PNG, or WebP image.")
            return render_template("create_post.html")

        filename = f"{uuid.uuid4().hex}.jpg"
        filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)

        try:
            uploaded.stream.seek(0)
            with Image.open(uploaded.stream) as image:
                image.verify()

            uploaded.stream.seek(0)
            with Image.open(uploaded.stream) as image:
                image = image.convert("RGB")
                image.thumbnail((1600, 1600))
                image.save(filepath, "JPEG", quality=88, optimize=True)

        except (UnidentifiedImageError, OSError, ValueError):
            flash("The selected file is not a valid image.")
            return render_template("create_post.html")

        conn = get_db_connection()
        cursor = conn.cursor()

        try:
            cursor.execute(
                """
                INSERT INTO posts (user_id, image_filename, caption)
                VALUES (%s, %s, %s)
                """,
                (session["user_id"], filename, caption),
            )
            conn.commit()

        except Exception:
            conn.rollback()
            if os.path.exists(filepath):
                os.remove(filepath)
            raise

        finally:
            cursor.close()
            conn.close()

        flash("Post published successfully.")
        return redirect(url_for("feed"))

    return render_template("create_post.html")


@app.route("/post/<int:post_id>/edit", methods=["GET", "POST"])
@login_required
def edit_post(post_id):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        cursor.execute(
            "SELECT id, user_id, image_filename, caption FROM posts WHERE id=%s",
            (post_id,),
        )
        post = cursor.fetchone()

        if not post:
            abort(404)
        if post["user_id"] != session["user_id"]:
            abort(403)

        if request.method == "POST":
            caption = request.form.get("caption", "").strip()
            if len(caption) > 2200:
                flash("Captions must be 2200 characters or fewer.", "error")
                post["caption"] = caption
                return render_template("edit_post.html", post=post)

            cursor.execute(
                "UPDATE posts SET caption=%s WHERE id=%s AND user_id=%s",
                (caption, post_id, session["user_id"]),
            )
            conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        cursor.close()
        conn.close()

    if request.method == "POST":
        flash("Post updated successfully.", "success")
        return redirect(url_for("profile", username=session["username"]))

    return render_template("edit_post.html", post=post)


@app.route("/post/<int:post_id>/delete", methods=["POST"])
@login_required
def delete_post(post_id):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        cursor.execute(
            "SELECT user_id, image_filename FROM posts WHERE id=%s",
            (post_id,),
        )
        post = cursor.fetchone()

        if not post:
            abort(404)
        if post["user_id"] != session["user_id"]:
            abort(403)

        cursor.execute(
            "DELETE FROM posts WHERE id=%s AND user_id=%s",
            (post_id, session["user_id"]),
        )
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        cursor.close()
        conn.close()

    image_path = get_media_file_path(app.config["UPLOAD_FOLDER"], post.get("image_filename"))
    if image_path is not None:
        try:
            os.remove(image_path)
        except FileNotFoundError:
            pass
        except OSError:
            app.logger.exception("Unable to remove image for deleted post %s", post_id)
            flash("Post deleted, but its image file could not be removed.", "error")
            return redirect(url_for("profile", username=session["username"]))

    flash("Post deleted successfully.", "success")
    return redirect(url_for("profile", username=session["username"]))


@app.route("/reel/<int:reel_id>/delete", methods=["POST"])
@login_required
def delete_reel(reel_id):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        cursor.execute(
            "SELECT user_id, video_filename FROM reels WHERE id=%s",
            (reel_id,),
        )
        reel = cursor.fetchone()

        if not reel:
            abort(404)
        if reel["user_id"] != session["user_id"]:
            abort(403)

        cursor.execute(
            "DELETE FROM reels WHERE id=%s AND user_id=%s",
            (reel_id, session["user_id"]),
        )
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        cursor.close()
        conn.close()

    video_path = get_media_file_path(app.config["REEL_UPLOAD_FOLDER"], reel.get("video_filename"))
    if video_path is not None:
        try:
            os.remove(video_path)
        except FileNotFoundError:
            pass
        except OSError:
            app.logger.exception("Unable to remove video for deleted reel %s", reel_id)
            flash("Reel deleted, but its video file could not be removed.", "error")
            if request.form.get("next") == "reels":
                return redirect(url_for("reels"))
            return redirect(url_for("profile", username=session["username"]))

    flash("Reel deleted successfully.", "success")
    if request.form.get("next") == "reels":
        return redirect(url_for("reels"))
    return redirect(url_for("profile", username=session["username"]))


@app.route("/reel/<int:reel_id>/edit", methods=["GET", "POST"])
@login_required
def edit_reel(reel_id):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        cursor.execute(
            "SELECT id, user_id, video_filename, caption FROM reels WHERE id=%s",
            (reel_id,),
        )
        reel = cursor.fetchone()

        if not reel:
            abort(404)
        if reel["user_id"] != session["user_id"]:
            abort(403)

        if request.method == "POST":
            caption = request.form.get("caption", "").strip()
            if len(caption) > 500:
                flash("Reel captions must be 500 characters or fewer.", "error")
                reel["caption"] = caption
                return render_template("edit_reel.html", reel=reel)

            cursor.execute(
                "UPDATE reels SET caption=%s WHERE id=%s AND user_id=%s",
                (caption, reel_id, session["user_id"]),
            )
            conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        cursor.close()
        conn.close()

    if request.method == "POST":
        flash("Reel updated successfully.", "success")
        return redirect(url_for("profile", username=session["username"]))

    return render_template("edit_reel.html", reel=reel)


@app.route("/reels", methods=["GET", "POST"])
@login_required
def reels():
    if request.method == "POST":
        uploaded = request.files.get("video")
        caption = request.form.get("caption", "").strip()

        if not uploaded or not uploaded.filename:
            flash("Choose a video to share.", "error")
            return redirect(url_for("reels"))
        if len(caption) > 500:
            flash("Reel captions must be 500 characters or fewer.", "error")
            return redirect(url_for("reels"))

        extension = uploaded.filename.rsplit(".", 1)[-1].lower()
        if "." not in uploaded.filename or extension not in ALLOWED_REEL_EXTENSIONS:
            flash("Use an MP4 or WebM video.", "error")
            return redirect(url_for("reels"))

        uploaded.stream.seek(0, os.SEEK_END)
        upload_size = uploaded.stream.tell()
        uploaded.stream.seek(0)
        if upload_size > app.config["REEL_MAX_UPLOAD_BYTES"]:
            flash("Videos must be 25 MB or smaller.", "error")
            return redirect(url_for("reels"))

        signature = uploaded.stream.read(12)
        uploaded.stream.seek(0)
        is_mp4 = extension == "mp4" and signature[4:8] == b"ftyp"
        is_webm = extension == "webm" and signature.startswith(b"\x1aE\xdf\xa3")
        if not is_mp4 and not is_webm:
            flash("The selected file is not a valid MP4 or WebM video.", "error")
            return redirect(url_for("reels"))

        filename = f"{uuid.uuid4().hex}.{extension}"
        filepath = os.path.join(app.config["REEL_UPLOAD_FOLDER"], filename)
        uploaded.save(filepath)

        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            cursor.execute(
                """
                INSERT INTO reels (user_id, video_filename, caption)
                VALUES (%s, %s, %s)
                """,
                (session["user_id"], filename, caption),
            )
            conn.commit()
        except Exception:
            conn.rollback()
            if os.path.exists(filepath):
                os.remove(filepath)
            raise
        finally:
            cursor.close()
            conn.close()

        flash("Your reel is live.", "success")
        return redirect(url_for("reels"))

    search_query = request.args.get("q", "").strip()[:100]
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        query = """
            SELECT r.id, r.user_id, r.video_filename, r.caption, r.created_at,
                   u.username, u.profile_image,
                   EXISTS(
                       SELECT 1 FROM follows f
                       WHERE f.follower_id=%s AND f.followed_id=u.id
                   ) AS followed_by_me
            FROM reels r
            JOIN users u ON u.id = r.user_id
            WHERE u.is_verified=1
        """
        params = [session["user_id"]]
        if search_query:
            query += " AND (r.caption LIKE %s OR u.username LIKE %s)"
            search_pattern = f"%{search_query}%"
            params.extend((search_pattern, search_pattern))
        query += " ORDER BY r.created_at DESC, r.id DESC LIMIT 50"
        cursor.execute(query, params)
        reel_items = cursor.fetchall()
    finally:
        cursor.close()
        conn.close()

    return render_template(
        "reels.html",
        reels=reel_items,
        search_query=search_query,
    )


# ---------------- LIKE / UNLIKE ----------------

@app.route("/post/<int:post_id>/like", methods=["POST"])
@login_required
def toggle_like(post_id):
    user_id = session["user_id"]
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        cursor.execute(
            "SELECT id, user_id FROM posts WHERE id = %s",
            (post_id,),
        )
        post = cursor.fetchone()
        if not post:
            abort(404)

        cursor.execute(
            "SELECT user_id FROM likes WHERE user_id=%s AND post_id=%s",
            (user_id, post_id),
        )

        if cursor.fetchone():
            cursor.execute(
                "DELETE FROM likes WHERE user_id=%s AND post_id=%s",
                (user_id, post_id),
            )
        else:
            cursor.execute(
                "INSERT INTO likes (user_id, post_id) VALUES (%s, %s)",
                (user_id, post_id),
            )
            if post["user_id"] != user_id:
                cursor.execute(
                    """
                    INSERT INTO notifications
                        (recipient_id, actor_id, notification_type, post_id)
                    VALUES (%s, %s, 'like', %s)
                    """,
                    (post["user_id"], user_id, post_id),
                )

        conn.commit()

    except Exception:
        conn.rollback()
        raise

    finally:
        cursor.close()
        conn.close()

    return redirect(url_for("feed"))


# ---------------- COMMENTS ----------------

@app.route("/post/<int:post_id>/comment", methods=["POST"])
@login_required
def add_comment(post_id):
    comment = request.form.get("comment_text", "").strip()

    if not comment or len(comment) > 1000:
        flash("Comment must contain 1–1000 characters.")
        return redirect(url_for("feed"))

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        cursor.execute("SELECT user_id FROM posts WHERE id=%s", (post_id,))
        post = cursor.fetchone()
        if not post:
            abort(404)

        cursor.execute(
            """
            INSERT INTO comments (user_id, post_id, comment_text)
            VALUES (%s, %s, %s)
            """,
            (session["user_id"], post_id, comment),
        )
        if post["user_id"] != session["user_id"]:
            cursor.execute(
                """
                INSERT INTO notifications
                    (recipient_id, actor_id, notification_type, post_id)
                VALUES (%s, %s, 'comment', %s)
                """,
                (post["user_id"], session["user_id"], post_id),
            )
        conn.commit()

    except Exception:
        conn.rollback()
        raise

    finally:
        cursor.close()
        conn.close()

    return redirect(url_for("feed"))


# ---------------- FOLLOW / UNFOLLOW ----------------

@app.route("/user/<int:target_id>/follow", methods=["POST"])
@login_required
def toggle_follow(target_id):
    user_id = session["user_id"]

    if user_id == target_id:
        flash("You cannot follow yourself.")
        return redirect(url_for("feed"))

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        cursor.execute(
            "SELECT id, username FROM users WHERE id=%s",
            (target_id,),
        )
        target = cursor.fetchone()
        if not target:
            abort(404)

        cursor.execute(
            """
            SELECT follower_id FROM follows
            WHERE follower_id=%s AND followed_id=%s
            """,
            (user_id, target_id),
        )

        if cursor.fetchone():
            cursor.execute(
                """
                DELETE FROM follows
                WHERE follower_id=%s AND followed_id=%s
                """,
                (user_id, target_id),
            )
        else:
            cursor.execute(
                """
                INSERT INTO follows (follower_id, followed_id)
                VALUES (%s, %s)
                """,
                (user_id, target_id),
            )
            cursor.execute(
                """
                INSERT INTO notifications
                    (recipient_id, actor_id, notification_type)
                VALUES (%s, %s, 'follow')
                """,
                (target_id, user_id),
            )

        conn.commit()

    except Exception:
        conn.rollback()
        raise

    finally:
        cursor.close()
        conn.close()

    if request.form.get("return_to") == "profile":
        return redirect(url_for("profile", username=target["username"]))
    if request.form.get("return_to") == "reels":
        return redirect(url_for("reels"))
    if request.form.get("return_to") == "search":
        return redirect(url_for("search", q=request.form.get("q", "")[:100]))
    return redirect(url_for("feed"))


# ---------------- PROFILE ----------------

@app.route("/profile/<username>")
@login_required
def profile(username):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        cursor.execute(
            "SELECT id, username, full_name, bio, website, profile_image, "
            "is_verified, created_at "
            "FROM users WHERE username=%s",
            (username.lower(),),
        )
        user = cursor.fetchone()

        if not user:
            abort(404)

        cursor.execute(
            "SELECT COUNT(*) AS total FROM posts WHERE user_id=%s",
            (user["id"],),
        )
        user["post_count"] = cursor.fetchone()["total"]

        cursor.execute(
            "SELECT COUNT(*) AS total FROM reels WHERE user_id=%s",
            (user["id"],),
        )
        user["reel_count"] = cursor.fetchone()["total"]

        cursor.execute(
            "SELECT COUNT(*) AS total FROM follows WHERE followed_id=%s",
            (user["id"],),
        )
        user["follower_count"] = cursor.fetchone()["total"]

        cursor.execute(
            "SELECT COUNT(*) AS total FROM follows WHERE follower_id=%s",
            (user["id"],),
        )
        user["following_count"] = cursor.fetchone()["total"]

        cursor.execute(
            """
            SELECT EXISTS(
                SELECT 1 FROM follows
                WHERE follower_id=%s AND followed_id=%s
            ) AS is_following
            """,
            (session["user_id"], user["id"]),
        )
        is_following = bool(cursor.fetchone()["is_following"])

        cursor.execute(
            """
            SELECT p.id, p.image_filename, p.caption, p.created_at,
                   (SELECT COUNT(*) FROM likes l
                    WHERE l.post_id=p.id) AS like_count,
                   (SELECT COUNT(*) FROM comments c
                    WHERE c.post_id=p.id) AS comment_count
            FROM posts p
            WHERE p.user_id=%s
            ORDER BY p.created_at DESC, p.id DESC
            """,
            (user["id"],),
        )
        posts = cursor.fetchall()

        cursor.execute(
            """
            SELECT id, video_filename, caption, created_at
            FROM reels WHERE user_id=%s
            ORDER BY created_at DESC, id DESC
            """,
            (user["id"],),
        )
        reels = cursor.fetchall()

        cursor.execute(
            """
            SELECT p.id, p.image_filename, p.caption, p.created_at,
                   u.username AS owner_username,
                   (SELECT COUNT(*) FROM likes l
                    WHERE l.post_id=p.id) AS like_count,
                   (SELECT COUNT(*) FROM comments c
                    WHERE c.post_id=p.id) AS comment_count
            FROM post_tags pt
            JOIN posts p ON p.id=pt.post_id
            JOIN users u ON u.id=p.user_id
            WHERE pt.user_id=%s
            ORDER BY pt.created_at DESC, p.id DESC
            """,
            (user["id"],),
        )
        tagged_posts = cursor.fetchall()

    finally:
        cursor.close()
        conn.close()

    return render_template(
        "profile.html",
        user=user,
        posts=posts,
        reels=reels,
        tagged_posts=tagged_posts,
        is_owner=user["id"] == session["user_id"],
        is_following=is_following,
    )


@app.route("/settings/profile", methods=["GET", "POST"])
@login_required
def edit_profile():
    if request.method == "POST":
        full_name = request.form.get("full_name", "").strip()
        bio = request.form.get("bio", "").strip()
        website = request.form.get("website", "").strip()

        if len(full_name) > 100:
            flash("Your name must be 100 characters or fewer.", "error")
            return render_template(
                "edit_profile.html",
                profile_data={
                    "full_name": full_name,
                    "bio": bio,
                    "website": website,
                },
            )
        if len(bio) > 300:
            flash("Your bio must be 300 characters or fewer.", "error")
            return render_template(
                "edit_profile.html",
                profile_data={
                    "full_name": full_name,
                    "bio": bio,
                    "website": website,
                },
            )

        normalized_website = None
        if website:
            if len(website) > 2048:
                flash("Your website URL must be 2,048 characters or fewer.", "error")
                return render_template(
                    "edit_profile.html",
                    profile_data={
                        "full_name": full_name,
                        "bio": bio,
                        "website": website,
                    },
                )
            if "://" not in website:
                website = f"https://{website}"
            if len(website) > 2048:
                flash("Your website URL must be 2,048 characters or fewer.", "error")
                return render_template(
                    "edit_profile.html",
                    profile_data={
                        "full_name": full_name,
                        "bio": bio,
                        "website": request.form.get("website", "").strip(),
                    },
                )
            try:
                parsed_website = urlsplit(website)
                if (
                    parsed_website.scheme not in {"http", "https"}
                    or not parsed_website.hostname
                    or parsed_website.username
                    or parsed_website.password
                ):
                    raise ValueError
                parsed_website.port
            except ValueError:
                flash("Enter a valid website URL beginning with http:// or https://.", "error")
                return render_template(
                    "edit_profile.html",
                    profile_data={
                        "full_name": full_name,
                        "bio": bio,
                        "website": request.form.get("website", "").strip(),
                    },
                )
            normalized_website = website

        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            cursor.execute(
                """
                UPDATE users
                SET full_name=%s, bio=%s, website=%s
                WHERE id=%s
                """,
                (full_name, bio, normalized_website, session["user_id"]),
            )
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            cursor.close()
            conn.close()

        flash("Your profile has been updated.", "success")
        return redirect(url_for("profile", username=session["username"]))

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute(
            "SELECT full_name, bio, website FROM users WHERE id=%s",
            (session["user_id"],),
        )
        profile_data = cursor.fetchone()
        if not profile_data:
            abort(404)
    finally:
        cursor.close()
        conn.close()

    return render_template("edit_profile.html", profile_data=profile_data)


@app.route("/post/<int:post_id>/tag", methods=["POST"])
@login_required
def tag_post(post_id):
    username = request.form.get("username", "").strip().lstrip("@").lower()
    if not username or len(username) > 30:
        flash("Enter a valid username to tag.", "error")
        return redirect(url_for("profile", username=session["username"]))

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute(
            "SELECT id FROM posts WHERE id=%s AND user_id=%s",
            (post_id, session["user_id"]),
        )
        if not cursor.fetchone():
            abort(404)

        cursor.execute(
            "SELECT id FROM users WHERE username=%s AND is_verified=1",
            (username,),
        )
        tagged_user = cursor.fetchone()
        if not tagged_user:
            flash("No verified account was found with that username.", "error")
            return redirect(url_for("profile", username=session["username"]))

        cursor.execute(
            """
            INSERT INTO post_tags (post_id, user_id)
            VALUES (%s, %s)
            """,
            (post_id, tagged_user["id"]),
        )
        conn.commit()
    except mysql.connector.IntegrityError:
        conn.rollback()
        flash("That person is already tagged in this post.", "error")
    except Exception:
        conn.rollback()
        raise
    finally:
        cursor.close()
        conn.close()

    return redirect(url_for("profile", username=session["username"]))


@app.route("/post/<int:post_id>/tag/remove", methods=["POST"])
@login_required
def remove_post_tag(post_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "DELETE FROM post_tags WHERE post_id=%s AND user_id=%s",
            (post_id, session["user_id"]),
        )
        if cursor.rowcount == 0:
            abort(404)
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        cursor.close()
        conn.close()

    flash("You were removed from the tagged post.", "success")
    return redirect(url_for("profile", username=session["username"]))


@app.route("/profile/<username>/photo", methods=["POST"])
@login_required
def update_profile_photo(username):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        cursor.execute(
            "SELECT username FROM users WHERE id=%s",
            (session["user_id"],),
        )
        user = cursor.fetchone()

        if not user:
            abort(404)
        if user["username"].lower() != username.lower():
            abort(403)

        uploaded = request.files.get("profile_image")
        if not uploaded or not uploaded.filename:
            flash("Select a profile photo first.", "error")
            return redirect(url_for("profile", username=user["username"]))

        extension = uploaded.filename.rsplit(".", 1)[-1].lower()
        if "." not in uploaded.filename or extension not in ALLOWED_EXTENSIONS:
            flash("Use a JPG, PNG, or WebP image.", "error")
            return redirect(url_for("profile", username=user["username"]))

        filename = f"{uuid.uuid4().hex}.jpg"
        filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)

        try:
            uploaded.stream.seek(0)
            with Image.open(uploaded.stream) as image:
                image.verify()

            uploaded.stream.seek(0)
            with Image.open(uploaded.stream) as image:
                image = ImageOps.exif_transpose(image).convert("RGB")
                image = ImageOps.fit(image, (512, 512))
                image.save(filepath, "JPEG", quality=88, optimize=True)

        except (Image.DecompressionBombError, UnidentifiedImageError, OSError, ValueError):
            if os.path.exists(filepath):
                os.remove(filepath)
            flash("The selected file is not a valid image.", "error")
            return redirect(url_for("profile", username=user["username"]))

        try:
            cursor.execute(
                "UPDATE users SET profile_image=%s WHERE id=%s",
                (filename, session["user_id"]),
            )
            conn.commit()
        except Exception:
            conn.rollback()
            if os.path.exists(filepath):
                os.remove(filepath)
            raise

        flash("Profile photo updated.", "success")
        return redirect(url_for("profile", username=user["username"]))

    finally:
        cursor.close()
        conn.close()


@app.route("/search")
@login_required
def search():
    query = request.args.get("q", "").strip()[:100]
    users = []
    discovery_posts = []

    if query:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        try:
            cursor.execute(
                """
                SELECT id, username, full_name, bio, profile_image,
                       EXISTS(
                           SELECT 1 FROM follows f
                           WHERE f.follower_id=%s AND f.followed_id=users.id
                       ) AS followed_by_me
                FROM users
                WHERE is_verified=1
                    AND (username LIKE %s OR full_name LIKE %s)
                ORDER BY username
                LIMIT 50
                """,
                (session["user_id"], f"%{query}%", f"%{query}%"),
            )
            users = cursor.fetchall()

            cursor.execute(
                """
                SELECT p.id, p.user_id, p.image_filename, p.caption,
                       p.created_at, u.username,
                       (SELECT COUNT(*) FROM likes l
                        WHERE l.post_id=p.id) AS like_count,
                       (SELECT COUNT(*) FROM comments c
                        WHERE c.post_id=p.id) AS comment_count
                FROM posts p
                JOIN users u ON u.id=p.user_id
                WHERE u.is_verified=1
                  AND (p.caption LIKE %s OR u.username LIKE %s)
                ORDER BY p.created_at DESC, p.id DESC
                LIMIT 36
                """,
                (f"%{query}%", f"%{query}%"),
            )
            discovery_posts = cursor.fetchall()
        finally:
            cursor.close()
            conn.close()
    else:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        try:
            cursor.execute(
                """
                SELECT p.id, p.user_id, p.image_filename, p.caption,
                       p.created_at, u.username,
                       (SELECT COUNT(*) FROM likes l
                        WHERE l.post_id=p.id) AS like_count,
                       (SELECT COUNT(*) FROM comments c
                        WHERE c.post_id=p.id) AS comment_count
                FROM posts p
                JOIN users u ON u.id=p.user_id
                WHERE u.is_verified=1
                ORDER BY p.created_at DESC, p.id DESC
                LIMIT 36
                """
            )
            discovery_posts = cursor.fetchall()
        finally:
            cursor.close()
            conn.close()

    return render_template(
        "search.html",
        query=query,
        users=users,
        discovery_posts=discovery_posts,
    )


@app.route("/messages", methods=["GET", "POST"])
@login_required
def messages():
    user_id = session["user_id"]
    source = request.form if request.method == "POST" else request.args
    recipient_username = source.get("to", "").strip().lower()[:30]
    recipient = None
    messages = []
    conversations = []
    recipient_not_found = False

    if request.method == "POST":
        message_text = request.form.get("message_text", "").strip()
        if not recipient_username:
            flash("Choose a recipient before sending a message.", "error")
            return redirect(url_for("messages"))
        if not message_text or len(message_text) > 2000:
            flash("Messages must contain 1–2000 characters.", "error")
            return redirect(url_for("messages", to=recipient_username))

        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        try:
            cursor.execute(
                "SELECT id, username, profile_image FROM users "
                "WHERE username=%s AND is_verified=1",
                (recipient_username,),
            )
            recipient = cursor.fetchone()
            if not recipient:
                flash("That username is not a verified account.", "error")
                return redirect(url_for("messages"))
            if recipient["id"] == user_id:
                flash("You cannot send a message to yourself.", "error")
                return redirect(url_for("messages"))

            cursor.execute(
                """
                INSERT INTO direct_messages (sender_id, recipient_id, message_text)
                VALUES (%s, %s, %s)
                """,
                (user_id, recipient["id"], message_text),
            )
            message_id = cursor.lastrowid
            cursor.execute(
                """
                INSERT INTO notifications
                    (recipient_id, actor_id, notification_type, message_id)
                VALUES (%s, %s, 'message', %s)
                """,
                (recipient["id"], user_id, message_id),
            )
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            cursor.close()
            conn.close()

        flash("Message sent.", "success")
        return redirect(url_for("messages", to=recipient["username"]))

    if recipient_username:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        try:
            cursor.execute(
                """
                SELECT id, username, profile_image
                FROM users
                WHERE username=%s AND is_verified=1
                """,
                (recipient_username,),
            )
            recipient = cursor.fetchone()
            if recipient:
                cursor.execute(
                    """
                    UPDATE notifications
                    SET is_read=1
                    WHERE recipient_id=%s AND actor_id=%s
                      AND notification_type='message' AND is_read=0
                    """,
                    (user_id, recipient["id"]),
                )
                conn.commit()
                cursor.execute(
                    """
                    SELECT dm.sender_id, dm.message_text, dm.created_at,
                           sender.username AS sender_username
                    FROM direct_messages dm
                    JOIN users sender ON sender.id = dm.sender_id
                    WHERE (dm.sender_id=%s AND dm.recipient_id=%s)
                       OR (dm.sender_id=%s AND dm.recipient_id=%s)
                    ORDER BY dm.id DESC
                    LIMIT 200
                    """,
                    (user_id, recipient["id"], recipient["id"], user_id),
                )
                messages = cursor.fetchall()
                messages.reverse()
        finally:
            cursor.close()
            conn.close()

        recipient_not_found = recipient is None

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute(
            """
            SELECT u.id, u.username, u.profile_image,
                   dm.message_text AS last_message,
                   dm.sender_id AS last_sender_id,
                   dm.created_at AS last_message_at,
                   (
                       SELECT COUNT(*)
                       FROM notifications n
                       WHERE n.recipient_id=%s AND n.actor_id=u.id
                         AND n.notification_type='message' AND n.is_read=0
                   ) AS unread_count
            FROM (
                SELECT CASE
                           WHEN sender_id=%s THEN recipient_id
                           ELSE sender_id
                       END AS other_user_id,
                       MAX(id) AS last_message_id
                FROM direct_messages
                WHERE sender_id=%s OR recipient_id=%s
                GROUP BY other_user_id
            ) recent
            JOIN direct_messages dm ON dm.id=recent.last_message_id
            JOIN users u ON u.id=recent.other_user_id
            WHERE u.is_verified=1
            ORDER BY dm.id DESC
            LIMIT 50
            """,
            (user_id, user_id, user_id, user_id),
        )
        conversations = cursor.fetchall()
    finally:
        cursor.close()
        conn.close()

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute(
            "SELECT username, profile_image FROM users WHERE id=%s",
            (user_id,),
        )
        current_user = cursor.fetchone()
    finally:
        cursor.close()
        conn.close()

    return render_template(
        "messages.html",
        recipient=recipient,
        recipient_username=recipient_username,
        recipient_not_found=recipient_not_found,
        messages=messages,
        conversations=conversations,
        current_user_id=user_id,
        current_user=current_user,
    )


@app.route("/notifications")
@login_required
def notifications():
    user_id = session["user_id"]
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute(
            """
            SELECT n.id, n.notification_type, n.post_id, n.message_id,
                   n.created_at, actor.username AS actor_username
            FROM notifications n
            JOIN users actor ON actor.id=n.actor_id
            WHERE n.recipient_id=%s
            ORDER BY n.created_at DESC, n.id DESC
            LIMIT 100
            """,
            (user_id,),
        )
        notification_items = cursor.fetchall()
        cursor.execute(
            "UPDATE notifications SET is_read=1 WHERE recipient_id=%s AND is_read=0",
            (user_id,),
        )
        conn.commit()
        for item in notification_items:
            item["is_read"] = True
    except Exception:
        conn.rollback()
        raise
    finally:
        cursor.close()
        conn.close()

    return render_template(
        "notifications.html",
        notifications=notification_items,
    )


if __name__ == "__main__":
    app.run(debug=False)
