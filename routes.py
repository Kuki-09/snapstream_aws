from flask import Blueprint, abort, jsonify, render_template, request, redirect, send_from_directory, url_for, session, flash
import os
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
import re
import subprocess
from datetime import datetime, timedelta
import json
import boto3
from boto3.dynamodb.conditions import Attr
import uuid

main_routes = Blueprint("main_routes", __name__)

     
ADMIN_ORG_TOKEN = "SNAPSTREAM-ADMIN-2026"
UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
EMAIL_REGEX = r"^[\w\.-]+@[\w\.-]+\.\w+$"

     
dynamodb = boto3.resource("dynamodb", region_name="us-east-1") 
sns = boto3.client("sns", region_name="us-east-1") 


USERS_TABLE = dynamodb.Table("users")
ADMINS_TABLE = dynamodb.Table("admins")
MEDIA_TABLE = dynamodb.Table("media")
ACTIVITY_TABLE = dynamodb.Table("activity")

SNS_TOPIC_ARN = "arn:aws:sns:us-east-1:509399590795:admin-system-events"

def get_user_by_email(email):
    resp = USERS_TABLE.get_item(
        Key={"email": email}
    )
    return resp.get("Item")

def create_user(name, email, password_hash):
    try:
        user = {
            "user_id": str(uuid.uuid4()),
            "email": email,
            "name": name,
            "password": password_hash,
            "created_at": datetime.utcnow().isoformat(),
            "last_login": None,
            "role": "user",
            "status": "inactive"
        }
        USERS_TABLE.put_item(Item=user)
        print(f"User created: {email}")
        return user
    except Exception as e:
        print("Error creating user:", e)
        return None

def get_admin_by_email(email):
    resp = ADMINS_TABLE.get_item(
        Key={"email": email}
    )
    return resp.get("Item")

def create_admin(email, name, password_hash):
    admin = {
        "admin_id": str(uuid.uuid4()),
        "email": email,
        "name": name,
        "password": password_hash,
        "created_at": datetime.utcnow().isoformat()
    }
    ADMINS_TABLE.put_item(Item=admin)
    return admin
def save_media(user_id, media_data):
    media = {
        "media_id": str(uuid.uuid4()),
        "user_id": user_id,
        **media_data,
        "progress": media_data.get("progress", 0),
        "ai_metadata": media_data.get("ai_metadata"),
        "date_uploaded": datetime.utcnow().isoformat()
    }
    MEDIA_TABLE.put_item(Item=media)
    return media
def get_media_for_user(user_id):
    resp = MEDIA_TABLE.scan(
        FilterExpression=Attr("user_id").eq(user_id)
    )
    return resp.get("Items", [])

def get_media_by_id(user_id, media_id):
    resp = MEDIA_TABLE.get_item(Key={"media_id": media_id})
    item = resp.get("Item")

    if not item:
        return None

    if item["user_id"] != user_id:
        return None

    return item

def delete_media_item(media):
    MEDIA_TABLE.delete_item(
        Key={"media_id": media["media_id"]}
    )

def get_media_duration(file_path):
    """
    Returns duration as string "mm:ss" using ffprobe (part of ffmpeg)
    """
    try:
        result = subprocess.run(
            [
                "ffprobe", 
                "-v", "error",
                "-show_entries", "format=duration",
                "-of", "default=noprint_wrappers=1:nokey=1",
                file_path
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            check=True
        )
        duration_seconds = float(result.stdout.strip())
        minutes = int(duration_seconds // 60)
        seconds = int(duration_seconds % 60)
        return f"{minutes:02d}:{seconds:02d}"
    except Exception as e:
        print("Error getting duration:", e)
        return "--:--"


def get_all_users():
    try:
        response = USERS_TABLE.scan()
        users = response.get("Items", [])

     
        users.sort(key=lambda x: x.get("created_at", ""), reverse=True)
        return users
    except Exception as e:
        print("Error fetching users:", e)
        return []

@main_routes.route("/")
def home():
    """Dynamic home page based on session type"""
    if "admin_email" in session:
        return redirect(url_for("main_routes.admin_dashboard"))
    elif "user_email" in session:
        return redirect(url_for("main_routes.dashboard"))
    return redirect(url_for("main_routes.login"))

@main_routes.route("/login", methods=["GET","POST"])
def login():
    if "user_email" in session:
        return redirect(url_for("main_routes.dashboard"))
    if "admin_email" in session:
        return redirect(url_for("main_routes.admin_dashboard"))

    if request.method == "POST":
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")

     
        response = USERS_TABLE.get_item(Key={"email": email})
        user = response.get("Item")

        if user:
            if user.get("status") == "suspended":
                flash("Your account has been suspended. Please contact support.", "error")
                return redirect(url_for("main_routes.login"))
            elif user.get("status") != "active":
                flash("Your account is not active. Please contact support.", "error")
                return redirect(url_for("main_routes.login"))

            if check_password_hash(user.get("password"), password):
                session["user_email"] = email
                session["user_name"] = user.get("name")
                session.pop("admin_email", None)

     
                USERS_TABLE.update_item(
                    Key={"email": email},
                    UpdateExpression="SET last_login = :login_time",
                    ExpressionAttributeValues={":login_time": datetime.utcnow().isoformat()}
                )

         
                ACTIVITY_TABLE.put_item(
                    Item={
                        "user_id": user["user_id"],
                        "timestamp": datetime.utcnow().isoformat(),
                        "type": "user_login",
                        "description": f"{user['name']} logged in",
                        "read": False
                    }
                )

                return redirect(url_for("main_routes.dashboard"))

        flash("Invalid email or password", "error")
        return redirect(url_for("main_routes.login"))

    return render_template("login.html")

@main_routes.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password")
        confirm = request.form.get("confirm")

        if not re.match(EMAIL_REGEX, email):
            flash("Please enter a valid email address", "error")
            return redirect(url_for("main_routes.signup"))

        if password != confirm:
            flash("Passwords do not match", "error")
            return redirect(url_for("main_routes.signup"))

        if len(password) < 8:
            flash("Password must be at least 8 characters long", "error")
            return redirect(url_for("main_routes.signup"))

     
        response = USERS_TABLE.get_item(Key={"email": email})
        if "Item" in response:
            flash("Email already exists", "error")
            return redirect(url_for("main_routes.signup"))

     
        user_id = str(uuid.uuid4())
        new_user = {
            "user_id": user_id,
            "email": email,
            "name": name,
            "password": generate_password_hash(password),
            "status": "active",
            "role": "user",
            "created_at": datetime.utcnow().isoformat(),
            "last_login": None
        }

        try:
            USERS_TABLE.put_item(Item=new_user)


            ACTIVITY_TABLE.put_item(
                Item={
                    "user_id": user_id,
                    "timestamp": datetime.utcnow().isoformat(),
                    "type": "user_registration",
                    "description": f"{name} registered",
                    "read": False
                }
            )

            flash("Signup successful! Please log in.", "success")
            try:
                sns.publish(
                    TopicArn=SNS_TOPIC_ARN,
                    Subject="New User Registration",
                    Message=(
                        f"A new user has signed up.\n\n"
                        f"Name: {name}\n"
                        f"Email: {email}\n"
                        f"User ID: {user_id}\n"
                        f"Time: {datetime.utcnow().isoformat()}"
                    )
                )
            except Exception as e:
                print("SNS publish failed:", e)

            return redirect(url_for("main_routes.login"))

        except Exception as e:
            print("Error creating user:", e)
            flash("An error occurred. Please try again.", "error")
            return redirect(url_for("main_routes.signup"))

    return render_template("signup.html")

@main_routes.route("/forgot_password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form.get("email", "").strip()

     
        response = USERS_TABLE.get_item(Key={"email": email})
        user = response.get("Item")

        if user:
            session['reset_email'] = user['email']
            return redirect(url_for("main_routes.reset_password"))
        else:
            flash("Email not found.", "error")
            return redirect(url_for("main_routes.forgot_password"))

    return render_template("forgot_password.html")


@main_routes.route("/reset_password", methods=["GET", "POST"])
def reset_password():
    email = session.get("reset_email")
    if not email:
        flash("Unauthorized access.", "error")
        return redirect(url_for("main_routes.login"))

    response = USERS_TABLE.get_item(
        Key={"email": email}
    )
    user = response.get("Item")

    if not user:
        session.pop("reset_email", None)
        flash("User not found.", "error")
        return redirect(url_for("main_routes.login"))

    if request.method == "POST":
        new_password = request.form.get("new_password")
        confirm_password = request.form.get("confirm_password")

        if not new_password or not confirm_password:
            flash("Please fill out all fields.", "error")
        elif new_password != confirm_password:
            flash("Passwords do not match.", "error")
        else:
     
            USERS_TABLE.update_item(
                Key={"email": user["email"]},
                UpdateExpression="SET password = :pwd",
                ExpressionAttributeValues={":pwd": generate_password_hash(new_password)}
            )
            session.pop("reset_email", None)
            flash("Password reset successful. Please log in.", "success")
            return redirect(url_for("main_routes.login"))

    return render_template("reset_password.html")

@main_routes.route("/dashboard")
def dashboard():
    if "user_email" not in session:
        return redirect(url_for("main_routes.login"))

     
    response = USERS_TABLE.get_item(Key={"email": session["user_email"]})
    user = response.get("Item")
    if not user:
        session.clear()
        flash("User not found. Please login again.")
        return redirect(url_for("main_routes.login"))

     
    response = MEDIA_TABLE.scan(
        FilterExpression=Attr("user_id").eq(user['user_id'])
    )
    all_media = response.get("Items", [])
    recent_media = sorted(all_media, key=lambda x: x.get("date_uploaded", ""), reverse=True)[:5]

     
    total_media = len(all_media)

     
    total_storage_used = sum(m.get("size", 0) for m in all_media)
    total_storage_used = round(total_storage_used, 2)

     
    initials = "".join([n[0] for n in user.get("name", "").split()]).upper() if user.get("name") else "?"

    return render_template(
        "home.html",
        username=user.get("name"),
        media=recent_media,
        initials=initials,
        total_media=total_media,
        total_storage_used=total_storage_used
    )

@main_routes.route("/profile")
def profile():
    if "user_email" not in session:
        return redirect(url_for("main_routes.login"))

     
    response = USERS_TABLE.get_item(Key={"email": session["user_email"]})
    user = response.get("Item")
    if not user:
        session.clear()
        return redirect(url_for("main_routes.login"))

     
    response = MEDIA_TABLE.scan(
        FilterExpression=Attr("user_id").eq(user["user_id"])
    )
    media_items = response.get("Items", [])

    total_media = len(media_items)
    images = len([m for m in media_items if m.get("type") == "image"])
    videos = len([m for m in media_items if m.get("type") == "video"])
    audios = len([m for m in media_items if m.get("type") == "audio"])

    initials = "".join([n[0] for n in user.get("name", "").split()]).upper() if user.get("name") else "U"

    return render_template(
        "profile.html",
        full_name=user.get("name"),
        email=user.get("email"),
        role="User",
        created_on=datetime.fromisoformat(user.get("created_at"))
            if user.get("created_at") else "",
        total_media=total_media,
        images=images,
        videos=videos,
        audios=audios,
        initials=initials,
        active="profile"
    )

@main_routes.route("/delete-account", methods=["POST"])
def delete_account():
    if "user_email" not in session:
        return redirect(url_for("main_routes.login"))

     
    response = USERS_TABLE.get_item(Key={"email": session["user_email"]})
    user = response.get("Item")

    if not user:
        session.clear()
        flash("User not found.", "error")
        return redirect(url_for("main_routes.login"))

     
    activity_item = {
        "user_id": user["user_id"],
        "timestamp": datetime.utcnow().isoformat(),
        "type": "account_deleted",
        "description": f"{user['name']} deleted their account",
        "read": False
    }
    ACTIVITY_TABLE.put_item(Item=activity_item)

     
    USERS_TABLE.delete_item(Key={"email": user["email"]})

     
    response = MEDIA_TABLE.scan(
        FilterExpression=Attr("user_id").eq(user["user_id"])
    )
    media_items = response.get("Items", [])
    for media in media_items:
        MEDIA_TABLE.delete_item(Key={"media_id": media["media_id"]})
     
        file_path = os.path.join(UPLOAD_FOLDER, media["file_path"])
        if os.path.exists(file_path):
            os.remove(file_path)

    session.clear()
    flash("Your account has been deleted successfully.", "success")
    return redirect(url_for("main_routes.login"))

@main_routes.route("/media")
def all_media():
    if "user_email" not in session:
        return redirect(url_for("main_routes.login"))

     
    response = USERS_TABLE.get_item(Key={"email": session["user_email"]})
    user = response.get("Item")

    if not user:
        session.clear()
        flash("User not found. Please login again.")
        return redirect(url_for("main_routes.login"))


    FilterExpression = Attr("user_id").eq(user['user_id']) | Attr("status").eq("Completed")

    response = MEDIA_TABLE.scan(FilterExpression=FilterExpression)

    all_media = response.get("Items", [])

     
    all_media.sort(key=lambda x: x.get("date_uploaded", ""), reverse=True)

    initials = "".join([n[0] for n in user["name"].split()]).upper() if user.get("name") else "U"

    return render_template(
        "all_media.html",
        username=user["name"],
        initials=initials,
        media=all_media
    )

@main_routes.route("/user/stats")
def user_stats():
    if "user_email" not in session:
        return jsonify({"error": "Unauthorized"}), 401

     
    response = USERS_TABLE.get_item(Key={"email": session["user_email"]})
    user = response.get("Item")
    if not user:
        return jsonify({"error": "User not found"}), 404

    user_id = user["user_id"]


     
    response = MEDIA_TABLE.scan(
        FilterExpression=Attr("user_id").eq(user_id)
    )
    user_media = response.get("Items", [])

    total_media = len(user_media)
    processing = sum(1 for m in user_media if m.get("status") == "Processing")
    completed = sum(1 for m in user_media if m.get("status") == "Completed")
    total_size = round(sum(float(m.get("size", 0)) for m in user_media), 2)

    return jsonify({
        "total_media": total_media,
        "processing": processing,
        "completed": completed,
        "storage_used": total_size
    })

@main_routes.route("/api/notifications")
def api_notifications():
    if "user_email" not in session:
        return jsonify({"error": "Unauthorized"}), 401

     
    response = USERS_TABLE.get_item(Key={"email": session["user_email"]})
    user = response.get("Item")
    if not user:
        return jsonify({"error": "User not found"}), 404

    user_id = user['user_id']

    response = ACTIVITY_TABLE.scan(
        FilterExpression=Attr("user_id").eq(user_id)
    )


    notifications = response.get("Items", [])

    notifications.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
    notifications = notifications[:6]

    unread_count = sum(1 for n in notifications if not n.get("read", False))

    result = [
        {
            "id": n.get("timestamp"),
            "type": n.get("type"),
            "description": n.get("description"),
            "timestamp": n.get("timestamp"),
            "read": n.get("read", False)
        }
        for n in notifications
    ]

    return jsonify({"notifications": result, "unread_count": unread_count})

@main_routes.route("/api/notifications/read/<timestamp>", methods=["POST"])
def mark_notification_read(timestamp):
    if "user_email" not in session:
        return jsonify({"error": "Unauthorized"}), 401

     
    response = USERS_TABLE.get_item(Key={"email": session["user_email"]})
    user = response.get("Item")
    if not user:
        return jsonify({"error": "Not found"}), 404

    user_id = user["user_id"]
    response = ACTIVITY_TABLE.get_item(
        Key={
            "user_id": user_id,
            "timestamp": timestamp
        }
    )
    notif = response.get("Item")

    if not notif or notif.get("user_id") != user_id:
        return jsonify({"error": "Not found"}), 404

     
    ACTIVITY_TABLE.update_item(
        Key={
        "user_id": user_id,
        "timestamp": timestamp
},
        UpdateExpression="SET #r = :val",
        ExpressionAttributeNames={"#r": "read"},
        ExpressionAttributeValues={":val": True}
    )

    return jsonify({"success": True})

@main_routes.route("/uploads/<path:filename>")
def uploaded_file(filename):
    folder = os.path.abspath(UPLOAD_FOLDER)
    safe_path = os.path.abspath(os.path.join(folder, filename))

     
    try:
        if os.path.commonpath([folder, safe_path]) != folder:
            return "Access Denied", 403
    except ValueError:
     
        return "Access Denied", 403

    if not os.path.exists(safe_path):
        return "File not found", 404

    return send_from_directory(folder, filename)


@main_routes.route("/upload", methods=["POST"])
def upload_media():
    if "user_email" not in session:
        return jsonify({"error": "Unauthorized"}), 401

    file = request.files.get("file")
    if not file:
        return jsonify({"error": "No file uploaded"}), 400

    filename = secure_filename(file.filename)
    ext = filename.rsplit(".", 1)[-1].lower()

    if ext in ["png","jpg","jpeg","gif","webp"]:
        media_type = "image"
    elif ext in ["mp3","wav","aac","m4a"]:
        media_type = "audio"
    elif ext in ["mp4","mov","avi","mkv"]:
        media_type = "video"
    else:
        return jsonify({"error": "Unsupported file type"}), 400

    base, ext_with_dot = os.path.splitext(filename)
    counter = 1
    upload_path = os.path.join(UPLOAD_FOLDER, filename)
    while os.path.exists(upload_path):
        filename = f"{base}_{counter}{ext_with_dot}"
        upload_path = os.path.join(UPLOAD_FOLDER, filename)
        counter += 1

    file.save(upload_path)
    if media_type in ["audio", "video"]:
        duration = get_media_duration(upload_path)
    else:
        duration = "--:--"

     
    user_resp = USERS_TABLE.get_item(Key={"email": session["user_email"]})
    user = user_resp.get("Item")
    if not user:
        return jsonify({"error": "User not found"}), 404

    media_id = str(uuid.uuid4())
    media_item = {
        "media_id": media_id,
        "user_id": user["user_id"],
        "title": filename,
        "description": "",
        "file_path": filename,
        "type": media_type,
        "size": round(os.path.getsize(upload_path)/(1024*1024), 2),
        "status": "Queued",
        "progress": 0,
        "duration": duration,
        "ai_metadata": {},
        "date_uploaded": datetime.utcnow().isoformat()
    }
    MEDIA_TABLE.put_item(Item=media_item)


    from tasks import process_media_task
    process_media_task.delay(media_id)

    ACTIVITY_TABLE.put_item(Item={
        "user_id": user['user_id'],
        "type": "media_upload",
        "description": f"{user['name']} uploaded {filename}",
        "timestamp": datetime.utcnow().isoformat(),
        "read": False
    })

    return jsonify({"message": "Upload successful", "media_id": media_id}), 201

@main_routes.route("/filter")
def filter_media():
    if "user_email" not in session:
        return jsonify([])

    user_resp = USERS_TABLE.get_item(Key={"email": session["user_email"]})
    user = user_resp.get("Item")
    if not user:
        return jsonify([])

    media_type = request.args.get("type")
    status = request.args.get("status")
    search = request.args.get("search", "").lower().strip()
    limit = request.args.get("limit", type=int)
    FilterExpression = Attr("user_id").eq(user['user_id']) | Attr("status").eq("Completed")
    response = MEDIA_TABLE.scan(FilterExpression=FilterExpression)
    results = response.get("Items", [])

    if media_type and media_type != "All Types":
        results = [m for m in results if m.get("type", "").lower() == media_type.lower()]

    if status and status != "All Status":
        results = [m for m in results if m.get("status", "").lower() == status.lower()]

    if search:
        def matches(media):
            if search in (media.get("title") or "").lower():
                return True

            meta = media.get("ai_metadata") or {}
            searchable_chunks = []

            if media.get("type") == "audio":
                searchable_chunks.extend([
                    meta.get("transcript", ""),
                    " ".join(meta.get("entities", [])),
                    meta.get("sentiment", "")
                ])
            elif media.get("type") in ["image", "video"]:
                searchable_chunks.extend([
                    " ".join(meta.get("objects", [])),
                    meta.get("text", "")
                ])

            combined_text = " ".join(searchable_chunks).lower()
            return search in combined_text

        results = list(filter(matches, results))

     
    results.sort(key=lambda m: m.get("date_uploaded") or "", reverse=True)

     
    if limit:
        results = results[:limit]

    return jsonify([
        {
            "id": m.get("media_id"),
            "title": m.get("title"),
            "description": m.get("description"),
            "file_path": m.get("file_path"),
            "img": (
                url_for(
                    "main_routes.uploaded_file",
                    filename=m.get("thumbnail_path")
                )
                if m.get("type") == "video" and m.get("thumbnail_path")
                else url_for(
                    "main_routes.uploaded_file",
                    filename=m.get("file_path")
                )
            ),

            "type": m.get("type"),
            "size": m.get("size"),
            "status": m.get("status"),
            "date_uploaded": m.get("date_uploaded")[:16].replace("T", " ") if m.get("date_uploaded") else "",
            "duration": m.get("duration"),
            "ai_metadata": m.get("ai_metadata"),
            "progress": m.get("progress")
        }
        for m in results
    ])

@main_routes.route("/media/<media_id>")
def media_details(media_id):
    if "user_email" not in session:
        return redirect(url_for("main_routes.login"))

     
    user_resp = USERS_TABLE.get_item(Key={"email": session["user_email"]})
    user = user_resp.get("Item")
    if not user:
        session.clear()
        flash("User not found. Please login again.", "error")
        return redirect(url_for("main_routes.login"))


    response = MEDIA_TABLE.scan(
            FilterExpression = (Attr("media_id").eq(media_id)) & (Attr("user_id").eq(user['user_id']) | Attr("status").eq("Completed"))

    )
    items = response.get("Items", [])
    if not items:
        abort(404)

    media = items[0]

    if isinstance(media.get("ai_metadata"), str):
        try:
            media["ai_metadata"] = json.loads(media["ai_metadata"])
        except:
            media["ai_metadata"] = {}

    return render_template("media_analysis.html", media=media)

@main_routes.route("/delete/<media_id>", methods=["DELETE"])
def delete_media(media_id):
    if "user_email" not in session:
        return jsonify({"error": "Unauthorized"}), 401


    user_resp = USERS_TABLE.get_item(Key={"email": session["user_email"]})
    user = user_resp.get("Item")
    if not user:
        return jsonify({"error": "User not found"}), 404

    resp = MEDIA_TABLE.get_item(Key={"media_id": media_id})
    media = resp.get("Item")
    if not media:
        return jsonify({"error": "Media not found"}), 404


    if media.get("user_id") != user["user_id"]:
        return jsonify({"error": "Not authorized to delete this media"}), 403

 
    file_path = os.path.join(UPLOAD_FOLDER, media.get("file_path", ""))
    if os.path.exists(file_path):
        os.remove(file_path)

  
    MEDIA_TABLE.delete_item(Key={"media_id": media_id})

   
    activity_item = {
        "user_id": user['user_id'],
        "type": "media_deleted",
        "description": f"{user['name']} deleted {media.get('title')}",
        "timestamp": datetime.utcnow().isoformat(),
        "read": False
    }
    ACTIVITY_TABLE.put_item(Item=activity_item)

    return jsonify({"message": "Media deleted successfully"}), 200


@main_routes.route("/download/<media_id>")
def download_media(media_id):
    
    response = MEDIA_TABLE.get_item(Key={"media_id": media_id})
    media = response.get("Item")
    if not media:
        abort(404)

    file_path = os.path.join(UPLOAD_FOLDER, media["file_path"])

    if not os.path.exists(file_path):
        abort(404)

    return send_from_directory(
        directory=UPLOAD_FOLDER,
        path=media["file_path"],
        as_attachment=True
    )


@main_routes.route("/admin_login", methods=["GET","POST"])
def admin_login():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]

     
        response = ADMINS_TABLE.get_item(Key={"email": email})
        admin = response.get("Item")

        if admin and check_password_hash(admin["password"], password):
            session.pop("user_name", None)
            session["admin_email"] = email
            return redirect(url_for("main_routes.admin_dashboard"))

        flash("Invalid admin credentials","error")
    return render_template("admin_login.html")

@main_routes.route("/admin_signup", methods=["GET", "POST"])
def admin_signup():
    if request.method == "POST":
        fullname = request.form["fullname"]
        email = request.form["email"]
        password = request.form["password"]
        confirm_password = request.form["confirm_password"]
        token = request.form["org_token"]

        if token != ADMIN_ORG_TOKEN:
            flash("Invalid organization token", "error")
            return redirect(url_for("main_routes.admin_signup"))

     
        response = ADMINS_TABLE.get_item(Key={"email": email})
        if "Item" in response:
            flash("Admin already exists", "error")
            return redirect(url_for("main_routes.admin_signup"))

        if password != confirm_password:
            flash("Passwords do not match", "error")
            return redirect(url_for("main_routes.admin_signup"))

     
        ADMINS_TABLE.put_item(
            Item={
                "admin_id": str(uuid.uuid4()),
                "email": email,
                "name": fullname,
                "password": generate_password_hash(password),
                "created_at": datetime.utcnow().isoformat()
            }
        )

        flash("Admin created successfully", "success")
        return redirect(url_for("main_routes.admin_login"))

    return render_template("admin_signup.html")

@main_routes.route('/admin/forgot-password', methods=['GET', 'POST'])
def admin_forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')

     
        response = ADMINS_TABLE.get_item(Key={"email": email})
        admin = response.get("Item")

        if not admin:
            flash("No admin account found with this email", "error")
            return redirect(url_for('main_routes.admin_forgot_password'))

        flash("Admin account found! You can reset your password now.", "success")
        return redirect(url_for('main_routes.admin_reset_password', email=email))

    return render_template('admin_forgot_password.html')

@main_routes.route('/admin/reset-password', methods=['GET', 'POST'])
def admin_reset_password():
    email = request.args.get('email')  

     
    response = ADMINS_TABLE.get_item(Key={"email": email})
    admin = response.get("Item")

    if not email or not admin:
        flash("Invalid or missing email", "error")
        return redirect(url_for('main_routes.admin_forgot_password'))

    if request.method == 'POST':
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        if new_password != confirm_password:
            flash("Passwords do not match", "error")
            return redirect(url_for('main_routes.admin_reset_password', email=email))

     
        ADMINS_TABLE.update_item(
            Key={"email": email},
            UpdateExpression="SET #pwd = :new_pwd",
            ExpressionAttributeNames={"#pwd": "password"},
            ExpressionAttributeValues={":new_pwd": generate_password_hash(new_password)}
        )

        flash("Password has been reset successfully!", "success")
        return redirect(url_for('main_routes.admin_login'))

    return render_template('admin_reset_password.html', email=email)

@main_routes.route("/admin_dashboard")
def admin_dashboard():
    if "admin_email" not in session:
        return redirect(url_for("main_routes.admin_login"))

    if "user_email" in session:
        session.pop("user_email", None)
        session.pop("user_name", None)

     
    response = USERS_TABLE.scan(
        FilterExpression=Attr("role").ne("admin")
    )
    users = response.get("Items", [])
     
    users.sort(key=lambda u: u.get("created_at", ""), reverse=True)

    total_users = len(users)

     
    active_users = sum(
        1 for u in users
        if u.get("last_login") and
        datetime.fromisoformat(u["last_login"]) >= datetime.utcnow() - timedelta(seconds=60)
    )

     
    response = MEDIA_TABLE.scan(
        FilterExpression=Attr("status").eq("Processing")
    )
    processing_queue = len(response.get("Items", []))

     
    response = MEDIA_TABLE.scan(
        ProjectionExpression="size"
    )
    total_storage_used = sum(m.get("size", 0) for m in response.get("Items", []))
    
     
    response = ACTIVITY_TABLE.scan(
        FilterExpression=Attr("user_id").eq("ADMIN")
    )
    recent_activity = response.get("Items", [])
     
    recent_activity.sort(key=lambda a: a.get("timestamp", ""), reverse=True)
    recent_activity = recent_activity[:6]

    return render_template(
        "admin_dashboard.html",
        active="admin",
        users=users,
        total_users=total_users,
        active_users=active_users,
        processing_queue=processing_queue,
        total_storage_used=round(total_storage_used, 2),
        recent_activity=recent_activity,
        initials="A"
    )

@main_routes.route("/admin/activity")
def admin_activity_page():
    if "admin_email" not in session:
        return redirect(url_for("main_routes.admin_login"))

     
    response = ACTIVITY_TABLE.scan(
        FilterExpression=Attr("user_id").eq("ADMIN")
    )
    all_activity = response.get("Items", [])
    
     
    all_activity.sort(key=lambda a: a.get("timestamp", ""), reverse=True)

    return render_template("admin_overview.html", activities=all_activity)

@main_routes.route("/admin/stats")
def admin_stats():
    if "admin_email" not in session:
        return jsonify({"error": "Unauthorized"}), 401

     
    response = USERS_TABLE.scan()
    users = response.get("Items", [])
    total_users = len(users)

     
    now = datetime.utcnow()
    active_users = sum(
        1 for u in users 
        if u.get("role") != "admin" and u.get("last_login") and
        datetime.fromisoformat(u["last_login"]) >= now - timedelta(seconds=60)
    )

     
    response = MEDIA_TABLE.scan(
        FilterExpression=Attr("status").eq("Processing")
    )
    processing_queue = len(response.get("Items", []))

     
    response = MEDIA_TABLE.scan()
    total_storage = sum(
        float(m.get("size", 0)) for m in response.get("Items", [])
    )

    return jsonify({
        "total_users": total_users,
        "active_users": active_users,
        "processing_queue": processing_queue,
        "total_storage_used": round(total_storage, 2)
    })

@main_routes.route("/admin/recent-activity")
def admin_recent_activity():
    if "admin_email" not in session:
        return jsonify({"error": "Unauthorized"}), 401

     
    response = ACTIVITY_TABLE.scan(
        FilterExpression=Attr("user_id").eq("ADMIN") & Attr("type").ne("user_login")
    )
    activities = response.get("Items", [])

     
    activities.sort(key=lambda x: x.get("timestamp", ""), reverse=True)

     
    activities = activities[:6]

    return jsonify([
        {
            "description": act.get("description", ""),
            "timestamp": act.get("timestamp", "")
        }
        for act in activities
    ])

@main_routes.route("/admin/analytics/storage")
def analytics_storage():
     
    response = MEDIA_TABLE.scan()
    media_items = response.get("Items", [])

     
    by_type = {}
    total_used = 0

    for m in media_items:
        media_type = m.get("type", "unknown")
        size = float(m.get("size", 0))
        total_used += size
        by_type[media_type] = by_type.get(media_type, 0) + size

    return jsonify({
        "total_used": total_used,
        "by_type": by_type
    })

@main_routes.route("/admin/analytics/processing")
def analytics_processing():
     
    response = MEDIA_TABLE.scan()
    media_items = response.get("Items", [])

    response_data = {}

    for m in media_items:
        status = m.get("status", "").lower()
        date_uploaded = m.get("date_uploaded")
        if not date_uploaded:
            continue

     
        try:
            dt = datetime.fromisoformat(date_uploaded)
        except:
            continue

     
        day = dt.strftime("%a")  

        if day not in response_data:
            response_data[day] = {}
        if status not in response_data[day]:
            response_data[day][status] = 0

        response_data[day][status] += 1

    return jsonify(response_data)

@main_routes.route("/admin/update-user-status", methods=["POST"])
def admin_update_user_status():
    if "admin_email" not in session:
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json()
    user_ids = data.get("user_ids", [])
    new_status = data.get("status")
    allowed_statuses = ["active", "inactive", "suspended"]
    if new_status not in allowed_statuses:
        return jsonify({"error": "Invalid status"}), 400

    updated = []
    admin_email = session.get("admin_email")
    admin = get_admin_by_email(admin_email)
    admin_name = admin.get("name") if admin else "Admin"

    for uid in user_ids:
     
        resp = USERS_TABLE.scan( FilterExpression=Attr("user_id").eq(str(uid)))
        user = resp.get("Items", [None])[0]
        if not user:
            continue

        old_status = user.get("status", "")
     
        USERS_TABLE.update_item(
            Key={"email": user["email"]},
            UpdateExpression="SET #s = :new_status",
            ExpressionAttributeNames={"#s": "status"},
            ExpressionAttributeValues={":new_status": new_status}
        )
        updated.append({"id": uid, "status": new_status})

     
        ACTIVITY_TABLE.put_item(
            Item={
                "user_id": "ADMIN",
                "type": "user_status_change",
                "description": f"{admin_name} changed status of {user.get('name')} from {old_status} to {new_status}",
                "timestamp": datetime.utcnow().isoformat(),
                "read": False
            }
        )
        try:
            sns.publish(
                TopicArn=SNS_TOPIC_ARN,
                Subject="User Status Updated",
                Message=f"{admin_name} changed status of {user.get('name')} to {new_status}"
            )
        except Exception as e:
             print("SNS publish failed:", e)

    return jsonify({"updated": updated})

@main_routes.route("/admin/get-users")
def get_users_api():
    if "admin_email" not in session:
        return jsonify({"error": "Unauthorized"}), 401


    response = USERS_TABLE.scan(
        FilterExpression=Attr("role").ne("admin")
    )
    users = response.get("Items", [])

    users.sort(key=lambda x: x.get("created_at", ""), reverse=True)

    return jsonify([
        {
            "id": u.get("user_id"),
            "name": u.get("name"),
            "email": u.get("email"),
            "role": u.get("role"),
            "status": u.get("status"),
            "created_at": u.get("created_at", "").split("T")[0] 
        }
        for u in users
    ])

@main_routes.route("/admin/media")
def admin_all_media():
    if "admin_email" not in session:
        return redirect(url_for("main_routes.admin_login"))

    response = MEDIA_TABLE.scan()
    all_media = response.get("Items", [])

    all_media.sort(key=lambda x: x.get("date_uploaded", ""), reverse=True)

    for media in all_media:
        if isinstance(media.get("ai_metadata"), str):
            try:
                media["ai_metadata"] = json.loads(media["ai_metadata"])
            except:
                media["ai_metadata"] = {}

    return render_template(
        "admin_all_media.html",
        media=all_media,
        initials="A"
    )

@main_routes.route("/admin/media/data")
def admin_media_data():
    if "admin_email" not in session:
        return jsonify({"error": "Unauthorized"}), 401

     
    response = MEDIA_TABLE.scan(
        FilterExpression=Attr("status").eq("Completed")
    )
    media_items = response.get("Items", [])

     
    media_items.sort(key=lambda x: x.get("date_uploaded", ""), reverse=True)

    return jsonify([
        {
           "id": m.get("media_id"),
            "title": m.get("title"),
            "file_url": url_for("main_routes.uploaded_file", filename=m.get("file_path")),
            "type": m.get("type"),
            "size": m.get("size"),
            "status": m.get("status"),
            "date_uploaded": m.get("date_uploaded") or ""
        }
        for m in media_items
    ])

@main_routes.route("/admin/delete-media/<media_id>", methods=["DELETE"])
def admin_delete_media(media_id):
    if "admin_email" not in session:
        return jsonify({"error": "Unauthorized"}), 401

     
    response = MEDIA_TABLE.get_item(Key={"media_id": str(media_id)})
    media = response.get("Item")
    if not media:
        return jsonify({"error": "Media not found"}), 404

    user = None
    if "user_id" in media:
        user_resp = USERS_TABLE.scan(
            FilterExpression=Attr("user_id").eq(media["user_id"]),
            Limit=1
        )
        user = user_resp.get("Items", [None])[0]



     
    file_path = os.path.join(UPLOAD_FOLDER, media.get("file_path", ""))
    if os.path.exists(file_path):
        os.remove(file_path)

     
    activity_admin = {
        "user_id": "ADMIN",
        "type": "media_deleted_by_admin",
        "description": f"Admin deleted media '{media.get('title')}' uploaded by {user.get('name') if user else 'Unknown User'}",
        "timestamp": datetime.utcnow().isoformat(),
        "read": False
    }
    ACTIVITY_TABLE.put_item(Item=activity_admin)

     
    if user:
        activity_user = {
            "user_id": user["user_id"],
            "type": "media_deleted_by_admin",
            "description": f"Your media '{media.get('title')}' was deleted by admin.",
            "timestamp": datetime.utcnow().isoformat(),
            "read": False
        }
        ACTIVITY_TABLE.put_item(Item=activity_user)

     
    MEDIA_TABLE.delete_item(Key={"media_id": str(media_id)})

    return jsonify({"message": "Media deleted successfully"})

@main_routes.route("/about")
def about():
    return render_template("about.html")

@main_routes.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("main_routes.login"))
