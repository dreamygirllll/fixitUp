from flask import Flask, render_template, request, redirect, url_for, flash , session , jsonify
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_bcrypt import Bcrypt
from mongoengine import connect
from models import User, Issue,  Feedback, Notification, Discussions, DuplicateResolvedRequest , Admin , Authorities , UserEmail, Comment , Reply,ServiceRequest
from datetime import datetime , timedelta
from functools import wraps
from flask import abort
from mongoengine.queryset.visitor import Q
from mongoengine.errors import DoesNotExist
from flask_mail import Mail, Message
from bson import ObjectId
from textblob import TextBlob


# config.py or a secure config section
ADMIN_SIGNUP_KEY = "faiza11"


# ------- WORK HARD IF YOU WANNA SUCCEED ---------
app = Flask(__name__)
app.secret_key = 'supersecretkey'
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USERNAME'] = 'bcsf22m005@pucit.edu.pk'
app.config['MAIL_PASSWORD'] = 'dhafhknlsdjfcpbm'  # Not your Gmail password!
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_DEFAULT_SENDER'] = ('Your Name', 'bcsf22m005@pucit.edu.pk')


mail = Mail(app)
# ------------------ MongoDB Connection ------------------
connect(
    db='community_service_db',
    host='localhost',
    port=27017
)

# ------------------ Flask Extensions ------------------
login_manager = LoginManager(app)
login_manager.login_view = 'login'
bcrypt = Bcrypt(app)

# ------------------ User Loader ------------------
@login_manager.user_loader
def load_user(user_id):
    from models import Admin, User
    user = Admin.objects(id=user_id).first()
    if user:
        return user
    return User.objects(id=user_id).first()
from flask import request, flash, redirect, url_for, render_template
from flask_login import login_required
from datetime import datetime
from models import User, Issue, Notification  # Make sure Notification is imported

from datetime import datetime, timedelta


# ------------------ Public Route ------------------
@app.route('/')
def home():
    return render_template('home.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        if User.objects(email=email).first():
            flash("User already exists. Please login.", "warning")
            return redirect(url_for('login'))

        hashed_pw = bcrypt.generate_password_hash(password).decode('utf-8')
        user = User(name=name, email=email, password=hashed_pw).save()
        login_user(user)
        flash("Signup successful! You are now logged in.", "success")
        return redirect(url_for('dashboard'))

    return render_template('signup.html')
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    error = None
    next_page = request.args.get('next')

    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        session['email'] = email  # Save email in session

        user = User.objects(email=email).first()

        if not user:
            error = "Email not found in our records."
            return render_template('login.html', error=error)

        if bcrypt.check_password_hash(user.password, password):
            login_user(user)
            flash("Login successful!", "success")


            return redirect(next_page or url_for('dashboard'))
        else:
            error = "Incorrect password."

    return render_template('login.html', error=error)
@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    error = None

    if request.method == 'GET':
        email = request.args.get('email')
        if not email:
            # If no email is passed via GET, redirect to login with flash message
            flash("Please enter your email first before resetting password.", "danger")
            return redirect(url_for('login'))

        session['email'] = email  # Save email in session
        user = User.objects(email=email).first()
        if not user:
            error = "Email not found in our records."
            return render_template('forgot_password.html', error=error)

        return render_template('forgot_password.html', email=email, show_reset=True)

    elif request.method == 'POST':
        email = session.get('email')
        if not email:
            error = "Session expired. Please go back and enter your email again."
            return render_template('forgot_password.html', error=error)

        user = User.objects(email=email).first()
        if not user:
            error = "Email not found in our records."
            return render_template('forgot_password.html', error=error)

        new_password = request.form.get('new_password')
        if new_password:
            hashed_pw = bcrypt.generate_password_hash(new_password).decode('utf-8')
            user.update(password=hashed_pw)
            flash("Password changed successfully!", "success")
            session.pop('email', None)
            return render_template('forgot_password.html', reset_done=True)
        else:
            error = "Please enter a new password."
            return render_template('forgot_password.html', email=email, show_reset=True, error=error)
@app.route('/logout')
@login_required
def logout():
    logout_user()
    session.clear()
    flash("Logged out successfully.", "info")
    return redirect(url_for('home'))

# ------------------ Issue Reporting ------------------
@app.route('/submit_suggestion', methods=['POST'])
@login_required
def submit_suggestion():
    suggestion = request.form.get('suggestion')

    if not suggestion:
        flash("Suggestion cannot be empty.", "error")
        return redirect(url_for('dashboard'))

    new_feedback = Feedback(
        user=current_user.id,
        suggestion=suggestion
    )
    new_feedback.save()
    flash("Thank you for your suggestion!", "success")
    return redirect(url_for('home'))

@app.route('/report_issue', methods=['POST'])
@login_required
def report_issue():
    title = request.form['title'].strip().lower()
    city = request.form['city'].strip().lower()
    description = request.form['description']
    area = request.form.get('area', '')

    # 🧠 Step 1: Check for duplicate issue
    existing_issue = Issue.objects(title__iexact=title, city__iexact=city).first()
    if existing_issue:
        return render_template(
            'duplicate_issue_prompt.html',
            existing_issue=existing_issue,
            city=city.title(),
            title=title.title()
        )

    # 🛠️ Step 2: Create new issue
    new_issue = Issue(
        title=title.title(),
        city=city.title(),
        area=area,
        description=description,
        email=current_user.email,
        reported_by=current_user
    )

    try:
        new_issue.save()
    except Exception as e:
        flash(f"Failed to save issue: {str(e)}", "danger")
        return redirect(url_for('dashboard'))

    # 📨 Step 3: Send email to authority
    authority = Authorities.objects(city=city.title()).first()
    if authority:
        try:
            tracking_url = url_for('track_email', issue_id=new_issue.id, _external=True)

            msg = Message(
                subject=f"[Action Required] New Issue Reported in {city.title()}",
                sender=app.config['MAIL_USERNAME'],
                recipients=[authority.email],
                body=f"""
Dear Authority,

A new issue has been reported by {current_user.name}.

City: {city.title()}
Area: {area}
Title: {title.title()}
Description: {description}

To acknowledge and start resolving this issue, please click the following link:
{tracking_url}

This will mark the issue as *In-Progress* in the system.

Thank you,
Community Service Portal
                """
            )
            mail.send(msg)

            email_record = UserEmail(
                recipient_email=authority.email,
                subject=msg.subject,
                message_body=msg.body,
                issue=new_issue
            )
            email_record.save()

            flash("Issue reported successfully and email sent!", "success")
        except Exception as e:
            flash(f"Issue reported but failed to send email: {str(e)}", "danger")
    else:
        flash("Issue reported but no authority found for this city.", "warning")

    return redirect(url_for('dashboard'))


@app.route('/track_email/<issue_id>')
def track_email(issue_id):
    issue = Issue.objects(id=issue_id).first()
    if issue:
        if not issue.email_clicked:
            issue.email_clicked = True
            if issue.status == "pending":
                issue.status = "in-progress"
                print("the issue status has been updated")
            issue.save()
    return "Thank you for acknowledging the issue. You may now close this tab."
@app.route('/my_issues')
@login_required
def my_issues():
    current = current_user._get_current_object()
    issues = Issue.objects(reported_by=current_user)
    return render_template('my_issues.html', issues=issues)

#<----------------- STATUS ------------------->
@app.route('/dashboard')
@login_required
def dashboard():
    # Get issues of current user
    issues = Issue.objects(reported_by=current_user.id)

    # Serialize the issues into plain dictionaries
    serialized_issues = []
    for issue in issues.order_by('-created_at'):
        serialized_issues.append({
            'title': issue.title,
            'city': issue.city,
            'description': issue.description,
            'created_at': issue.created_at.isoformat(),
            'status': issue.status
        })

    # Count issues by status
    pending_count = Issue.objects(reported_by=current_user.id, status='pending').count()
    in_progress_count = Issue.objects(reported_by=current_user.id, status='in-progress').count()
    completed_count = Issue.objects(reported_by=current_user.id, status='resolved').count()

    return render_template(
        'index.html',
        issues=serialized_issues,
        pending_count=pending_count,
        in_progress_count=in_progress_count,
        completed_count=completed_count
    )

# ------------------ Feedback ------------------
def get_sentiment(comment):
    analysis = TextBlob(comment).sentiment.polarity
    if analysis > 0.1:
        return "positive"
    elif analysis < -0.1:
        return "negative"
    else:
        return "neutral"


@app.route('/feedback', methods=['GET', 'POST'])
@login_required
def feedback():
    if request.method == 'POST':
        problem = request.form.get('problem')
        rating = request.form.get('rating')
        comment = request.form.get('comment')

        if not problem or not rating or not comment:
            flash("All fields are required.", "danger")
            return redirect(url_for('feedback'))

        try:
            rating = int(rating)
            if rating < 1 or rating > 5:
                raise ValueError
        except ValueError:
            flash("Rating must be an integer between 1 and 5.", "danger")
            return redirect(url_for('feedback'))

        # Analyze sentiment
        sentiment = get_sentiment(comment)

        # Save feedback with sentiment
        fb = Feedback(
            user=current_user._get_current_object(),
            problem=problem,
            rating=rating,
            comment=comment,
            sentiment=sentiment,  # Added sentiment field
            submitted_at=datetime.utcnow()
        )
        fb.save()

        return render_template('feedback_confirmation.html', sentiment=sentiment)

    return render_template('feedback.html')

# ------------------ Notifications ------------------
@app.route('/post_discussion', methods=['POST'])
@login_required
def post_discussion():
    title = request.form.get('title')
    message = request.form.get('message')
    category = request.form.get('category', 'General')  # Default to "General" if not provided

    if not title or not message:
        flash("Title and message are required.", "danger")
        return redirect(url_for('discussions'))

    # Create and save the discussion
    post = Discussions(
        title=title,
        message=message,
        category=category,
        posted_by=current_user
    )
    post.save()
    print("Discussion document is added to database")
    flash("Discussion posted successfully!", "success")
    return redirect(url_for('discussions'))
@app.route('/discussions')
@login_required
def discussions():
    all_discussions = Discussions.objects.order_by('-created_at')
    return render_template('discussions.html', posts=all_discussions)


@app.route('/add_comment/<discussion_id>', methods=['POST'])
@login_required
def add_comment(discussion_id):
    text = request.form.get('comment')
    if text:
        discussion = Discussions.objects.get(id=ObjectId(discussion_id))
        comment = Comment(user=current_user, text=text)
        discussion.comments.append(comment)
        discussion.save()
        flash("Comment added!", "success")
    else:
        flash("Comment cannot be empty.", "danger")

    # Redirect back to the discussion block using anchor
    return redirect(url_for('discussions') + f'#discussion-{discussion_id}')
@app.route('/add_reply/<discussion_id>/<int:comment_index>', methods=['POST'])
@login_required
def add_reply(discussion_id, comment_index):
    text = request.form.get('reply')
    if text:
        discussion = Discussions.objects.get(id=ObjectId(discussion_id))
        reply = Reply(user=current_user, text=text)
        discussion.comments[comment_index].replies.append(reply)
        discussion.save()
        flash("Reply added!", "success")
    else:
        flash("Reply cannot be empty.", "danger")

    # Redirect back to the same discussion using anchor
    return redirect(url_for('discussions') + f'#discussion-{discussion_id}')




@app.route('/mark_notification_read/<string:note_id>', methods=['POST'])
@login_required
def mark_notification_read(note_id):
    note = Notification.objects(id=note_id).first()
    if note:
        note.update(is_read=True)
        flash("Notification marked as read", "info")
    return redirect(url_for('notifications'))


# ------------------ Search Issues ------------------
@app.route('/search_issues', methods=['GET'])
@login_required
def search_issues():
    keyword = request.args.get('q', '')
    results = Issue.objects(title__icontains=keyword)
    return render_template('search_issues.html', issues=results, query=keyword)

# ------------------ Duplicate Resolved Requests ------------------
@app.route('/duplicates')
@login_required
def duplicates():
    dupes = DuplicateResolvedRequest.objects()
    return render_template('duplicates.html', duplicates=dupes)
@app.after_request
def add_header(response):
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, private, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response
# --------------------admin required-----------------
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'admin':
            abort(403)  # Forbidden
        return f(*args, **kwargs)

    return decorated_function


# --------------------admin Signup-------------------
@app.route('/admin_signup', methods=['GET', 'POST'])
def admin_signup():
    if current_user.is_authenticated:
        return redirect(url_for('admin_dashboard'))

    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        admin_key = request.form.get('admin_key')  # Get the admin key from the form

        # Check if the provided admin key matches the required one
        if admin_key != ADMIN_SIGNUP_KEY:
            flash("Invalid Admin Key. Access denied.", "danger")
            return redirect(url_for('admin_signup'))

        # Check if admin already exists
        if Admin.objects(email=email).first():
            flash("Admin already exists. Please login.", "warning")
            return redirect(url_for('admin_login'))

        # Proceed to register the admin
        hashed_pw = bcrypt.generate_password_hash(password).decode('utf-8')
        admin = Admin(name=name, email=email, password=hashed_pw).save()
        login_user(admin)
        flash("Admin signup successful! You are now logged in.", "success")
        return redirect(url_for('admin_dashboard'))

    return render_template('admin_signup.html')


# ---------------------Admin login -----------------
@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    if current_user.is_authenticated:
        return redirect(url_for('admin_dashboard'))  # Redirect to admin dashboard if already logged in

    error = None

    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        session['email'] = email  # Save email in session

        from models import Admin  # Make sure Admin model is imported

        admin = Admin.objects(email=email).first()

        if not admin:
            error = "Admin email not found in our records."
            return render_template('admin_login.html', error=error)

        if bcrypt.check_password_hash(admin.password, password):
            login_user(admin)
            flash("Admin login successful!", "success")
            return redirect(url_for('admin_dashboard'))
        else:
            error = "Incorrect password."

    return render_template('admin_login.html', error=error)


# ---------------------admin logout------------------
@app.route('/admin_logout')
@login_required
def admin_logout():
    logout_user()
    session.clear()
    flash("Admin logged out successfully.", "info")
    return redirect(url_for('home'))


# --------------------admin dashboard-------------
from flask import request  # Make sure this is imported

@app.route('/admin_dashboard')
def admin_dashboard():
    # 1. Issue Counts
    total = Issue.objects.count()
    pending = Issue.objects(status='pending').count()
    in_progress = Issue.objects(status='in-progress').count()
    resolved = Issue.objects(status='resolved').count()

    # 2. Recent Issues
    recent_issues = Issue.objects.order_by('-created_at')[:5]

    # 3. Sentiment Filter
    selected_sentiment = request.args.get('sentiment', '').lower()

    # 4. Feedback Filtering
    raw_feedbacks = (
        Feedback.objects(sentiment=selected_sentiment).order_by('-submitted_at') if selected_sentiment
        else Feedback.objects.order_by('-submitted_at')
    )

    valid_feedbacks = []
    for fb in raw_feedbacks:
        try:
            _ = fb.user.id  # triggers dereference check
            valid_feedbacks.append(fb)
            if len(valid_feedbacks) == 5:
                break
        except DoesNotExist:
            continue

    # 5. Chart Data - Last 7 Days
    today = datetime.utcnow().date()
    labels = []
    values = []
    for i in range(6, -1, -1):
        day = today - timedelta(days=i)
        labels.append(day.strftime('%d %b'))
        values.append(Issue.objects(
            created_at__gte=datetime(day.year, day.month, day.day),
            created_at__lt=datetime(day.year, day.month, day.day + 1)
        ).count())

    # 6. Render Template
    return render_template('admin_dashboard.html',
        total_issues=total,
        pending_count=pending,
        in_progress_count=in_progress,
        resolved_count=resolved,
        recent_issues=recent_issues,
        feedbacks=valid_feedbacks,
        selected_sentiment=selected_sentiment,
        chart_labels=labels,
        chart_data=values
    )



# ------------------admin-update-status-----------

@app.route('/admin/update_status/<string:issue_id>', methods=['POST'])
@login_required
@admin_required
def update_issue_status(issue_id):
    new_status = request.form.get('status')
    issue = Issue.objects(id=issue_id).first()

    if issue:
        old_status = issue.status
        issue.status = new_status
        issue.save()

        # Send notification only if status changed to 'resolved'
        if issue.reported_by:  # issue.reported_by is a User object
            Notification(
                user=issue.reported_by,
                message=f"Your issue titled '{issue.title}' reported on {issue.created_at.strftime('%Y-%m-%d')} has been resolved."
            ).save()

            print("Issue status updated")
        flash("Issue status updated.", "success")
    else:
        flash("Issue not found.", "danger")

    return redirect(url_for('view_issues'))

# -----------------view issues by admin------------

@app.route('/admin/issues')
@app.route('/admin/issues')
@login_required
@admin_required
def view_issues():
    status_filter = request.args.get('status')
    sort_order = request.args.get('sort', 'desc')
    user_email = request.args.get('user_email', '').strip().lower()

    issues_query = Issue.objects()

    # Filter by issue status if provided
    if status_filter:
        issues_query = issues_query.filter(status=status_filter)

    # Filter by user's email if provided
    if user_email:
        user = User.objects(email__iexact=user_email).first()
        if user:
            issues_query = issues_query.filter(reported_by=user)
        else:
            issues_query = issues_query.none()  # No matching user = no issues

    # Sorting
    if sort_order == 'asc':
        issues_query = issues_query.order_by('created_at')
    else:
        issues_query = issues_query.order_by('-created_at')

    # Filter out issues with missing reported_by references
    valid_issues = []
    for issue in issues_query:
        try:
            _ = issue.reported_by  # Try dereferencing
            valid_issues.append(issue)
        except DoesNotExist:
            continue  # Skip if user doesn't exist

    return render_template('view_issues.html', issues=valid_issues)


# ------------------ Service Requests ------------------
@app.route('/service_request', methods=['GET', 'POST'])
@login_required
def service_request():
    if request.method == 'POST':
        data = request.form
        ServiceRequest(
            service_type=data['service_type'],
            details=data['details'],
            requested_by=current_user._get_current_object()
        ).save()
        flash("Service requested successfully", "success")
        return redirect(url_for('dashboard'))

    return render_template('service_request.html')
# ----------------------edit user by admin--------------
@app.route('/admin/edit_user/<string:user_id>', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_user(user_id):
    user = User.objects(id=user_id).first()
    if not user:
        flash("User not found.", "danger")
        return redirect(url_for('view_users'))

    if request.method == 'POST':
        user.name = request.form['name']
        user.email = request.form['email']
        user.role = request.form['role']
        user.save()
        flash("User updated successfully.", "success")
        return redirect(url_for('view_users'))

    return render_template('edit_user.html', user=user)


# -------------delete user------------------
@app.route('/admin/issues/<issue_id>/delete', methods=['POST'])
@login_required
@admin_required
def delete_issue(issue_id):
    issue = Issue.objects(id=issue_id).first()
    if issue:
        issue.delete()
    return redirect(url_for('view_issues'))
@app.route('/admin_forgot_password', methods=['GET', 'POST'])
def admin_forgot_password():
    error = None

    if request.method == 'GET':
        email = request.args.get('email')
        if not email:
            flash("Please enter your admin email before resetting password.", "danger")
            return redirect(url_for('admin_login'))  # redirect to admin login

        session['admin_email'] = email
        admin = Admin.objects(email=email).first()
        if not admin:
            error = "Admin email not found in records."
            return render_template('admin_forgot_password.html', error=error)

        return render_template('admin_forgot_password.html', email=email, show_reset=True)

    elif request.method == 'POST':
        email = session.get('admin_email')
        if not email:
            error = "Session expired. Please go back and enter your email again."
            return render_template('admin_forgot_password.html', error=error)

        admin = Admin.objects(email=email).first()
        if not admin:
            error = "Admin email not found in records."
            return render_template('admin_forgot_password.html', error=error)

        new_password = request.form.get('new_password')
        if new_password:
            hashed_pw = bcrypt.generate_password_hash(new_password).decode('utf-8')
            admin.update(password=hashed_pw)
            flash("Admin password changed successfully!", "success")
            session.pop('admin_email', None)
            return render_template('admin_forgot_password.html', reset_done=True)
        else:
            error = "Please enter a new password."
            return render_template('admin_forgot_password.html', email=email, show_reset=True,error=error)


from flask_login import current_user

@app.route('/notifications')
@login_required
def notifications():
    notifications = Notification.objects(user=current_user).order_by('-created_at')
    return render_template('notifications.html', notifications=notifications)

@app.route('/api/signup', methods=['POST'])
def api_signup():
    data = request.get_json()
    name = data.get('name')
    email = data.get('email')
    password = data.get('password')

    if not name or not email or not password:
        return jsonify({"status": "fail", "message": "All fields are required"}), 400

    if User.objects(email=email).first():
        return jsonify({"status": "fail", "message": "User already exists"}), 409

    hashed_pw = bcrypt.generate_password_hash(password).decode('utf-8')
    user = User(name=name, email=email, password=hashed_pw).save()
    login_user(user)
    return jsonify({"status": "success", "message": "Signup successful", "user_id": str(user.id)}), 201
@app.route('/api/login', methods=['POST'])
def api_login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    user = User.objects(email=email).first()
    if not user:
        return jsonify({"status": "fail", "message": "Email not found"}), 404

    if not bcrypt.check_password_hash(user.password, password):
        return jsonify({"status": "fail", "message": "Incorrect password"}), 401

    login_user(user)
    return jsonify({"status": "success", "message": "Login successful", "user_id": str(user.id)}), 200
@app.route('/api/forgot_password', methods=['POST'])
def api_forgot_password():
    data = request.get_json()
    email = data.get('email')
    new_password = data.get('new_password')

    if not email or not new_password:
        return jsonify({"status": "fail", "message": "Email and new password required"}), 400

    user = User.objects(email=email).first()
    if not user:
        return jsonify({"status": "fail", "message": "Email not found"}), 404

    hashed_pw = bcrypt.generate_password_hash(new_password).decode('utf-8')
    user.update(password=hashed_pw)
    return jsonify({"status": "success", "message": "Password updated successfully"}), 200
@app.route('/api/logout', methods=['POST'])
@login_required
def api_logout():
    logout_user()
    session.clear()
    return jsonify({"status": "success", "message": "Logged out successfully."}), 200
@app.route('/api/submit_suggestion', methods=['POST'])
@login_required
def api_submit_suggestion():
    data = request.get_json()
    suggestion = data.get('suggestion')

    if not suggestion:
        return jsonify({"status": "error", "message": "Suggestion cannot be empty."}), 400

    new_feedback = Feedback(
        user=current_user.id,
        suggestion=suggestion
    )
    new_feedback.save()
    return jsonify({"status": "success", "message": "Suggestion submitted successfully."}), 201
@app.route('/api/report_issue', methods=['POST'])
@login_required
def api_report_issue():
    data = request.get_json()

    title = data.get('title')
    city = data.get('city')
    description = data.get('description')
    area = data.get('area', '')

    if not title or not city or not description:
        return jsonify({"status": "error", "message": "Title, city, and description are required."}), 400

    new_issue = Issue(
        title=title,
        city=city,
        area=area,
        description=description,
        email=current_user.email,
        reported_by=current_user
    )

    try:
        new_issue.save()
    except Exception as e:
        return jsonify({"status": "error", "message": f"Failed to save issue: {str(e)}"}), 500

    authority = Authorities.objects(city=city).first()

    if authority:
        try:
            tracking_url = url_for('track_email', issue_id=new_issue.id, _external=True)
            msg = Message(
                subject=f"[Action Required] New Issue Reported in {city}",
                sender=app.config['MAIL_USERNAME'],
                recipients=[authority.email],
                body=f"""
Dear Authority,

A new issue has been reported by {current_user.name}.

City: {city}
Description: {description}

To acknowledge and start resolving this issue, please click the following link:
{tracking_url}

This will mark the issue as *In-Progress* in the system.
And Kindly reply us (To this email) when the issue has resolved.

Thank you,
Community Service Portal - FixItUp
                """
            )
            mail.send(msg)

            email_record = UserEmail(
                recipient_email=authority.email,
                subject=msg.subject,
                message_body=msg.body,
                issue=new_issue
            )
            email_record.save()

            return jsonify({
                "status": "success",
                "message": "Issue reported and email sent.",
                "issue_id": str(new_issue.id)
            }), 201

        except Exception as e:
            return jsonify({
                "status": "warning",
                "message": f"Issue saved but failed to send email: {str(e)}",
                "issue_id": str(new_issue.id)
            }), 206
    else:
        return jsonify({
            "status": "warning",
            "message": "Issue saved but no authority found for this city.",
            "issue_id": str(new_issue.id)
        }), 206
@app.route('/api/track_email/<issue_id>', methods=['GET'])
def api_track_email(issue_id):
    issue = Issue.objects(id=issue_id).first()
    if issue:
        if not issue.email_clicked:
            issue.email_clicked = True
            if issue.status == "pending":
                issue.status = "in-progress"
            issue.save()
        return jsonify({"status": "success", "message": "Issue acknowledged."}), 200
    return jsonify({"status": "error", "message": "Issue not found."}), 404
@app.route('/api/my_issues', methods=['GET'])
@login_required
def api_my_issues():
    issues = Issue.objects(reported_by=current_user.id).order_by('-created_at')
    issue_list = [{
        "title": issue.title,
        "city": issue.city,
        "description": issue.description,
        "area": issue.area,
        "created_at": issue.created_at.isoformat(),
        "status": issue.status
    } for issue in issues]
    return jsonify({"status": "success", "issues": issue_list}), 200
@app.route('/api/dashboard_stats', methods=['GET'])
@login_required
def api_dashboard_stats():
    issues = Issue.objects(reported_by=current_user.id).order_by('-created_at')
    serialized_issues = [{
        'title': issue.title,
        'city': issue.city,
        'description': issue.description,
        'created_at': issue.created_at.isoformat(),
        'status': issue.status
    } for issue in issues]

    stats = {
        "pending": Issue.objects(reported_by=current_user.id, status='pending').count(),
        "in_progress": Issue.objects(reported_by=current_user.id, status='in-progress').count(),
        "completed": Issue.objects(reported_by=current_user.id, status='resolved').count(),
    }

    return jsonify({
        "status": "success",
        "issues": serialized_issues,
        "stats": stats
    }), 200
@app.route('/api/feedback', methods=['POST'])
@login_required
def api_feedback():
    data = request.get_json()
    problem = data.get('problem')
    rating = data.get('rating')
    comment = data.get('comment')

    if not problem or not rating or not comment:
        return jsonify({"status": "error", "message": "All fields are required."}), 400

    try:
        rating = int(rating)
        if rating < 1 or rating > 5:
            raise ValueError
    except ValueError:
        return jsonify({"status": "error", "message": "Rating must be between 1 and 5."}), 400

    fb = Feedback(
        user=current_user._get_current_object(),
        problem=problem,
        rating=rating,
        comment=comment,
        submitted_at=datetime.utcnow()
    )
    fb.save()

    return jsonify({"status": "success", "message": "Feedback submitted successfully."}), 201
@app.route('/api/post_discussion', methods=['POST'])
@login_required
def api_post_discussion():
    data = request.get_json()
    title = data.get('title')
    message = data.get('message')
    category = data.get('category', 'General')

    if not title or not message:
        return jsonify({"status": "error", "message": "Title and message are required."}), 400

    post = Discussions(
        title=title,
        message=message,
        category=category,
        posted_by=current_user
    )
    post.save()

    return jsonify({"status": "success", "message": "Discussion posted successfully."}), 201
@app.route('/api/discussions', methods=['GET'])
@login_required
def api_get_discussions():
    all_discussions = Discussions.objects.order_by('-created_at')
    data = []
    for d in all_discussions:
        data.append({
            "id": str(d.id),
            "title": d.title,
            "message": d.message,
            "category": d.category,
            "posted_by": d.posted_by.name,
            "created_at": d.created_at.isoformat(),
            "comments": [
                {
                    "user": c.user.name,
                    "text": c.text,
                    "replies": [
                        {"user": r.user.name, "text": r.text} for r in c.replies
                    ]
                } for c in d.comments
            ]
        })
    return jsonify({"status": "success", "discussions": data}), 200
@app.route('/api/add_comment/<discussion_id>', methods=['POST'])
@login_required
def api_add_comment(discussion_id):
    data = request.get_json()
    text = data.get('comment')

    if not text:
        return jsonify({"status": "error", "message": "Comment cannot be empty."}), 400

    try:
        discussion = Discussions.objects.get(id=discussion_id)
    except Discussions.DoesNotExist:
        return jsonify({"status": "error", "message": "Discussion not found."}), 404

    comment = Comment(user=current_user, text=text)
    discussion.comments.append(comment)
    discussion.save()

    return jsonify({"status": "success", "message": "Comment added successfully."}), 201
@app.route('/api/add_reply/<discussion_id>/<int:comment_index>', methods=['POST'])
@login_required
def api_add_reply(discussion_id, comment_index):
    data = request.get_json()
    text = data.get('reply')

    if not text:
        return jsonify({"status": "error", "message": "Reply cannot be empty."}), 400

    try:
        discussion = Discussions.objects.get(id=discussion_id)
    except Discussions.DoesNotExist:
        return jsonify({"status": "error", "message": "Discussion not found."}), 404

    if comment_index >= len(discussion.comments):
        return jsonify({"status": "error", "message": "Invalid comment index."}), 400

    reply = Reply(user=current_user, text=text)
    discussion.comments[comment_index].replies.append(reply)
    discussion.save()

    return jsonify({"status": "success", "message": "Reply added successfully."}), 201
@app.route('/api/mark_notification_read/<string:note_id>', methods=['POST'])
@login_required
def api_mark_notification_read(note_id):
    note = Notification.objects(id=note_id).first()
    if not note:
        return jsonify({"status": "error", "message": "Notification not found."}), 404

    note.update(is_read=True)
    return jsonify({"status": "success", "message": "Notification marked as read."}), 200
@app.route('/api/search_issues', methods=['GET'])
@login_required
def api_search_issues():
    keyword = request.args.get('q', '')
    results = Issue.objects(title__icontains=keyword)

    data = [{
        "id": str(issue.id),
        "title": issue.title,
        "city": issue.city,
        "description": issue.description,
        "status": issue.status,
        "created_at": issue.created_at.isoformat()
    } for issue in results]

    return jsonify({
        "status": "success",
        "query": keyword,
        "results": data
    }), 200
@app.route('/api/admin_signup', methods=['POST'])
def api_admin_signup():
    data = request.get_json()
    name = data.get('name')
    email = data.get('email')
    password = data.get('password')
    admin_key = data.get('admin_key')

    if admin_key != ADMIN_SIGNUP_KEY:
        return jsonify({"status": "error", "message": "Invalid admin key."}), 403

    if Admin.objects(email=email).first():
        return jsonify({"status": "error", "message": "Admin already exists."}), 400

    hashed_pw = bcrypt.generate_password_hash(password).decode('utf-8')
    admin = Admin(name=name, email=email, password=hashed_pw).save()
    login_user(admin)

    return jsonify({"status": "success", "message": "Admin registered and logged in."}), 201
@app.route('/api/admin_login', methods=['POST'])
def api_admin_login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    admin = Admin.objects(email=email).first()
    if not admin:
        return jsonify({"status": "error", "message": "Admin not found."}), 404

    if not bcrypt.check_password_hash(admin.password, password):
        return jsonify({"status": "error", "message": "Incorrect password."}), 401

    login_user(admin)
    return jsonify({"status": "success", "message": "Admin logged in successfully."}), 200
@app.route('/api/admin_logout', methods=['GET'])
@login_required
def api_admin_logout():
    logout_user()
    session.clear()
    return jsonify({"status": "success", "message": "Admin logged out successfully."}), 200
@app.route('/api/admin_dashboard', methods=['GET'])
@login_required
@admin_required
def api_admin_dashboard():
    total = Issue.objects.count()
    pending = Issue.objects(status='pending').count()
    in_progress = Issue.objects(status='in-progress').count()
    resolved = Issue.objects(status='resolved').count()

    recent_issues = Issue.objects.order_by('-created_at')[:5]
    feedbacks = Feedback.objects.order_by('-submitted_at')[:5]

    today = datetime.utcnow().date()
    labels = []
    values = []
    for i in range(6, -1, -1):
        day = today - timedelta(days=i)
        count = Issue.objects(
            created_at__gte=datetime(day.year, day.month, day.day),
            created_at__lt=datetime(day.year, day.month, day.day + 1)
        ).count()
        labels.append(day.strftime('%d %b'))
        values.append(count)

    return jsonify({
        "total_issues": total,
        "pending_count": pending,
        "in_progress_count": in_progress,
        "resolved_count": resolved,
        "recent_issues": [
            {
                "title": i.title,
                "city": i.city,
                "description": i.description,
                "status": i.status,
                "created_at": i.created_at.isoformat()
            } for i in recent_issues
        ],
        "recent_feedbacks": [
            {
                "user": str(fb.user.id) if fb.user else None,
                "comment": fb.comment,
                "problem": fb.problem,
                "rating": fb.rating,
                "submitted_at": fb.submitted_at.isoformat()
            } for fb in feedbacks if fb.user
        ],
        "chart_labels": labels,
        "chart_values": values
    }), 200
@app.route('/api/admin/update_status/<string:issue_id>', methods=['POST'])
@login_required
@admin_required
def api_update_issue_status(issue_id):
    data = request.get_json()
    new_status = data.get('status')
    issue = Issue.objects(id=issue_id).first()

    if not issue:
        return jsonify({"status": "error", "message": "Issue not found"}), 404

    old_status = issue.status
    issue.status = new_status
    issue.save()

    if issue.reported_by:
        Notification(
            user=issue.reported_by,
            message=f"Your issue '{issue.title}' reported on {issue.created_at.strftime('%Y-%m-%d')} has been marked '{new_status}'."
        ).save()

    return jsonify({"status": "success", "message": "Issue status updated"}), 200
@app.route('/api/admin/issues', methods=['GET'])
@login_required
@admin_required
def api_view_issues():
    status_filter = request.args.get('status')
    sort_order = request.args.get('sort', 'desc')

    query = Issue.objects()
    if status_filter:
        query = query.filter(status=status_filter)

    query = query.order_by('created_at' if sort_order == 'asc' else '-created_at')

    issues = []
    for issue in query:
        try:
            _ = issue.reported_by
            issues.append({
                "id": str(issue.id),
                "title": issue.title,
                "city": issue.city,
                "area": issue.area,
                "description": issue.description,
                "status": issue.status,
                "created_at": issue.created_at.isoformat(),
                "reported_by": str(issue.reported_by.id)
            })
        except DoesNotExist:
            continue

    return jsonify({
        "status": "success",
        "count": len(issues),
        "issues": issues
    }), 200
@app.route('/api/service_request', methods=['POST'])
@login_required
def api_service_request():
    data = request.get_json()

    if not data or 'service_type' not in data or 'details' not in data:
        return jsonify({"status": "error", "message": "Missing fields"}), 400

    ServiceRequest(
        service_type=data['service_type'],
        details=data['details'],
        requested_by=current_user._get_current_object()
    ).save()

    return jsonify({"status": "success", "message": "Service requested successfully"}), 201
@app.route('/api/admin/edit_user/<string:user_id>', methods=['PUT'])
@login_required
@admin_required
def api_edit_user(user_id):
    user = User.objects(id=user_id).first()
    if not user:
        return jsonify({"status": "error", "message": "User not found"}), 404

    data = request.get_json()
    user.name = data.get('name', user.name)
    user.email = data.get('email', user.email)
    user.role = data.get('role', user.role)
    user.save()

    return jsonify({"status": "success", "message": "User updated successfully"}), 200
@app.route('/api/admin/issues/<string:issue_id>', methods=['DELETE'])
@login_required
@admin_required
def api_delete_issue(issue_id):
    issue = Issue.objects(id=issue_id).first()
    if not issue:
        return jsonify({"status": "error", "message": "Issue not found"}), 404

    issue.delete()
    return jsonify({"status": "success", "message": "Issue deleted successfully"}), 200
@app.route('/api/admin/forgot_password', methods=['POST'])
def api_admin_forgot_password():
    data = request.get_json()
    if not data or 'email' not in data or 'new_password' not in data:
        return jsonify({"status": "error", "message": "Email and new password required."}), 400

    email = data['email']
    new_password = data['new_password']

    admin = Admin.objects(email=email).first()
    if not admin:
        return jsonify({"status": "error", "message": "Admin email not found."}), 404

    hashed_pw = bcrypt.generate_password_hash(new_password).decode('utf-8')
    admin.update(password=hashed_pw)

    return jsonify({"status": "success", "message": "Password updated successfully."}), 200
@app.route('/api/notifications', methods=['GET'])
@login_required
def api_notifications():
    notifications = Notification.objects(user=current_user).order_by('-created_at')
    result = []
    for note in notifications:
        result.append({
            "id": str(note.id),
            "message": note.message,
            "is_read": note.is_read,
            "created_at": note.created_at.isoformat()
        })
    return jsonify({"notifications": result}), 200



# ------------------ Run Server ------------------
if __name__ == '__main__':
    app.run(debug=True)
