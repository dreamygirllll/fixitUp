from flask import Flask, render_template, request, redirect, url_for, flash , session
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_bcrypt import Bcrypt
from mongoengine import connect
from models import User, Issue, ServiceRequest, Feedback, Notification, Discussion, DuplicateResolvedRequest

app = Flask(__name__)
app.secret_key = 'supersecretkey'

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
    return User.objects(id=user_id).first()

# ------------------ Public Route ------------------
@app.route('/')
def home():
    return render_template('home.html')

# ------------------ Dashboard ------------------
@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('index.html')

# ------------------ Auth Routes ------------------
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
            return redirect(url_for('dashboard'))
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
@app.route('/report_issue', methods=['GET', 'POST'])
@login_required
def report_issue():
    if request.method == 'POST':
        data = request.form
        existing = Issue.objects(title=data['title'], status="Resolved").first()
        if existing:
            DuplicateResolvedRequest(original_issue=existing, duplicate_title=data['title']).save()
            flash("A similar issue was already resolved", "warning")
            return redirect(url_for('report_issue'))

        Issue(
            title=data['title'],
            description=data['description'],
            reported_by=current_user._get_current_object()
        ).save()
        flash("Issue reported successfully", "success")
        return redirect(url_for('my_issues'))

    return render_template('report_issue.html')

@app.route('/my_issues')
@login_required
def my_issues():
    current = current_user._get_current_object()
    issues = Issue.objects(reported_by=current)
    return render_template('my_issues.html', issues=issues)

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

# ------------------ Feedback ------------------
@app.route('/feedback', methods=['GET', 'POST'])
@login_required
def feedback():
    if request.method == 'POST':
        data = request.form
        Feedback(
            user=current_user._get_current_object(),
            rating=int(data['rating']),
            comment=data['comment']
        ).save()
        flash("Feedback submitted", "success")
        return redirect(url_for('dashboard'))

    return render_template('feedback.html')

# ------------------ Notifications ------------------
@app.route('/notifications')
@login_required
def notifications():
    notes = Notification.objects(user=current_user._get_current_object(), is_read=False)
    return render_template('notifications.html', notifications=notes)

@app.route('/mark_notification_read/<string:note_id>', methods=['POST'])
@login_required
def mark_notification_read(note_id):
    note = Notification.objects(id=note_id).first()
    if note:
        note.update(is_read=True)
        flash("Notification marked as read", "info")
    return redirect(url_for('notifications'))

# ------------------ Discussions ------------------
@app.route('/post_discussion', methods=['GET', 'POST'])
@login_required
def post_discussion():
    if request.method == 'POST':
        data = request.form
        Discussion(
            topic=data['topic'],
            posted_by=current_user._get_current_object(),
            comments=[]
        ).save()
        flash("Discussion posted", "success")
        return redirect(url_for('discussions'))

    return render_template('post_discussion.html')

@app.route('/discussions')
@login_required
def discussions():
    all_disc = Discussion.objects()
    return render_template('discussions.html', discussions=all_disc)

@app.route('/add_comment/<string:discussion_id>', methods=['POST'])
@login_required
def add_comment(discussion_id):
    data = request.form
    disc = Discussion.objects(id=discussion_id).first()
    if disc:
        disc.update(push__comments=f"{current_user.name}: {data['comment']}")
        flash("Comment added", "success")
    return redirect(url_for('discussions'))

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

# ------------------ Run Server ------------------
if __name__ == '__main__':
    app.run(debug=True)
