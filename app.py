from flask import Flask, render_template, request, redirect, url_for, flash , session
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_bcrypt import Bcrypt
from mongoengine import connect
from models import User, Issue, ServiceRequest, Feedback, Notification, Discussion, DuplicateResolvedRequest , Admin
from datetime import datetime
from functools import wraps
from flask import abort
from mongoengine.queryset.visitor import Q
from mongoengine.errors import DoesNotExist


# ------- WORK HARD IF YOU WANNA SUCCEED ---------
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
    from models import Admin, User
    user = Admin.objects(id=user_id).first()
    if user:
        return user
    return User.objects(id=user_id).first()
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
    title = request.form.get('title')
    city = request.form.get('city')
    description = request.form.get('description')
    email = session.get('email')  # Get email from session
    if not title or not city or not description:
        flash("All fields are required!", "error")
        return redirect(url_for('dashboard'))

    new_issue = Issue(
        title=title,
        city=city,
        email=email,
        description=description,
        status='Pending',
        reported_by=current_user.id
    )
    new_issue.save()
    flash("Issue reported successfully!", "success")
    return redirect(url_for('dashboard'))



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

    # Count pending and completed issues
    pending_count = Issue.objects(reported_by=current_user.id, status='Pending').count()
    completed_count = Issue.objects(reported_by=current_user.id, status='Completed').count()

    return render_template(
        'index.html',
        issues=serialized_issues,   # Now JSON-serializable
        pending_count=pending_count,
        completed_count=completed_count
    )



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
        problem = request.form.get('problem')
        rating = int(request.form.get('rating'))
        comment = request.form.get('comment')

        feedback = Feedback(
            user=current_user._get_current_object(),
            problem=problem,
            rating=rating,
            comment=comment,
            submitted_at=datetime.now()
        )
        feedback.save()

        return render_template('thank_you.html')  # or handle via JS

    return render_template('feedback.html',user_name=current_user.name)


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
        return redirect(url_for('admin_dashboard'))  # redirect to a different admin dashboard if needed

    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']

        if Admin.objects(email=email).first():
            flash("Admin already exists. Please login.", "warning")
            return redirect(url_for('admin_login'))

        hashed_pw = bcrypt.generate_password_hash(password).decode('utf-8')
        admin = Admin(name=name, email=email, password=hashed_pw).save()
        login_user(admin)
        flash("Admin signup successful! You are now logged in.", "success")
        return redirect(url_for('admin_dashboard'))  # You can customize this

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
@app.route('/admin/dashboard')
@login_required
@admin_required
def admin_dashboard():
    all_issues = Issue.objects()
    all_users = User.objects()
    all_services = ServiceRequest.objects()
    return render_template('admin_dashboard.html', issues=all_issues, users=all_users, services=all_services)


# ------------------admin-update-status-----------
@app.route('/admin/update_status/<string:issue_id>', methods=['POST'])
@login_required
@admin_required
def update_issue_status(issue_id):
    new_status = request.form.get('status')
    issue = Issue.objects(id=issue_id).first()
    if issue:
        issue.update(status=new_status)
        flash("Issue status updated.", "success")
    return redirect(url_for('view_issues'))


# -----------------view issues by admin------------



@app.route('/admin/issues')
@login_required
@admin_required
def view_issues():
    status_filter = request.args.get('status')
    sort_order = request.args.get('sort', 'desc')

    issues_query = Issue.objects()

    if status_filter:
        issues_query = issues_query.filter(status=status_filter)

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



# -------------------view services by admin-----------------
@app.route('/admin/services')
@login_required
@admin_required
def view_services():
    services = ServiceRequest.objects()
    return render_template('view_services.html', services=services)


# --------------view users by admin--------------
@app.route('/admin/users', methods=['GET', 'POST'])
@login_required
@admin_required
def view_users():
    # Handle delete
    if request.method == 'POST':
        user_id = request.form.get('delete_user_id')
        if user_id:
            user = User.objects(id=user_id).first()
            if user:
                user.delete()
                flash('User deleted successfully.', 'success')
            else:
                flash('User not found.', 'danger')
        return redirect(url_for('view_users'))

    # Handle search
    query = request.args.get('q')
    if query:
        users = User.objects(Q(name__icontains=query) | Q(email__icontains=query) | Q(role__icontains=query))
    else:
        users = User.objects()

    return render_template('view_users.html', users=users)


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


# -------------delte user------------------
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

# ------------------ Run Server ------------------
if __name__ == '__main__':
    app.run(debug=True)
