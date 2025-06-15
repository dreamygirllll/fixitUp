from mongoengine import Document, StringField, EmailField, IntField, FloatField, BooleanField, ReferenceField, \
    ListField, DateTimeField
from flask_login import UserMixin
from datetime import datetime


# ------------------ User Model ------------------

class User(Document, UserMixin):
    name = StringField(required=True)
    email = EmailField(required=True, unique=True)
    password = StringField(required=True)
    age = IntField()

    def get_id(self):
        return str(self.id)

    def to_json(self):
        return {
            "id": str(self.id),
            "name": self.name,
            "email": self.email,
            "age": self.age
        }


# ------------------ Issue Model ------------------

class Issue(Document):
    title = StringField(required=True)
    description = StringField()
    status = StringField(default="Open")  # Open, In Progress, Resolved
    reported_by = ReferenceField(User)
    created_at = DateTimeField(default=datetime.utcnow)

    def to_json(self):
        return {
            "id": str(self.id),
            "title": self.title,
            "description": self.description,
            "status": self.status,
            "reported_by": str(self.reported_by.id) if self.reported_by else None,
            "created_at": self.created_at.isoformat()
        }


# ------------------ Service Request Model ------------------

class ServiceRequest(Document):
    service_type = StringField(required=True)  # e.g., Cleaning, Maintenance
    details = StringField()
    requested_by = ReferenceField(User)
    created_at = DateTimeField(default=datetime.utcnow)

    def to_json(self):
        return {
            "id": str(self.id),
            "service_type": self.service_type,
            "details": self.details,
            "requested_by": str(self.requested_by.id) if self.requested_by else None,
            "created_at": self.created_at.isoformat()
        }


# ------------------ Feedback Model ------------------

class Feedback(Document):
    user = ReferenceField(User)
    rating = IntField(min_value=1, max_value=5)
    comment = StringField()
    submitted_at = DateTimeField(default=datetime.utcnow)

    def to_json(self):
        return {
            "id": str(self.id),
            "user": str(self.user.id) if self.user else None,
            "rating": self.rating,
            "comment": self.comment,
            "submitted_at": self.submitted_at.isoformat()
        }


# ------------------ Notification Model ------------------

class Notification(Document):
    user = ReferenceField(User)
    message = StringField(required=True)
    is_read = BooleanField(default=False)
    sent_at = DateTimeField(default=datetime.utcnow)

    def to_json(self):
        return {
            "id": str(self.id),
            "user": str(self.user.id) if self.user else None,
            "message": self.message,
            "is_read": self.is_read,
            "sent_at": self.sent_at.isoformat()
        }


# ------------------ Discussion Model ------------------

class Discussion(Document):
    topic = StringField(required=True)
    posted_by = ReferenceField(User)
    comments = ListField(StringField())  # Format: "Username: Comment"
    created_at = DateTimeField(default=datetime.utcnow)

    def to_json(self):
        return {
            "id": str(self.id),
            "topic": self.topic,
            "posted_by": str(self.posted_by.id) if self.posted_by else None,
            "comments": self.comments,
            "created_at": self.created_at.isoformat()
        }


# ------------------ Duplicate Resolved Request Model ------------------

class DuplicateResolvedRequest(Document):
    original_issue = ReferenceField(Issue)
    duplicate_title = StringField()
    reported_at = DateTimeField(default=datetime.utcnow)

    def to_json(self):
        return {
            "id": str(self.id),
            "original_issue": str(self.original_issue.id) if self.original_issue else None,
            "duplicate_title": self.duplicate_title,
            "reported_at": self.reported_at.isoformat()
        }
