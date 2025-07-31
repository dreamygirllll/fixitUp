from mongoengine import Document, StringField, EmailField, IntField, FloatField, BooleanField, ReferenceField, \
    ListField, DateTimeField
from flask_login import UserMixin
from datetime import datetime
from mongoengine import (
    Document, EmbeddedDocument, StringField, ReferenceField, DateTimeField,
    ListField, EmbeddedDocumentField
)


# ------------------ User Model ------------------

class User(Document, UserMixin):
    name = StringField(required=True)
    email = EmailField(required=True, unique=True)
    password = StringField(required=True)
    role = StringField(default='user')
    meta = {'collection': 'user'}
    age = IntField()

    def get_id(self):
        return str(self.id)

    def to_json(self):
        return {
            "id": str(self.id),
            "name": self.name,
            "email": self.email,
            "age": self.age,
            "role": self.role
        }

    @property
    def is_admin(self):
        return False

class Admin(Document, UserMixin):
    name = StringField(required=True)
    email = EmailField(required=True, unique=True)
    password = StringField(required=True)
    contact = StringField()
    designation = StringField(default="Admin")  # Optional: e.g., System Admin, City Manager, etc.
    role = StringField(default='admin')
    meta = {'collection': 'admins'}
    def get_id(self):
        return str(self.id)

    def to_json(self):
        return {
            "id": str(self.id),
            "name": self.name,
            "email": self.email,
            "contact": self.contact,
            "designation": self.designation,
            "role":self.role
        }


class Authorities(Document):
    city = StringField(required=True, unique=True)
    email = EmailField(required=True)

    meta = {'collection': 'authorities'}

    def to_json(self):
        return {
            "id": str(self.id),
            "city": self.city,
            "email": self.email
        }

class Reply(EmbeddedDocument):
    user = ReferenceField('User', required=True)
    text = StringField(required=True)
    created_at = DateTimeField(default=datetime.utcnow)

class Comment(EmbeddedDocument):
    user = ReferenceField('User', required=True)
    text = StringField(required=True)
    created_at = DateTimeField(default=datetime.utcnow)
    replies = ListField(EmbeddedDocumentField(Reply))

class Discussions(Document):
    title = StringField(required=True)
    message = StringField(required=True)
    category = StringField(default='General')
    posted_by = ReferenceField('User', required=True)
    created_at = DateTimeField(default=datetime.utcnow)
    comments = ListField(EmbeddedDocumentField(Comment))

class Issue(Document):
    title = StringField(required=True)
    description = StringField()
    city = StringField(required=True)
    area = StringField()  # Newly added
    email = StringField(required=True)
    status = StringField(default="pending", choices=["pending", "in-progress", "resolved"])
    email_clicked = BooleanField(default=False)
    reported_by = ReferenceField(User)
    created_at = DateTimeField(default=datetime.utcnow)

    def to_json(self):
        return {
            "id": str(self.id),
            "title": self.title,
            "description": self.description,
            "city": self.city,
            "area": self.area,
            "email": self.email,
            "status": self.status,
            "email_clicked": self.email_clicked,
            "reported_by": str(self.reported_by.id) if self.reported_by else None,
            "created_at": self.created_at.isoformat()
        }
class UserEmail(Document):
    recipient_email = StringField(required=True)
    subject = StringField(required=True)
    message_body = StringField()
    issue = ReferenceField(Issue)
    sent_at = DateTimeField(default=datetime.utcnow)

    meta = {'collection': 'user_emails'}

    def to_json(self):
        return {
            "id": str(self.id),
            "recipient_email": self.recipient_email,
            "subject": self.subject,
            "message_body": self.message_body,
            "issue": str(self.issue.id) if self.issue else None,
            "sent_at": self.sent_at.isoformat()
        }


# ------------------ Feedback Model ------------------

from mongoengine import *
from datetime import datetime

class Feedback(Document):
    user = ReferenceField(User, required=True)
    problem = StringField(required=True)
    rating = IntField(min_value=1, max_value=5, required=True)
    comment = StringField(required=True)
    submitted_at = DateTimeField(default=datetime.utcnow)

    # 🆕 New field for sentiment result
    sentiment = StringField(choices=["positive", "neutral", "negative"])

    def to_json(self):
        return {
            "id": str(self.id),
            "user": str(self.user.id) if self.user else None,
            "problem": self.problem,
            "rating": self.rating,
            "comment": self.comment,
            "sentiment": self.sentiment,  # include sentiment in output
            "submitted_at": self.submitted_at.isoformat()
        }


class Notification(Document):
    user = ReferenceField(User, required=True)  # Reference to actual User document
    message = StringField(required=True)
    created_at = DateTimeField(default=datetime.utcnow)
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
