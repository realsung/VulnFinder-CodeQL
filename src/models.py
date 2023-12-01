from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class FileStatus(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True, nullable=False)
    status = db.Column(db.Integer, nullable=False)
    date = db.Column(db.Date, nullable=False)
    size = db.Column(db.Integer, nullable=False)
    path = db.Column(db.String(80), nullable=False)

    def __repr__(self):
        return f'<CodeQL {self.name}>'