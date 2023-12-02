from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class FileStatus(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True, nullable=False)
    status = db.Column(db.Integer, nullable=False)
    isAnalysis = db.Column(db.Integer, nullable=False)
    date = db.Column(db.DateTime, nullable=False)
    size = db.Column(db.Integer, nullable=False)
    path = db.Column(db.String(80), nullable=False)

    def __repr__(self):
        return f'<CodeQL {self.name}>'

class Report(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=False, nullable=False)
    vulnname = db.Column(db.String(80), nullable=False)
    description = db.Column(db.String(200), nullable=False) 
    severity = db.Column(db.String(80), nullable=False)
    message = db.Column(db.String(200), nullable=False)
    path = db.Column(db.String(80), nullable=False)
    startline = db.Column(db.Integer, nullable=False)
    startcolumn = db.Column(db.Integer, nullable=False)
    endline = db.Column(db.Integer, nullable=False)
    endcolumn = db.Column(db.Integer, nullable=False)

    def __repr__(self):
        return f'<Report {self.name}>'