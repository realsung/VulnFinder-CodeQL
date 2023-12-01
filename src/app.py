from flask import Flask, render_template, request, flash, redirect, url_for, make_response, jsonify
from flask_cors import CORS
from werkzeug.utils import secure_filename
import os
import random
import hashlib
import re
import requests
import zipfile
# from dotenv import load_dotenv
from flask_sqlalchemy import SQLAlchemy
from models import db, FileStatus
from subprocess import Popen
from datetime import datetime, timedelta, timezone

# remote
UPLOAD_FOLDER = '/app/uploads/'
DB_PATH = '/app/codeql-db/'

# local
# UPLOAD_FOLDER = '/root/VulnFinder-CodeQL/src/uploads/'
# DB_PATH = '/root/VulnFinder-CodeQL/src/codeql-db/'

ALLOWED_EXTENSIONS = {'zip'}
KST = timezone(timedelta(hours=9))

# load_dotenv()
app = Flask(__name__)

db_file = os.path.join(os.path.dirname(__file__), 'codeql.db')
db_uri = 'sqlite:///{}'.format(db_file)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['SQLALCHEMY_DATABASE_URI'] = db_uri
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)
with app.app_context():
    db.create_all()

cors = CORS(app, resources={r"/upload": {"origins": "https://api.github.com"}})

def db_uplaod_file(name, status, date, size, path):
    file_status = FileStatus(name=name, status=status, date=date, size=size, path=path)
    db.session.add(file_status)
    db.session.commit()

# def db_get_file_status(id) -> FileStatus:
#     file_status = FileStatus.query.filter_by(id=id).first()
#     return file_status

def db_get_file_status_by_name(name) -> int:
    file_status = FileStatus.query.filter_by(name=name).first()
    return file_status.status

def db_update_file_status_by_name(name, status):
    file_status = FileStatus.query.filter_by(name=name).first()
    file_status.status = status
    db.session.commit()

def db_delete_file_by_id(id):
    file_status = FileStatus.query.filter_by(id=id).first()
    db.session.delete(file_status)
    db.session.commit()

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def create_db(dirname):
    try:
        command = f'codeql database create {DB_PATH}{dirname} --source-root {UPLOAD_FOLDER}{dirname} --language=cpp --command="cmake . && make"'
        command = f'codeql database create {DB_PATH}{dirname} --source-root {UPLOAD_FOLDER}{dirname} --language=cpp'
        print(command)
        # command = f'codeql database create --language=python {DB_PATH}{dirname} --source-root {UPLOAD_FOLDER}{dirname}'
        # command = f'codeql database create --language=csharp {DB_PATH}{dirname} --source-root {UPLOAD_FOLDER}{dirname}'
        process = Popen(command, shell=True)
        return process
    except Exception as e:
        raise e

@app.route('/')
def hello():
    return 'Init Test'

@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file part')
            return redirect(url_for('upload'))
        
        file = request.files['file']
        if file.filename == '':
            flash('No selected file')
            return redirect(url_for('upload'))
        
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            filename = filename.split('.zip')[0] + '-' + hashlib.sha256(str(random.getrandbits(256)).encode('utf-8')).hexdigest()[:8] + '.zip'
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            with zipfile.ZipFile(os.path.join(app.config['UPLOAD_FOLDER'], filename), 'r') as zip_ref:
                zip_ref.extractall(os.path.join(app.config['UPLOAD_FOLDER'], filename.split('.zip')[0]))

            db_uplaod_file(
                filename.split('.zip')[0], 
                0, 
                datetime.now(), 
                os.path.getsize(os.path.join(app.config['UPLOAD_FOLDER'], filename)),
                os.path.join(app.config['UPLOAD_FOLDER'],
                filename.split('.zip')[0]))

            resp = make_response(jsonify({'message': 'OK'}), 200)
            return resp
        else:
            resp = make_response(jsonify({'message': 'Invalid file extension'}), 400)
            return resp
        
    elif request.method == 'GET':
        url = request.args.get('url')
        if not url:
            return render_template('upload.html')
        
        match = re.search(r'https://github\.com/(.+)/(.+)', url)
        if not match:
            resp = make_response(jsonify({'message': 'Invalid url'}), 400)
            return resp
        
        user = match.group(1)
        repo = match.group(2)
        api_url = f'https://api.github.com/repos/{user}/{repo}/zipball'
        api_res = requests.get(api_url)
        if api_res.status_code == 200:
            filename = f'{user}-{repo}-{hashlib.sha256(str(random.getrandbits(256)).encode("utf-8")).hexdigest()[:8]}.zip'
            with open(os.path.join(app.config['UPLOAD_FOLDER'], filename), 'wb') as f:
                f.write(api_res.content)
            with zipfile.ZipFile(os.path.join(app.config['UPLOAD_FOLDER'], filename), 'r') as zip_ref:
                zip_ref.extractall(os.path.join(app.config['UPLOAD_FOLDER'], filename.split('.zip')[0]))

            db_uplaod_file(
                filename.split('.zip')[0], 
                0, 
                datetime.now(tz=KST), 
                os.path.getsize(os.path.join(app.config['UPLOAD_FOLDER'], filename)),
                os.path.join(app.config['UPLOAD_FOLDER'],
                filename.split('.zip')[0]))

            resp = make_response(jsonify({'message': 'OK'}), 200)
            return resp
        else:
            resp = make_response(jsonify({'message': 'Error'}), 400)
            return resp


@app.route('/codeql-create', methods=['POST'])
def codeql_create():
    data = request.json
    filename = data.get('filename')
    if filename:
        if db_get_file_status_by_name(filename) == 1:
            return jsonify({'message': f'CodeQL for {filename} already exists'}), 400
        db_update_file_status_by_name(filename, 1)
        process = create_db(filename)

        return jsonify({'message': f'Creating CodeQL for {filename}'})
    return jsonify({'message': 'No filename provided'}), 400

@app.route('/codeql-analyze')
def codeql_analyze():
    # database analyze --format csv --output=results.csv --search-path=/home/runner/work/CodeQL-Test/CodeQL-Test --threads=4 --ram=16G --timeout=60m
    return 'CodeQL Analyze Test'

@app.route('/status')
def status():
    return 'Status Test'

@app.route('/list')
def filelist():
    files = FileStatus.query.all()
    return render_template('file_list.html', files=files)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=True, threaded=False, processes=2)