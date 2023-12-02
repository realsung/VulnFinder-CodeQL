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
from models import db, FileStatus, Report
from subprocess import Popen
from datetime import datetime, timedelta, timezone
import csv

'''
Todo
- Threading 추가
- 외래키 추가로 각 리포트 가져오기
'''

ANALYSIS_LANGUAGE = 'javascript'

# remote
# UPLOAD_FOLDER = '/app/uploads/'
# DB_PATH = '/app/codeql-db/'
# CSV_PATH = '/app/codeql-csv/'
# ANALYSIS_PATH = f'/app/{ANALYSIS_LANGUAGE}-cwe/scripts/'

# local
UPLOAD_FOLDER = '/root/VulnFinder-CodeQL/src/uploads/'
DB_PATH = '/root/VulnFinder-CodeQL/src/codeql-db/'
CSV_PATH = '/root/VulnFinder-CodeQL/src/codeql-csv/'
# ANALYSIS_PATH = f'/root/VulnFinder-CodeQL/src/{ANALYSIS_LANGUAGE}-cwe/'
ANALYSIS_PATH = f'/root/CodeQL/codeql/qlpacks/codeql/javascript-queries/0.8.3/Security/'

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

def db_uplaod_file(name, status, isAnalysis, date, size, path):
    file_status = FileStatus(name=name, status=status, isAnalysis=isAnalysis, date=date, size=size, path=path)
    db.session.add(file_status)
    db.session.commit()

def db_report(name, vulnname, description, severity, message, path, startline, startcolumn, endline, endcolumn):
    report = Report(name=name, vulnname=vulnname, description=description, severity=severity, message=message, path=path, startline=startline, startcolumn=startcolumn, endline=endline, endcolumn=endcolumn)
    db.session.add(report)
    # db.session.commit()

def get_csv_list():
    csv_list = []
    for root, dirs, files in os.walk(CSV_PATH):
        for file in files:
            if file.endswith('.csv'):
                csv_list.append(os.path.join(root, file))
    return csv_list

def read_csv_and_update_db(filename):
    with open(filename, 'r') as f:
        reader = csv.reader(f)
        # headers = next(reader, None)
        for row in reader:
            name = filename
            vulnname = row[0]
            description = row[1]
            severity = row[2]
            message = row[3]
            path = row[4]
            startline = int(row[5])
            startcolumn = int(row[6])
            endline = int(row[7])
            endcolumn = int(row[8])
            db_report(name, vulnname, description, severity, message, path, startline, startcolumn, endline, endcolumn)
        db.session.commit()

def isFileExist(filename) -> bool:
    os.path.isfile(filename)

# def db_get_file_status(id) -> FileStatus:
#     file_status = FileStatus.query.filter_by(id=id).first()
#     return file_status

def db_get_file_status_by_name(name) -> int:
    file_status = FileStatus.query.filter_by(name=name).first()
    return file_status.status

def db_get_file_isAnalysis_by_name(name) -> int:
    file_status = FileStatus.query.filter_by(name=name).first()
    return file_status.isAnalysis

def db_update_file_status_by_name(name, status):
    file_status = FileStatus.query.filter_by(name=name).first()
    file_status.status = status
    db.session.commit()

def db_update_file_isAnalysis_by_name(name, isAnalysis):
    file_status = FileStatus.query.filter_by(name=name).first()
    file_status.isAnalysis = isAnalysis
    db.session.commit()

def db_delete_file_by_id(id):
    file_status = FileStatus.query.filter_by(id=id).first()
    db.session.delete(file_status)
    db.session.commit()

def allowed_file(filename) -> bool:
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def create_db(dirname):
    try:
        # command = f'codeql database create {DB_PATH}{dirname} --source-root {UPLOAD_FOLDER}{dirname} --language=cpp --command="cmake . && make"'
        # command = f'codeql database create {DB_PATH}{dirname} --source-root {UPLOAD_FOLDER}{dirname} --language=cpp'
        # command = f'codeql database create --language=python {DB_PATH}{dirname} --source-root {UPLOAD_FOLDER}{dirname}'
        command = f'codeql database create --language=javascript {DB_PATH}{dirname} --source-root {UPLOAD_FOLDER}{dirname}'
        process = Popen(command, shell=True)
        return process
    except Exception as e:
        raise e

def analyze_db(dirname):
    try:
        # sarif 방식도 고려
        # Reference : https://docs.github.com/en/code-security/codeql-cli/getting-started-with-the-codeql-cli/analyzing-your-code-with-codeql-queries
        ql_scripts = get_ql_scripts()
        for ql_script in ql_scripts:
            script_name = ql_script.split('/')[-1].split('.ql')[0]
            # command = f'codeql database analyze --format=csv --output={CSV_PATH}{dirname}-{script_name}.csv --threads=2 {DB_PATH}{dirname} {ql_script}'
            command = f'codeql database analyze --format=csv --output={CSV_PATH}{dirname}-{script_name}.csv --threads=1 {DB_PATH}{dirname} {ql_script}'
            print("!!!!!!!!!", command)
            # command = f'codeql database analyze --format=csv --output={CSV_PATH}{dirname}.csv --threads=2 {DB_PATH}{dirname} {ql_script}'
            # codeql database analyze --format=csv --output=/root/VulnFinder-CodeQL/src/codeql-csv/cwe-079.csv --threads=2 /root/VulnFinder-CodeQL/src/codeql-db/CWE-079-383a5975 /root/CodeQL/codeql/qlpacks/codeql/javascript-queries/0.8.3/Declarations/UnusedVariable.ql
            # codeql database analyze --format=csv --output=/root/VulnFinder-CodeQL/src/codeql-csv/cwe-079.csv --threads=2 /root/VulnFinder-CodeQL/src/codeql-db/CWE-079-383a5975 /root/CodeQL/codeql/qlpacks/codeql/javascript-queries/0.8.3/Security/CWE-079/ReflectedXss.ql
            process = Popen(command, shell=True)
            process.wait()
            if os.path.exists(f'{CSV_PATH}{dirname}-{script_name}.csv'):
                read_csv_and_update_db(f'{CSV_PATH}{dirname}-{script_name}.csv')
            else:
                pass
    except Exception as e:
        raise e

def get_ql_scripts():
    ql_scripts = []
    for root, dirs, files in os.walk(ANALYSIS_PATH):
        for file in files:
            if file.endswith('.ql'):
                ql_scripts.append(os.path.join(root, file))
    return ql_scripts

@app.route('/')
def hello():
    return render_template('index.html', lang=ANALYSIS_LANGUAGE)

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
                0,
                datetime.now(), 
                os.path.getsize(os.path.join(app.config['UPLOAD_FOLDER'], filename)),
                os.path.join(app.config['UPLOAD_FOLDER'],
                filename.split('.zip')[0]))

            return redirect(url_for('filelist'))
            # resp = make_response(jsonify({'message': 'OK'}), 200)
            # return resp
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
                0,
                datetime.now(tz=KST), 
                os.path.getsize(os.path.join(app.config['UPLOAD_FOLDER'], filename)),
                os.path.join(app.config['UPLOAD_FOLDER'],
                filename.split('.zip')[0]))

            return redirect(url_for('filelist'))
            # resp = make_response(jsonify({'message': 'OK'}), 200)
            # return resp
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
        process = create_db(filename)
        process.wait()
        db_update_file_status_by_name(filename, 1)

        return jsonify({'message': f'Creating CodeQL for {filename}'})
    return jsonify({'message': 'No filename provided'}), 400

@app.route('/codeql-analysis', methods=['POST'])
def codeql_analyze():
    data = request.json
    filename = data.get('filename')
    if filename:
        if db_get_file_isAnalysis_by_name(filename) == 1:
            return jsonify({'message': f'CodeQL for {filename} already analyzed'}), 400
        db_update_file_isAnalysis_by_name(filename, 1)
        analyze_db(filename)
        return jsonify({'message': f'Analyzing CodeQL for {filename}'})
    return jsonify({'message': 'No filename provided'}), 400

@app.route('/list-csv')
def list_csv():
    dirs = get_csv_list()
    return dirs

@app.route('/status')
def status():
    data = Report.query.all()
    return render_template('status.html', data=data)

@app.route('/result')
def result():
    data = Report.query.all()
    return render_template('result.html', data=data)

@app.route('/list')
def filelist():
    files = FileStatus.query.all()
    return render_template('file_list.html', files=files)

@app.route('/test')
def test():
    return get_ql_scripts()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=True, threaded=False, processes=2)