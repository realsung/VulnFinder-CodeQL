from flask import Flask, render_template, request, flash, redirect, url_for, make_response, jsonify
from flask_cors import CORS
from werkzeug.utils import secure_filename
import os
import random
import hashlib
import re
import requests
import zipfile

UPLOAD_FOLDER = '/app/uploads'
ALLOWED_EXTENSIONS = {'zip'}

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
cors = CORS(app, resources={r"/upload": {"origins": "https://api.github.com"}})

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/')
def hello():
    return 'Init Test'

'''
Todo
- 날짜 정보 추가
- 파일 저장 경로
- 파일 이름
- 파일 크기
'''
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

            resp = make_response(jsonify({'message': 'OK'}), 200)
            return resp
        else:
            resp = make_response(jsonify({'message': 'Invalid file extension'}), 400)
            return resp
        
    elif request.method == 'GET':
        # id = url
        # github api https://api.github.com/repos/realsung/VulnFinder-CodeQL/zipball
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
            resp = make_response(jsonify({'message': 'OK'}), 200)
            return resp
        else:
            resp = make_response(jsonify({'message': 'Error'}), 400)
            return resp


@app.route('/codeql-create')
def codeql_create():
    return 'CodeQL Create Test'

@app.route('/codeql-analyze')
def codeql_analyze():
    return 'CodeQL Analyze Test'

@app.route('/status')
def status():
    return 'Status Test'

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False, threaded=False, processes=2)