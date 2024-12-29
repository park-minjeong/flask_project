from flask import Flask, render_template, session, redirect, url_for, flash, request
from flask_sqlalchemy import SQLAlchemy
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from flask_migrate import Migrate
import os
from datetime import datetime

db = SQLAlchemy()
migrate = Migrate()

def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'f5d3a687bc0301f6a50211d86c0a31c513880705854de0fc1810dbe94d958f99'
    app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:root@localhost/flask_db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['UPLOAD_FOLDER'] = 'uploads/'  # 파일 업로드 폴더

    db.init_app(app)
    migrate.init_app(app, db)  # Flask-Migrate 초기화

    # 사용자 모델
    class User(db.Model):
        id = db.Column(db.Integer, primary_key=True)
        username = db.Column(db.String(80), unique=True, nullable=False)
        password = db.Column(db.String(200), nullable=False)
        phone = db.Column(db.String(15), nullable=True)
        birthdate = db.Column(db.Date, nullable=True)
        address = db.Column(db.String(200), nullable=True)
        created_at = db.Column(db.DateTime, nullable=False, default=db.func.current_timestamp())
        is_admin = db.Column(db.Boolean, default=False)

    # 메인 페이지
    @app.route('/')
    def main():
        return render_template('main.html')

    # 로그인 페이지
    @app.route('/login', methods=['GET', 'POST'])
    def login():
        if request.method == 'POST':
            username = request.form['username']
            password = request.form['password']

            # 사용자 확인
            user = User.query.filter_by(username=username).first()
            if not user or not check_password_hash(user.password, password):
                flash('아이디 또는 비밀번호가 잘못되었습니다.', 'danger')
                return redirect(url_for('login'))

            # 세션에 사용자 ID 저장
            session['user_id'] = user.id
            flash('로그인 성공!', 'success')

            # 관리자 분기 처리
            if user.is_admin:
                return redirect(url_for('admin'))
            else:
                return redirect(url_for('main'))

        return render_template('login.html')
    
    # 로그아웃 라우트
    @app.route('/logout')
    def logout():
        session.pop('user_id', None)  # 세션에서 사용자 ID 제거
        flash('로그아웃되었습니다.', 'success')
        return redirect(url_for('login'))

    # 회원가입 페이지
    @app.route('/signup', methods=['GET', 'POST'])
    def signup():
        if request.method == 'POST':
            username = request.form['username']
            password = request.form['password']
            phone = request.form['phone']
            birthdate = request.form['birthdate']
            address = request.form['address']

            # 사용자 이름 중복 확인
            if User.query.filter_by(username=username).first():
                flash('이미 사용 중인 아이디입니다.', 'danger')
                return redirect(url_for('signup'))

            # 사용자 정보 저장
            hashed_password = generate_password_hash(password, method='pbkdf2:sha256')  # 비밀번호 해싱
            user = User(username=username, password=hashed_password, phone=phone,
                        birthdate=birthdate, address=address)
            db.session.add(user)
            db.session.commit()

            flash('회원가입이 완료되었습니다!', 'success')
            return redirect(url_for('login'))

        return render_template('signup.html')

    # 마이페이지
    @app.route('/mypage', methods=['GET', 'POST'])
    def mypage():
        if 'user_id' not in session:
            return redirect(url_for('login'))  # 로그인하지 않은 경우 리다이렉트

        user = User.query.get(session['user_id'])  # 세션에서 사용자 정보 가져오기

        if request.method == 'POST':
            # 수정된 데이터 가져오기
            user.phone = request.form['phone']
            user.birthdate = request.form['birthdate']
            user.address = request.form['address']
            
            db.session.commit()  # 데이터베이스에 변경사항 저장
            flash('정보가 성공적으로 수정되었습니다!', 'success')
            return redirect(url_for('mypage'))

        return render_template('mypage.html', user=user)

    # 게시판 페이지
    posts = []

    @app.route('/board', methods=['GET'])
    def board():
        query = request.args.get('query')
        filtered_posts = posts
        if query:
            filtered_posts = [post for post in posts if query.lower() in post['title'].lower()]
        return render_template('board.html', posts=filtered_posts)

    @app.route('/board/create', methods=['POST'])
    def create_post():
        title = request.form['title']
        content = request.form['content']
        file = request.files['file']
        filename = None
        if file:
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        
        post = {
            'id': len(posts) + 1,
            'title': title,
            'content': content,
            'file': filename,
            'created_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
        posts.append(post)
        flash('게시글이 성공적으로 작성되었습니다!', 'success')
        return redirect(url_for('board'))

    @app.route('/board/<int:post_id>')
    def post_detail(post_id):
        post = next((post for post in posts if post['id'] == post_id), None)
        if not post:
            flash('게시글을 찾을 수 없습니다.', 'danger')
            return redirect(url_for('board'))
        return render_template('post_detail.html', post=post)

    @app.route('/board/delete/<int:post_id>', methods=['POST'])
    def delete_post(post_id):
        global posts
        posts = [post for post in posts if post['id'] != post_id]
        flash('게시글이 삭제되었습니다.', 'danger')
        return redirect(url_for('board'))

    # 관리자 페이지
    @app.route('/admin')
    def admin():
        if 'user_id' not in session:
            flash('로그인이 필요합니다.', 'warning')
            return redirect(url_for('login'))

        current_user = User.query.get(session['user_id'])
        if not current_user or not current_user.is_admin:
            flash('관리자 권한이 필요합니다.', 'warning')
            return redirect(url_for('main'))

        users = User.query.all()
        return render_template('admin.html', users=users)

    return app
