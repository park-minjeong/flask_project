from flask import Flask
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'f5d3a687bc0301f6a50211d86c0a31c513880705854de0fc1810dbe94d958f99'
    app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:root@localhost/flask_db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    db.init_app(app)

  # 기본 라우트 정의
    @app.route('/')
    def home():
        return "드디어 해냄"

    return app
