from flask import Flask, render_template, request, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import os

# Flaskアプリケーションの設定
app = Flask(__name__)

# SECRET_KEYを環境変数から取得
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your_default_secret_key')  # 環境変数がない場合のデフォルト値

# RenderのPostgreSQL接続情報を環境変数から取得
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL')  # Renderの環境変数を使用

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  # トラッキングを無効に

# SQLAlchemyの初期化
db = SQLAlchemy(app)

# ログインマネージャーの設定
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# ユーザーモデル（データベースのテーブルとして使用）
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)

# ユーザーの読み込み
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# インデックスページ（ホームページ）
@app.route('/')
def home():
    return render_template('index.html')

# ログインページ
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()  # ユーザー名で検索
        if user and user.password == password:  # パスワードが一致する場合
            login_user(user)
            return redirect(url_for('dashboard'))
    return render_template('login.html')

# ダッシュボードページ（ログイン後）
@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

# ログアウト
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

# データベース作成（最初の実行時にデータベースファイルを作成）
@app.before_first_request
def create_tables():
    db.create_all()

# アプリケーションの実行
if __name__ == '__main__':
    app.run(debug=True)
