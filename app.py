from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, login_user, logout_user, login_required,
    current_user, UserMixin
)
from werkzeug.security import generate_password_hash, check_password_hash

# 管理者用定数
ADMIN_USERNAME = 'honjobunseki'
ADMIN_PASSWORD = '78387838'

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'  # 本番では十分にランダムな値に変更してください
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///mydb.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# ユーザモデル
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(256), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.before_first_request
def create_tables():
    db.create_all()

# トップページ（任意）
@app.route('/')
def index():
    return render_template('index.html')

# ログインページ
@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        # 入力値の前後の空白を除去
        uname = request.form.get('username', '').strip()
        pw = request.form.get('password', '').strip()

        # 管理者としてログインする場合のチェック
        if uname == ADMIN_USERNAME and pw == ADMIN_PASSWORD:
            admin = User.query.filter_by(username=ADMIN_USERNAME).first()
            if not admin:
                # 管理者ユーザが存在しなければ自動作成
                admin = User(
                    username=ADMIN_USERNAME,
                    password=generate_password_hash(ADMIN_PASSWORD),
                    is_admin=True
                )
                db.session.add(admin)
                db.session.commit()
            login_user(admin)
            flash("管理者としてログインしました", "success")
            return redirect(url_for('admin'))
        
        # 一般ユーザとしてのログイン処理
        user = User.query.filter_by(username=uname).first()
        if user and check_password_hash(user.password, pw):
            login_user(user)
            flash("ログインしました", "success")
            # 一般ユーザの場合、入力したユーザのページに移動
            return redirect(url_for('user_page', username=user.username))
        else:
            error = "ユーザ名またはパスワードが間違っています。"
    return render_template('login.html', error=error)

# ログアウト
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("ログアウトしました", "info")
    return redirect(url_for('index'))

# 管理画面（管理者のみアクセス可能）
@app.route('/admin')
@login_required
def admin():
    if not current_user.is_admin:
        return "権限がありません", 403
    # 管理者の場合、管理画面用のテンプレート（admin.html）を表示
    return render_template('admin.html')

# ユーザページ
@app.route('/user/<username>')
@login_required
def user_page(username):
    # データベースから対象のユーザを取得
    user = User.query.filter_by(username=username).first()
    if not user:
        return "ユーザが見つかりません", 404
    # 管理者なら全ユーザページにアクセス可能、通常ユーザは自分のページのみ
    if not current_user.is_admin and user.username != current_user.username:
        return "他のユーザのページにはアクセスできません", 403
    return render_template('user_page.html', user=user)

if __name__ == '__main__':
    app.run(debug=True)
