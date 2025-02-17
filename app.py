import os
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, login_user, logout_user, login_required,
    current_user, UserMixin
)
from werkzeug.security import generate_password_hash, check_password_hash

########################
# 管理者ID・パスワード
########################
ADMIN_USERNAME = 'honjobunseki'
ADMIN_PASSWORD = '78387838'

app = Flask(__name__)
# Render等でSECRET_KEYを環境変数に設定している場合
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'fallback_secret_key')

# PostgreSQLの接続情報 (環境変数を利用、無ければデフォルト)
db_host = os.environ.get('DB_HOST', 'localhost')
db_name = os.environ.get('DB_NAME', 'jizen')
db_port = os.environ.get('DB_PORT', '5432')
db_user = os.environ.get('DB_USER', 'jizen_user')
db_password = os.environ.get('DB_PASSWORD', '')

app.config['SQLALCHEMY_DATABASE_URI'] = (
    f"postgresql://{db_user}:{db_password}@{db_host}:{db_port}/{db_name}"
)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

########################
#       モデル定義
########################

class User(UserMixin, db.Model):
    __tablename__ = 'users'  # テーブル名を明示的に指定
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(256), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

    # 下記はユーザページで利用するリレーション例(任意)
    # partners = db.relationship('Partner', backref='owner', lazy=True)
    # staffs = db.relationship('Staff', backref='owner', lazy=True)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.before_first_request
def create_tables():
    """初回アクセス時にテーブルを自動作成。"""
    db.create_all()

########################
#       ルート
########################

@app.route('/')
def index():
    """トップページ"""
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """ログインページ。管理者 or 一般ユーザを判定。"""
    error = None
    if request.method == 'POST':
        uname = request.form.get('username', '').strip()
        pw = request.form.get('password', '').strip()

        # 管理者ログイン
        if uname == ADMIN_USERNAME and pw == ADMIN_PASSWORD:
            admin = User.query.filter_by(username=ADMIN_USERNAME).first()
            if not admin:
                # 管理者ユーザが存在しなければ作成する
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

        # 一般ユーザログイン
        user = User.query.filter_by(username=uname).first()
        if user and check_password_hash(user.password, pw):
            login_user(user)
            flash("ログインしました", "success")
            return redirect(url_for('user_page', username=user.username))
        else:
            error = "ユーザ名またはパスワードが間違っています。"
    return render_template('login.html', error=error)

@app.route('/logout')
@login_required
def logout():
    """ログアウト"""
    logout_user()
    flash("ログアウトしました", "info")
    return redirect(url_for('index'))

########################
#  管理画面 (admin)
########################
@app.route('/admin')
@login_required
def admin():
    """管理画面: 全ユーザを表示 & ユーザ追加・削除画面へ遷移など。"""
    if not current_user.is_admin:
        return "権限がありません", 403

    # 全ユーザを取得しテンプレートへ
    all_users = User.query.all()
    return render_template('admin.html', users=all_users)

@app.route('/admin/add_user', methods=['GET', 'POST'])
@login_required
def add_user():
    """新規ユーザ追加フォーム"""
    if not current_user.is_admin:
        return "権限がありません", 403

    error = None
    if request.method == 'POST':
        uname = request.form.get('username', '').strip()
        pw = request.form.get('password', '').strip()
        # 既存ユーザ名と重複があればエラー
        if User.query.filter_by(username=uname).first():
            error = "そのユーザ名は既に使われています。"
        else:
            new_user = User(
                username=uname,
                password=generate_password_hash(pw),
                is_admin=False
            )
            db.session.add(new_user)
            db.session.commit()
            flash("ユーザが追加されました", "success")
            return redirect(url_for('admin'))

    return render_template('add_user.html', error=error)

@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    """ユーザ削除。管理者自身は削除不可。"""
    if not current_user.is_admin:
        return "権限がありません", 403

    user_to_delete = User.query.get(user_id)
    if not user_to_delete:
        flash("削除対象のユーザが見つかりません", "warning")
        return redirect(url_for('admin'))
    if user_to_delete.username == ADMIN_USERNAME:
        flash("管理者ユーザは削除できません", "danger")
        return redirect(url_for('admin'))

    db.session.delete(user_to_delete)
    db.session.commit()
    flash("ユーザが削除されました", "success")
    return redirect(url_for('admin'))

########################
#    ユーザページ
########################
@app.route('/user/<username>')
@login_required
def user_page(username):
    """一般ユーザのページ。管理者なら全ユーザページ閲覧可。"""
    user = User.query.filter_by(username=username).first()
    if not user:
        return "ユーザが見つかりません", 404
    if not current_user.is_admin and user.username != current_user.username:
        return "他のユーザのページにはアクセスできません", 403

    # 以下のpartners, staffs などは、必要に応じて実装/表示
    # partners = Partner.query.filter_by(user_id=user.id).all()
    # staffs = Staff.query.filter_by(user_id=user.id).all()

    return render_template('user_page.html', user=user)

if __name__ == '__main__':
    app.run(debug=True)
