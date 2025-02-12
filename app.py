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
app.config['SECRET_KEY'] = 'your_secret_key'  # 本番環境では十分にランダムな値に変更してください

# PostgreSQL の jizen データベースを利用するための接続文字列（ご自身の環境に合わせて変更）
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://your_postgres_user:your_postgres_password@your_postgres_host:your_postgres_port/jizen'
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
    # ※必要に応じて施行パートナー情報や担当者情報のリレーションを追加できます

# ※ここではシンプルにユーザ管理に専念します

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.before_first_request
def create_tables():
    db.create_all()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        # 入力値の前後の空白を除去
        uname = request.form.get('username', '').strip()
        pw = request.form.get('password', '').strip()
        # 管理者としてログインする場合
        if uname == ADMIN_USERNAME and pw == ADMIN_PASSWORD:
            admin = User.query.filter_by(username=ADMIN_USERNAME).first()
            if not admin:
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
        # 通常ユーザとしてのログイン
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
    logout_user()
    flash("ログアウトしました", "info")
    return redirect(url_for('index'))

# 管理画面（管理者のみアクセス可能）
@app.route('/admin')
@login_required
def admin():
    if not current_user.is_admin:
        return "権限がありません", 403
    users = User.query.all()
    return render_template('admin.html', users=users)

# 管理画面：新規ユーザ追加
@app.route('/admin/add_user', methods=['GET', 'POST'])
@login_required
def add_user():
    if not current_user.is_admin:
        return "権限がありません", 403
    error = None
    if request.method == 'POST':
        uname = request.form.get('username', '').strip()
        pw = request.form.get('password', '').strip()
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

# 管理画面：ユーザ削除
@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    if not current_user.is_admin:
        return "権限がありません", 403
    user_to_delete = User.query.get(user_id)
    if not user_to_delete:
        flash("削除対象のユーザが見つかりません", "warning")
        return redirect(url_for('admin'))
    # 管理者自身は削除できないようにする
    if user_to_delete.username == ADMIN_USERNAME:
        flash("管理者ユーザは削除できません", "danger")
        return redirect(url_for('admin'))
    db.session.delete(user_to_delete)
    db.session.commit()
    flash("ユーザが削除されました", "success")
    return redirect(url_for('admin'))

# ユーザごとのページ
@app.route('/user/<username>')
@login_required
def user_page(username):
    user = User.query.filter_by(username=username).first()
    if not user:
        return "ユーザが見つかりません", 404
    # 管理者はすべてのユーザページにアクセス可能、通常ユーザは自分のページのみアクセス可能
    if not current_user.is_admin and user.username != current_user.username:
        return "他のユーザのページにはアクセスできません", 403
    return render_template('user_page.html', user=user)

if __name__ == '__main__':
    app.run(debug=True)
