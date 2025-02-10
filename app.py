from flask import Flask, render_template, request, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from models import db, User

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///mydb.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# DB作成用（初回のみ有効化）
@app.before_first_request
def create_tables():
    db.create_all()

@app.route('/')
def index():
    return 'トップページ（ログインはこちら: /login）'

# --- ログイン / ログアウト ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        uname = request.form['username']
        pw = request.form['password']
        user = User.query.filter_by(username=uname).first()
        if user and check_password_hash(user.password, pw):
            login_user(user)
            return redirect(url_for('index'))
        else:
            return "ログイン失敗"
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

# --- 管理者用ページ ---
@app.route('/admin')
@login_required
def admin():
    if not current_user.is_admin:
        return "権限がありません", 403
    users = User.query.all()
    return render_template('admin.html', users=users)

# --- 新規ユーザ追加 ---
@app.route('/admin/add_user', methods=['GET','POST'])
@login_required
def add_user():
    if not current_user.is_admin:
        return "権限がありません", 403

    if request.method == 'POST':
        uname = request.form['username']
        pw = request.form['password']
        hashed_pw = generate_password_hash(pw)
        new_user = User(username=uname, password=hashed_pw)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('admin'))
    return render_template('add_user.html')

# --- ユーザごとのページ ---
@app.route('/user/<username>')
@login_required
def user_page(username):
    """
    ユーザ名に応じてページを表示。
    例）/user/alice -> 'alice' のページ
    """
    user = User.query.filter_by(username=username).first()
    if not user:
        return "ユーザが見つかりません", 404

    # 自分自身か、管理者だけがアクセスできるようにする例
    if user.username != current_user.username and not current_user.is_admin:
        return "他のユーザページにはアクセスできません", 403

    return render_template('user_page.html', user=user)

if __name__ == '__main__':
    app.run(debug=True)
