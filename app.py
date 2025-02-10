from flask import Flask, render_template, request, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'  # 本番環境では安全な値に変更してください
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///mydb.db'  # SQLite を利用。必要に応じて他のDBに変更可
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# ユーザーモデル
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(256), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# アプリ起動前にDBテーブルを作成（初回のみ有効）
@app.before_first_request
def create_tables():
    db.create_all()

# トップページ（ログイン前後共通）
@app.route('/')
def index():
    return render_template('index.html')

# ログインページ
@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        uname = request.form.get('username')
        pw = request.form.get('password')

        # 管理者としてログインする場合の判定
        if uname == 'honjobunseki' and pw == '78387838':
            # DBに管理者ユーザが存在しない場合は作成
            admin = User.query.filter_by(username='honjobunseki').first()
            if not admin:
                admin = User(
                    username='honjobunseki',
                    password=generate_password_hash('78387838'),
                    is_admin=True
                )
                db.session.add(admin)
                db.session.commit()
            login_user(admin)
            return redirect(url_for('admin'))
        
        # 通常のユーザとしてのログイン
        user = User.query.filter_by(username=uname).first()
        if user and check_password_hash(user.password, pw):
            login_user(user)
            return redirect(url_for('index'))
        else:
            error = "ユーザ名またはパスワードが間違っています。"
    return render_template('login.html', error=error)

# ログアウト
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

# 管理画面（管理者のみアクセス可能）
@app.route('/admin')
@login_required
def admin():
    if not current_user.is_admin:
        return "権限がありません", 403
    users = User.query.all()
    return render_template('admin.html', users=users)

# 管理画面から新規ユーザを追加するページ
@app.route('/admin/add_user', methods=['GET', 'POST'])
@login_required
def add_user():
    if not current_user.is_admin:
        return "権限がありません", 403
    error = None
    if request.method == 'POST':
        uname = request.form.get('username')
        pw = request.form.get('password')
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
            return redirect(url_for('admin'))
    return render_template('add_user.html', error=error)

# ユーザごとの専用ページ（動的ルーティング）
@app.route('/user/<username>')
@login_required
def user_page(username):
    user = User.query.filter_by(username=username).first()
    if not user:
        return "ユーザが見つかりません", 404

    # 自分のページか、管理者ならアクセス可能にする例
    if user.username != current_user.username and not current_user.is_admin:
        return "他のユーザのページにはアクセスできません", 403

    return render_template('user_page.html', user=user)

if __name__ == '__main__':
    app.run(debug=True)
