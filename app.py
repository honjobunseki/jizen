import os
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, login_user, logout_user, login_required,
    current_user, UserMixin
)
from werkzeug.security import generate_password_hash, check_password_hash

ADMIN_USERNAME = 'honjobunseki'
ADMIN_PASSWORD = '78387838'

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'fallback_secret_key')

# PostgreSQL接続例。環境変数などに合わせて設定してください
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

# ユーザモデル
class User(UserMixin, db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(256), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    # 施行パートナー、担当者とのリレーション
    partners = db.relationship('Partner', backref='owner', lazy=True)
    staffs = db.relationship('Staff', backref='owner', lazy=True)

# 施行パートナー(下請け・協力業者)モデル
class Partner(db.Model):
    __tablename__ = 'partners'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    company_name = db.Column(db.String(200), nullable=False)
    representative = db.Column(db.String(200))   # 代表者
    phone_number = db.Column(db.String(20))

# 担当者モデル
class Staff(db.Model):
    __tablename__ = 'staffs'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    staff_name = db.Column(db.String(200), nullable=False)
    # 必要に応じて担当者種別や石綿有資格者情報などを追加
    # ここでは簡略化

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.before_first_request
def create_tables():
    db.create_all()

# （ログイン、ログアウト、管理画面などのルートは省略/前述通りとする）

########################
#    ユーザページ      #
########################
@app.route('/user/<username>')
@login_required
def user_page(username):
    """ユーザページ: 4つのタブ
       (1) 施行パートナー一覧
       (2) 施行パートナー登録
       (3) 担当者一覧
       (4) 担当者登録
    """
    user = User.query.filter_by(username=username).first()
    if not user:
        return "ユーザが見つかりません", 404
    # 管理者は全ユーザページにアクセス可。通常ユーザは自分だけ
    if not current_user.is_admin and user.username != current_user.username:
        return "他のユーザのページにはアクセスできません", 403

    # 施行パートナー一覧を取得
    partners = Partner.query.filter_by(user_id=user.id).all()
    # 担当者一覧を取得
    staffs = Staff.query.filter_by(user_id=user.id).all()

    return render_template(
        'user_page.html',
        user=user,
        partners=partners,
        staffs=staffs
    )

########################
#  施行パートナー登録  #
########################
@app.route('/user/<username>/partner/add', methods=['GET', 'POST'])
@login_required
def add_partner(username):
    user = User.query.filter_by(username=username).first()
    if not user:
        return "ユーザが見つかりません", 404
    # 管理者 or ユーザ本人のみ登録可
    if not current_user.is_admin and user.username != current_user.username:
        return "他のユーザのページにはアクセスできません", 403
    
    if request.method == 'POST':
        company_name = request.form.get('company_name', '').strip()
        representative = request.form.get('representative', '')
        phone_number = request.form.get('phone_number', '')

        new_partner = Partner(
            user_id=user.id,
            company_name=company_name,
            representative=representative,
            phone_number=phone_number
        )
        db.session.add(new_partner)
        db.session.commit()
        flash("施行パートナーが登録されました", "success")
        # 登録後はユーザページに戻り、一覧に表示
        return redirect(url_for('user_page', username=user.username))

    return render_template('add_partner.html', user=user)

########################
#     担当者登録       #
########################
@app.route('/user/<username>/staff/add', methods=['GET', 'POST'])
@login_required
def add_staff(username):
    user = User.query.filter_by(username=username).first()
    if not user:
        return "ユーザが見つかりません", 404
    # 管理者 or ユーザ本人のみ登録可
    if not current_user.is_admin and user.username != current_user.username:
        return "他のユーザのページにはアクセスできません", 403
    
    if request.method == 'POST':
        staff_name = request.form.get('staff_name', '').strip()
        new_staff = Staff(
            user_id=user.id,
            staff_name=staff_name,
        )
        db.session.add(new_staff)
        db.session.commit()
        flash("担当者が登録されました", "success")
        # 登録後はユーザページに戻り、担当者一覧に表示
        return redirect(url_for('user_page', username=user.username))

    return render_template('add_staff.html', user=user)

if __name__ == '__main__':
    app.run(debug=True)
