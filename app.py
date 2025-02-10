from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, login_user, logout_user,
    login_required, current_user, UserMixin
)
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'  # 本番では安全な値に変更
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
    # 1対多のリレーション：1人のユーザに対して複数の施行パートナー情報
    partners = db.relationship('Partner', backref='owner', lazy=True)

# 施行パートナーモデル
class Partner(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    company_name = db.Column(db.String(200), nullable=False)  # 業者名
    representative = db.Column(db.String(200))                # 代表者職氏名（任意）
    labor_insurance_number = db.Column(db.String(100))          # 労働保険番号（任意）
    prefecture_code = db.Column(db.String(50))                  # 府県コード
    responsibility = db.Column(db.String(50))                 # 所掌
    jurisdiction = db.Column(db.String(50))                   # 管轄
    main_number = db.Column(db.String(50))                    # 基幹番号
    branch_number = db.Column(db.String(50))                  # 枝番号
    free_input = db.Column(db.Text)                           # 自由入力
    postal_code = db.Column(db.String(20))                    # 郵便番号
    address_prefecture = db.Column(db.String(100))            # 所在地（都道府県）
    address_city = db.Column(db.String(100))                  # 所在地（市区町村）
    address_town = db.Column(db.String(100))                  # 所在地（町域）（任意）
    address_details = db.Column(db.String(200))               # 所在地（詳細）（任意）
    phone_number = db.Column(db.String(20))                   # 電話番号
    fax_number = db.Column(db.String(20))                     # FAX番号（任意）

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.before_first_request
def create_tables():
    db.create_all()

# トップページ
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

        # 管理者としてログインする場合のチェック
        if uname == 'honjobunseki' and pw == '78387838':
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

        # 通常ユーザのログイン
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

# 管理画面から新規ユーザを追加
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

# ユーザごとのページ
@app.route('/user/<username>')
@login_required
def user_page(username):
    user = User.query.filter_by(username=username).first()
    if not user:
        return "ユーザが見つかりません", 404
    if user.username != current_user.username and not current_user.is_admin:
        return "他のユーザのページにはアクセスできません", 403
    # ユーザの施行パートナー一覧を取得
    partners = Partner.query.filter_by(user_id=user.id).all()
    return render_template('user_page.html', user=user, partners=partners)

# 施行パートナー登録フォーム（各ユーザ専用ページからアクセス）
@app.route('/user/<username>/partners/add', methods=['GET', 'POST'])
@login_required
def add_partner(username):
    user = User.query.filter_by(username=username).first()
    if not user:
        return "ユーザが見つかりません", 404
    if user.username != current_user.username and not current_user.is_admin:
        return "他のユーザのページにはアクセスできません", 403

    error = None
    if request.method == 'POST':
        # 入力されたフォームデータを取得
        company_name = request.form.get('company_name')
        representative = request.form.get('representative')
        labor_insurance_number = request.form.get('labor_insurance_number')
        prefecture_code = request.form.get('prefecture_code')
        responsibility = request.form.get('responsibility')
        jurisdiction = request.form.get('jurisdiction')
        main_number = request.form.get('main_number')
        branch_number = request.form.get('branch_number')
        free_input = request.form.get('free_input')
        postal_code = request.form.get('postal_code')
        address_prefecture = request.form.get('address_prefecture')
        address_city = request.form.get('address_city')
        address_town = request.form.get('address_town')
        address_details = request.form.get('address_details')
        phone_number = request.form.get('phone_number')
        # チェックボックス "fax_same" の値を確認（"on"なら電話番号と同じ）
        fax_same = request.form.get('fax_same')
        fax_number = request.form.get('fax_number') if not fax_same else phone_number

        new_partner = Partner(
            user_id=user.id,
            company_name=company_name,
            representative=representative,
            labor_insurance_number=labor_insurance_number,
            prefecture_code=prefecture_code,
            responsibility=responsibility,
            jurisdiction=jurisdiction,
            main_number=main_number,
            branch_number=branch_number,
            free_input=free_input,
            postal_code=postal_code,
            address_prefecture=address_prefecture,
            address_city=address_city,
            address_town=address_town,
            address_details=address_details,
            phone_number=phone_number,
            fax_number=fax_number
        )
        db.session.add(new_partner)
        db.session.commit()
        flash("施行パートナー（下請け・協力業者）の登録が完了しました", "success")
        return redirect(url_for('user_page', username=username))
    return render_template('add_partner.html', user=user, error=error)

if __name__ == '__main__':
    app.run(debug=True)
