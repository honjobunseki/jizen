from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, login_user, logout_user, login_required,
    current_user, UserMixin
)
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'  # 本番では適切な秘密鍵に設定
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///mydb.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# 既存のユーザモデル
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(256), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    # ユーザに関連する施行パートナー情報（既存の機能）
    partners = db.relationship('Partner', backref='owner', lazy=True)
    # 新たに担当者情報（Staff）のリレーションを追加
    staffs = db.relationship('Staff', backref='owner', lazy=True)

# 既存の施行パートナーモデル（例）
class Partner(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    company_name = db.Column(db.String(200), nullable=False)
    representative = db.Column(db.String(200))
    phone_number = db.Column(db.String(20))
    # 他の項目は省略
    # 担当者登録時に、業者として選択できるように利用

# 新たに担当者（スタッフ）モデルを追加
class Staff(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    # 業者種別：例えば '元請業者' または '施行パートナー'
    vendor_type = db.Column(db.String(50))
    # 施行パートナーの場合、どのパートナーか（Partner テーブルの id）
    partner_id = db.Column(db.Integer, db.ForeignKey('partner.id'), nullable=True)
    staff_name = db.Column(db.String(200), nullable=False)
    # 担当者種別（各項目のフラグ）
    is_handover = db.Column(db.Boolean, default=False)
    is_registration = db.Column(db.Boolean, default=False)
    is_transport = db.Column(db.Boolean, default=False)
    is_asbestos_qualified = db.Column(db.Boolean, default=False)
    is_construction = db.Column(db.Boolean, default=False)
    # 石綿有資格者種別　– 以下、各資格に対応する項目
    is_asbestos_chief = db.Column(db.Boolean, default=False)
    asbestos_chief_reg_number = db.Column(db.String(100))
    asbestos_chief_training_org = db.Column(db.String(200))
    
    is_building_inspector = db.Column(db.Boolean, default=False)
    building_inspector_reg_number = db.Column(db.String(100))
    # 複数チェックの場合、ここでは簡単に1つのフィールドにまとめる例
    building_inspector_qualification = db.Column(db.String(100))
    building_inspector_training_org = db.Column(db.String(200))
    
    is_preliminary_inspector = db.Column(db.Boolean, default=False)
    preliminary_inspector_reg_number = db.Column(db.String(100))
    preliminary_inspector_training_org = db.Column(db.String(200))
    
    email = db.Column(db.String(200))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.before_first_request
def create_tables():
    db.create_all()

# 既存のルート群（トップページ、ログイン、ログアウト、管理画面、ユーザ登録等）は省略（先ほどのコードを参照）

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        uname = request.form.get('username')
        pw = request.form.get('password')
        # 管理者としてログイン
        if uname == 'honjobunseki' and pw == '78387838':
            admin = User.query.filter_by(username='honjobunseki').first()
            if not admin:
                admin = User(username='honjobunseki',
                             password=generate_password_hash('78387838'),
                             is_admin=True)
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

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

# 管理画面（管理者のみ）
@app.route('/admin')
@login_required
def admin():
    if not current_user.is_admin:
        return "権限がありません", 403
    users = User.query.all()
    return render_template('admin.html', users=users)

# ユーザごとのページ（既存）
@app.route('/user/<username>')
@login_required
def user_page(username):
    user = User.query.filter_by(username=username).first()
    if not user:
        return "ユーザが見つかりません", 404
    if user.username != current_user.username and not current_user.is_admin:
        return "他のユーザのページにはアクセスできません", 403
    # 既存の施行パートナー一覧（partners）と新たに担当者一覧（staffs）も取得
    partners = Partner.query.filter_by(user_id=user.id).all()
    staffs = Staff.query.filter_by(user_id=user.id).all()
    return render_template('user_page.html', user=user, partners=partners, staffs=staffs)

# 施行パートナー登録は既存のものとします（省略）

# 担当者（スタッフ）登録フォーム
@app.route('/user/<username>/staff/add', methods=['GET', 'POST'])
@login_required
def add_staff(username):
    user = User.query.filter_by(username=username).first()
    if not user:
        return "ユーザが見つかりません", 404
    # 自分のページか管理者のみ登録可能
    if user.username != current_user.username and not current_user.is_admin:
        return "他のユーザのページにはアクセスできません", 403
    
    if request.method == 'POST':
        # 基本情報
        vendor_type = request.form.get('vendor_type')  # 例: "元請業者" または "施行パートナー"
        # もし vendor_type が「施行パートナー」なら、partner_id (業者のID) を取得（プルダウンで選択）
        partner_id = request.form.get('partner_id')  or None
        staff_name = request.form.get('staff_name')
        # 担当者種別チェックボックス
        is_handover = True if request.form.get('is_handover') == 'on' else False
        is_registration = True if request.form.get('is_registration') == 'on' else False
        is_transport = True if request.form.get('is_transport') == 'on' else False
        is_asbestos_qualified = True if request.form.get('is_asbestos_qualified') == 'on' else False
        is_construction = True if request.form.get('is_construction') == 'on' else False
        
        # 石綿有資格者種別チェック
        is_asbestos_chief = True if request.form.get('is_asbestos_chief') == 'on' else False
        asbestos_chief_reg_number = request.form.get('asbestos_chief_reg_number')
        asbestos_chief_training_org = request.form.get('asbestos_chief_training_org')
        
        is_building_inspector = True if request.form.get('is_building_inspector') == 'on' else False
        building_inspector_reg_number = request.form.get('building_inspector_reg_number')
        building_inspector_qualification = request.form.get('building_inspector_qualification')
        building_inspector_training_org = request.form.get('building_inspector_training_org')
        
        is_preliminary_inspector = True if request.form.get('is_preliminary_inspector') == 'on' else False
        preliminary_inspector_reg_number = request.form.get('preliminary_inspector_reg_number')
        preliminary_inspector_training_org = request.form.get('preliminary_inspector_training_org')
        
        email = request.form.get('email')
        
        new_staff = Staff(
            user_id=user.id,
            vendor_type=vendor_type,
            partner_id=partner_id,
            staff_name=staff_name,
            is_handover=is_handover,
            is_registration=is_registration,
            is_transport=is_transport,
            is_asbestos_qualified=is_asbestos_qualified,
            is_construction=is_construction,
            is_asbestos_chief=is_asbestos_chief,
            asbestos_chief_reg_number=asbestos_chief_reg_number,
            asbestos_chief_training_org=asbestos_chief_training_org,
            is_building_inspector=is_building_inspector,
            building_inspector_reg_number=building_inspector_reg_number,
            building_inspector_qualification=building_inspector_qualification,
            building_inspector_training_org=building_inspector_training_org,
            is_preliminary_inspector=is_preliminary_inspector,
            preliminary_inspector_reg_number=preliminary_inspector_reg_number,
            preliminary_inspector_training_org=preliminary_inspector_training_org,
            email=email
        )
        db.session.add(new_staff)
        db.session.commit()
        flash("担当者が登録されました", "success")
        return redirect(url_for('user_page', username=username))
    
    # 登録画面へ渡すために、施行パートナー一覧（Partner）も取得（業者選択用プルダウン）
    partners = Partner.query.filter_by(user_id=user.id).all()
    return render_template('add_staff.html', user=user, partners=partners)

if __name__ == '__main__':
    app.run(debug=True)
