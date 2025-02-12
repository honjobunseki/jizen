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

# 環境変数または直接PostgreSQLへの接続設定
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


##################
#    モデル定義   #
##################
class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(256), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

    # 施行パートナー、担当者とのリレーション
    partners = db.relationship('Partner', backref='owner', lazy=True)
    staffs = db.relationship('Staff', backref='owner', lazy=True)

class Partner(db.Model):
    __tablename__ = 'partners'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    company_name = db.Column(db.String(200), nullable=False)
    representative = db.Column(db.String(200))  # 代表者
    phone_number = db.Column(db.String(20))     # 必要に応じてその他の項目を追加

    # 任意の追加項目
    labor_insurance_number = db.Column(db.String(100))
    prefecture_code = db.Column(db.String(50))
    responsibility = db.Column(db.String(50))
    jurisdiction = db.Column(db.String(50))
    main_number = db.Column(db.String(50))
    branch_number = db.Column(db.String(50))
    free_input = db.Column(db.Text)
    postal_code = db.Column(db.String(20))
    address_prefecture = db.Column(db.String(100))
    address_city = db.Column(db.String(100))
    address_town = db.Column(db.String(100))
    address_details = db.Column(db.String(200))
    fax_number = db.Column(db.String(20))

class Staff(db.Model):
    __tablename__ = 'staffs'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    staff_name = db.Column(db.String(200), nullable=False)

    # 担当者種別フラグ
    is_handover = db.Column(db.Boolean, default=False)
    is_registration = db.Column(db.Boolean, default=False)
    is_transport = db.Column(db.Boolean, default=False)
    is_asbestos_qualified = db.Column(db.Boolean, default=False)
    is_construction = db.Column(db.Boolean, default=False)

    # 石綿有資格者種別（簡略例）
    is_asbestos_chief = db.Column(db.Boolean, default=False)
    asbestos_chief_reg_number = db.Column(db.String(100))
    asbestos_chief_training_org = db.Column(db.String(200))

    is_building_inspector = db.Column(db.Boolean, default=False)
    building_inspector_reg_number = db.Column(db.String(100))
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

##############################
#  ログイン/ログアウトなど   #
##############################
@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        uname = request.form.get('username', '').strip()
        pw = request.form.get('password', '').strip()

        if uname == ADMIN_USERNAME and pw == ADMIN_PASSWORD:
            # 管理者ログイン
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
        else:
            # 一般ユーザ
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

##########################
#    管理画面 (例)      #
##########################
@app.route('/admin')
@login_required
def admin():
    if not current_user.is_admin:
        return "権限がありません", 403
    return render_template('admin.html')

##########################
#   ユーザページの表示   #
##########################
@app.route('/user/<username>')
@login_required
def user_page(username):
    user = User.query.filter_by(username=username).first()
    if not user:
        return "ユーザが見つかりません", 404
    if not current_user.is_admin and user.username != current_user.username:
        return "他のユーザのページにはアクセスできません", 403

    # 施行パートナー一覧
    partners = Partner.query.filter_by(user_id=user.id).all()
    # 担当者一覧
    staffs = Staff.query.filter_by(user_id=user.id).all()
    return render_template('user_page.html', user=user, partners=partners, staffs=staffs)

#########################
# 施行パートナー登録処理 #
#########################
@app.route('/user/<username>/partner/add', methods=['GET', 'POST'])
@login_required
def add_partner(username):
    user = User.query.filter_by(username=username).first()
    if not user:
        return "ユーザが見つかりません", 404
    if not current_user.is_admin and user.username != current_user.username:
        return "他のユーザのページにはアクセスできません", 403

    error = None
    if request.method == 'POST':
        # フォームから受け取るデータ
        company_name = request.form.get('company_name', '').strip()
        representative = request.form.get('representative', '')
        labor_insurance_number = request.form.get('labor_insurance_number', '')
        prefecture_code = request.form.get('prefecture_code', '')
        responsibility = request.form.get('responsibility', '')
        jurisdiction = request.form.get('jurisdiction', '')
        main_number = request.form.get('main_number', '')
        branch_number = request.form.get('branch_number', '')
        free_input = request.form.get('free_input', '')
        postal_code = request.form.get('postal_code', '')
        address_prefecture = request.form.get('address_prefecture', '')
        address_city = request.form.get('address_city', '')
        address_town = request.form.get('address_town', '')
        address_details = request.form.get('address_details', '')
        phone_number = request.form.get('phone_number', '')
        fax_number = request.form.get('fax_number', '')
        fax_same = request.form.get('fax_same')  # チェックボックス "on" or None
        if fax_same == 'on':
            fax_number = phone_number  # 電話番号と同じ

        new_partner = Partner(
            user_id=user.id,
            company_name=company_name,
            representative=representative,
            phone_number=phone_number,
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
            fax_number=fax_number
        )
        db.session.add(new_partner)
        db.session.commit()
        flash("施行パートナー（下請け・協力業者）の登録が完了しました", "success")
        return redirect(url_for('user_page', username=user.username))

    return render_template('add_partner.html', user=user)

######################
#  担当者登録処理     #
######################
@app.route('/user/<username>/staff/add', methods=['GET', 'POST'])
@login_required
def add_staff(username):
    user = User.query.filter_by(username=username).first()
    if not user:
        return "ユーザが見つかりません", 404
    if not current_user.is_admin and user.username != current_user.username:
        return "他のユーザのページにはアクセスできません", 403

    if request.method == 'POST':
        vendor_type = request.form.get('vendor_type', '')
        partner_id = request.form.get('partner_id', '')
        staff_name = request.form.get('staff_name', '')
        is_handover = True if request.form.get('is_handover') == 'on' else False
        is_registration = True if request.form.get('is_registration') == 'on' else False
        is_transport = True if request.form.get('is_transport') == 'on' else False
        is_asbestos_qualified = True if request.form.get('is_asbestos_qualified') == 'on' else False
        is_construction = True if request.form.get('is_construction') == 'on' else False

        # 石綿関連チェック
        is_asbestos_chief = True if request.form.get('is_asbestos_chief') == 'on' else False
        asbestos_chief_reg_number = request.form.get('asbestos_chief_reg_number', '')
        asbestos_chief_training_org = request.form.get('asbestos_chief_training_org', '')

        is_building_inspector = True if request.form.get('is_building_inspector') == 'on' else False
        building_inspector_reg_number = request.form.get('building_inspector_reg_number', '')
        # ここでは複数チェックボックスの簡易例として一つのフィールドにまとめる例を省略
        building_inspector_training_org = request.form.get('building_inspector_training_org', '')

        is_preliminary_inspector = True if request.form.get('is_preliminary_inspector') == 'on' else False
        preliminary_inspector_reg_number = request.form.get('preliminary_inspector_reg_number', '')
        preliminary_inspector_training_org = request.form.get('preliminary_inspector_training_org', '')

        email = request.form.get('email', '')

        new_staff = Staff(
            user_id=user.id,
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
            # building_inspector_qualification=...  (省略例)
            building_inspector_training_org=building_inspector_training_org,
            is_preliminary_inspector=is_preliminary_inspector,
            preliminary_inspector_reg_number=preliminary_inspector_reg_number,
            preliminary_inspector_training_org=preliminary_inspector_training_org,
            email=email
        )
        db.session.add(new_staff)
        db.session.commit()
        flash("担当者が登録されました", "success")
        return redirect(url_for('user_page', username=user.username))

    # 施行パートナー一覧をプルダウンに表示する場合などに利用
    partners = Partner.query.filter_by(user_id=user.id).all()
    return render_template('add_staff.html', user=user, partners=partners)

if __name__ == '__main__':
    app.run(debug=True)
