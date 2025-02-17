import os
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
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', '2x9K#mP9$vL5nX3j@pQ7wR8cY4hN6bM1zD')

# PostgreSQL接続情報（Render環境の環境変数を使用）
db_host = os.environ.get('DB_HOST', 'dpg-cuisfvin91rc73bmn8pg-a.oregon-postgres.render.com')
db_name = os.environ.get('DB_NAME', 'jizen')
db_port = os.environ.get('DB_PORT', '5432')
db_user = os.environ.get('DB_USER', 'jizen_user')
db_password = os.environ.get('DB_PASSWORD', 'vX33zfbVI5AhvxitGnWUOC9SM5K8eoWW')

app.config['SQLALCHEMY_DATABASE_URI'] = f"postgresql://{db_user}:{db_password}@{db_host}:{db_port}/{db_name}"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

########################
#       モデル定義
########################

class User(UserMixin, db.Model):
    __tablename__ = 'users'  # テーブル名を 'users' にして予約語を避ける
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(256), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    partners = db.relationship('Partner', backref='owner', lazy=True)
    staffs = db.relationship('Staff', backref='owner', lazy=True)

class Partner(db.Model):
    __tablename__ = 'partners'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    company_name = db.Column(db.String(200), nullable=False)
    representative = db.Column(db.String(200))
    phone_number = db.Column(db.String(20))
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
    is_handover = db.Column(db.Boolean, default=False)
    is_registration = db.Column(db.Boolean, default=False)
    is_transport = db.Column(db.Boolean, default=False)
    is_asbestos_qualified = db.Column(db.Boolean, default=False)
    is_construction = db.Column(db.Boolean, default=False)
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
    # ★開発環境でのみ既存テーブルを削除してから作成する
    db.drop_all()
    db.create_all()

########################
#       ルート定義
########################

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        uname = request.form.get('username', '').strip()
        pw = request.form.get('password', '').strip()
        # 管理者ログイン
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
    logout_user()
    flash("ログアウトしました", "info")
    return redirect(url_for('index'))

#################################
#       管理画面 (admin.html)
#################################
@app.route('/admin')
@login_required
def admin():
    if not current_user.is_admin:
        return "権限がありません", 403
    all_users = User.query.all()
    return render_template('admin.html', users=all_users)

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

@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
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

#################################
#       ユーザページ (user_page)
#################################
@app.route('/user/<username>')
@login_required
def user_page(username):
    print("user_page: requested username =", username)
    user = User.query.filter_by(username=username).first()
    if not user:
        return "ユーザが見つかりません", 404
    if not current_user.is_admin and user.username != current_user.username:
        return "他のユーザのページにはアクセスできません", 403
    partners = Partner.query.filter_by(user_id=user.id).all()
    staffs = Staff.query.filter_by(user_id=user.id).all()
    return render_template('user_page.html', user=user, partners=partners, staffs=staffs)

#################################
#       施行パートナー登録 (add_partner)
#################################
@app.route('/user/<username>/partner/add', methods=['GET', 'POST'])
@login_required
def add_partner(username):
    user = User.query.filter_by(username=username).first()
    if not user:
        return "ユーザが見つかりません", 404
    if not current_user.is_admin and user.username != current_user.username:
        return "他のユーザのページにはアクセスできません", 403
    if request.method == 'POST':
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
        fax_same = request.form.get('fax_same')
        if fax_same == 'on':
            fax_number = phone_number

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
        flash("施行パートナーの登録が完了しました", "success")
        return redirect(url_for('user_page', username=user.username))
    return render_template('add_partner.html', user=user)

#################################
#       担当者登録 (add_staff)
#################################
@app.route('/user/<username>/staff/add', methods=['GET', 'POST'])
@login_required
def add_staff(username):
    user = User.query.filter_by(username=username).first()
    if not user:
        return "ユーザが見つかりません", 404
    if not current_user.is_admin and user.username != current_user.username:
        return "他のユーザのページにはアクセスできません", 403
    if request.method == 'POST':
        staff_name = request.form.get('staff_name', '')
        is_handover = True if request.form.get('is_handover') == 'on' else False
        is_registration = True if request.form.get('is_registration') == 'on' else False
        is_transport = True if request.form.get('is_transport') == 'on' else False
        is_asbestos_qualified = True if request.form.get('is_asbestos_qualified') == 'on' else False
        is_construction = True if request.form.get('is_construction') == 'on' else False

        is_asbestos_chief = True if request.form.get('is_asbestos_chief') == 'on' else False
        asbestos_chief_reg_number = request.form.get('asbestos_chief_reg_number', '')
        asbestos_chief_training_org = request.form.get('asbestos_chief_training_org', '')

        is_building_inspector = True if request.form.get('is_building_inspector') == 'on' else False
        building_inspector_reg_number = request.form.get('building_inspector_reg_number', '')
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
    partners = Partner.query.filter_by(user_id=user.id).all()
    return render_template('add_staff.html', user=user, partners=partners)

if __name__ == '__main__':
    app.run(debug=True)
