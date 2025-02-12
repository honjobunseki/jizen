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
app.config['SECRET_KEY'] = '2x9K#mP9$vL5nX3j@pQ7wR8cY4hN6bM1zD'
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://jizen_user:vX33zfbVI5AhvxitGnWUOC9SM5K8eoWW@dpg-cuisfvin91rc73bmn8pg-a.oregon-postgres.render.com/jizen'
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
    # 施行パートナー情報
    partners = db.relationship('Partner', backref='owner', lazy=True)
    # 担当者情報（Staff）のリレーション
    staffs = db.relationship('Staff', backref='owner', lazy=True)

# 施行パートナーモデル
class Partner(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    company_name = db.Column(db.String(200), nullable=False)
    representative = db.Column(db.String(200))
    phone_number = db.Column(db.String(20))

# 担当者（スタッフ）モデル
class Staff(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    vendor_type = db.Column(db.String(50))
    partner_id = db.Column(db.Integer, db.ForeignKey('partner.id'), nullable=True)
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
    db.create_all()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        uname = request.form.get('username', '').strip()
        pw = request.form.get('password', '').strip()
        
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
        
        user = User.query.filter_by(username=uname).first()
        if user and check_password_hash(user.password, pw):
            login_user(user)
            flash("ログインしました", "success")
            return redirect(url_for('index'))
        else:
            error = "ユーザ名またはパスワードが間違っています。"
    return render_template('login.html', error=error)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("ログアウトしました", "info")
    return redirect(url_for('index'))

@app.route('/admin')
@login_required
def admin():
    # デバッグ情報を収集
    debug_info = {
        "リクエスト情報": {
            "現在のユーザーID": current_user.id if current_user.is_authenticated else None,
            "現在のユーザー名": current_user.username if current_user.is_authenticated else None,
            "管理者権限": current_user.is_admin if current_user.is_authenticated else None
        }
    }
    
    if not current_user.is_admin:
        debug_info["エラー"] = "管理者権限がありません"
        return render_template('error.html', debug_info=debug_info), 403
    
    try:
        users = User.query.all()
        debug_info["取得データ"] = {
            "ユーザー数": len(users) if users else 0
        }
        return render_template('admin.html', users=users, debug_info=debug_info)
    except Exception as e:
        debug_info["エラー"] = str(e)
        return render_template('error.html', debug_info=debug_info), 500

@app.route('/user/<username>')
@login_required
def user_page(username):
    # デバッグ情報を画面に表示するための辞書
    debug_info = {
        "リクエスト情報": {
            "アクセス要求されたユーザー名": username,
            "現在のユーザーID": current_user.id,
            "現在のユーザー名": current_user.username,
            "管理者権限": current_user.is_admin
        }
    }
    
    user = User.query.filter_by(username=username).first()
    if not user:
        debug_info["エラー"] = f"ユーザー {username} がデータベースに見つかりません"
        return render_template('error.html', debug_info=debug_info), 404
    
    debug_info["データベース情報"] = {
        "見つかったユーザーID": user.id,
        "見つかったユーザー名": user.username
    }
    
    if not current_user.is_admin and user.username != current_user.username:
        debug_info["エラー"] = "アクセス権限がありません"
        return render_template('error.html', debug_info=debug_info), 403
    
    try:
        partners = Partner.query.filter_by(user_id=user.id).all()
        staffs = Staff.query.filter_by(user_id=user.id).all()
        
        debug_info["取得データ"] = {
            "パートナー数": len(partners),
            "スタッフ数": len(staffs)
        }
        
        return render_template('user_page.html', 
                             user=user, 
                             partners=partners, 
                             staffs=staffs, 
                             debug_info=debug_info)
    except Exception as e:
        debug_info["エラー"] = str(e)
        return render_template('error.html', debug_info=debug_info), 500

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

@app.route('/user/<username>/partner/add', methods=['GET', 'POST'])
@login_required
def add_partner(username):
    user = User.query.filter_by(username=username).first()
    if not user:
        return "ユーザが見つかりません", 404
    if not current_user.is_admin and user.username != current_user.username:
        return "他のユーザのページにはアクセスできません", 403
    
    if request.method == 'POST':
        company_name = request.form.get('company_name')
        representative = request.form.get('representative')
        phone_number = request.form.get('phone_number')
        
        new_partner = Partner(
            user_id=user.id,
            company_name=company_name,
            representative=representative,
            phone_number=phone_number
        )
        db.session.add(new_partner)
        db.session.commit()
        flash("施行パートナーが登録されました", "success")
        return redirect(url_for('user_page', username=username))
    
    return render_template('add_partner.html', user=user)

@app.route('/user/<username>/staff/add', methods=['GET', 'POST'])
@login_required
def add_staff(username):
    user = User.query.filter_by(username=username).first()
    if not user:
        return "ユーザが見つかりません", 404
    if not current_user.is_admin and user.username != current_user.username:
        return "他のユーザのページにはアクセスできません", 403
    
    if request.method == 'POST':
        vendor_type = request.form.get('vendor_type')
        partner_id = request.form.get('partner_id') or None
        staff_name = request.form.get('staff_name')
        is_handover = True if request.form.get('is_handover') == 'on' else False
        is_registration = True if request.form.get('is_registration') == 'on' else False
        is_transport = True if request.form.get('is_transport') == 'on' else False
        is_asbestos_qualified = True if request.form.get('is_asbestos_qualified') == 'on' else False
        is_construction = True if request.form.get('is_construction') == 'on' else False

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
    
    partners = Partner.query.filter_by(user_id=user.id).all()
    return render_template('add_staff.html', user=user, partners=partners)

if __name__ == '__main__':
    app.run(debug=True)
