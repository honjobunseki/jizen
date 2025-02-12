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
    partners = db.relationship('Partner', backref='owner', lazy=True)
    staffs = db.relationship('Staff', backref='owner', lazy=True)

# 施行パートナーモデル
class Partner(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    company_name = db.Column(db.String(200), nullable=False)
    representative = db.Column(db.String(200))
    phone_number = db.Column(db.String(20))

# 担当者モデル
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
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        
        # 管理者ログイン
        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
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
            return redirect(url_for('admin'))
        
        # 一般ユーザーログイン
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('user_page', username=username))
        
        flash('ユーザー名またはパスワードが間違っています', 'error')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('ログアウトしました', 'info')
    return redirect(url_for('index'))

@app.route('/admin')
@login_required
def admin():
    if not current_user.is_admin:
        flash('管理者権限が必要です', 'error')
        return redirect(url_for('index'))
    users = User.query.all()
    return render_template('admin.html', users=users)

@app.route('/user/<username>')
@login_required
def user_page(username):
    user = User.query.filter_by(username=username).first()
    if not user:
        flash('ユーザーが見つかりません', 'error')
        return redirect(url_for('index'))
    
    if not current_user.is_admin and current_user.username != username:
        flash('アクセス権限がありません', 'error')
        return redirect(url_for('index'))
    
    partners = Partner.query.filter_by(user_id=user.id).all()
    staffs = Staff.query.filter_by(user_id=user.id).all()
    return render_template('user_page.html', user=user, partners=partners, staffs=staffs)

@app.route('/admin/add_user', methods=['GET', 'POST'])
@login_required
def add_user():
    if not current_user.is_admin:
        flash('管理者権限が必要です', 'error')
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        
        if User.query.filter_by(username=username).first():
            flash('そのユーザー名は既に使用されています', 'error')
        else:
            new_user = User(
                username=username,
                password=generate_password_hash(password),
                is_admin=False
            )
            db.session.add(new_user)
            db.session.commit()
            flash('ユーザーを追加しました', 'success')
            return redirect(url_for('admin'))
    
    return render_template('add_user.html')

@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    if not current_user.is_admin:
        flash('管理者権限が必要です', 'error')
        return redirect(url_for('index'))
    
    user = User.query.get(user_id)
    if not user:
        flash('ユーザーが見つかりません', 'error')
    elif user.username == ADMIN_USERNAME:
        flash('管理者ユーザーは削除できません', 'error')
    else:
        db.session.delete(user)
        db.session.commit()
        flash('ユーザーを削除しました', 'success')
    
    return redirect(url_for('admin'))

@app.route('/user/<username>/partner/add', methods=['GET', 'POST'])
@login_required
def add_partner(username):
    user = User.query.filter_by(username=username).first()
    if not user:
        flash('ユーザーが見つかりません', 'error')
        return redirect(url_for('index'))
    
    if not current_user.is_admin and current_user.username != username:
        flash('アクセス権限がありません', 'error')
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        new_partner = Partner(
            user_id=user.id,
            company_name=request.form.get('company_name'),
            representative=request.form.get('representative'),
            phone_number=request.form.get('phone_number')
        )
        db.session.add(new_partner)
        db.session.commit()
        flash('施行パートナーを登録しました', 'success')
        return redirect(url_for('user_page', username=username))
    
    return render_template('add_partner.html', user=user)

@app.route('/user/<username>/staff/add', methods=['GET', 'POST'])
@login_required
def add_staff(username):
    user = User.query.filter_by(username=username).first()
    if not user:
        flash('ユーザーが見つかりません', 'error')
        return redirect(url_for('index'))
    
    if not current_user.is_admin and current_user.username != username:
        flash('アクセス権限がありません', 'error')
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        new_staff = Staff(
            user_id=user.id,
            vendor_type=request.form.get('vendor_type'),
            partner_id=request.form.get('partner_id'),
            staff_name=request.form.get('staff_name'),
            is_handover=request.form.get('is_handover') == 'on',
            is_registration=request.form.get('is_registration') == 'on',
            is_transport=request.form.get('is_transport') == 'on',
            is_asbestos_qualified=request.form.get('is_asbestos_qualified') == 'on',
            is_construction=request.form.get('is_construction') == 'on',
            is_asbestos_chief=request.form.get('is_asbestos_chief') == 'on',
            asbestos_chief_reg_number=request.form.get('asbestos_chief_reg_number'),
            asbestos_chief_training_org=request.form.get('asbestos_chief_training_org'),
            is_building_inspector=request.form.get('is_building_inspector') == 'on',
            building_inspector_reg_number=request.form.get('building_inspector_reg_number'),
            building_inspector_qualification=request.form.get('building_inspector_qualification'),
            building_inspector_training_org=request.form.get('building_inspector_training_org'),
            is_preliminary_inspector=request.form.get('is_preliminary_inspector') == 'on',
            preliminary_inspector_reg_number=request.form.get('preliminary_inspector_reg_number'),
            preliminary_inspector_training_org=request.form.get('preliminary_inspector_training_org'),
            email=request.form.get('email')
        )
        db.session.add(new_staff)
        db.session.commit()
        flash('担当者を登録しました', 'success')
        return redirect(url_for('user_page', username=username))
    
    partners = Partner.query.filter_by(user_id=user.id).all()
    return render_template('add_staff.html', user=user, partners=partners)

if __name__ == '__main__':
    app.run(debug=True)
