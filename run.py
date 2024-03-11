from flask import Flask, render_template, request, redirect, flash, url_for, session, abort
from sqlalchemy import desc
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, current_user, logout_user, login_required
from flask_bcrypt import Bcrypt, check_password_hash
from datetime import datetime
from werkzeug.utils import secure_filename
from urllib.parse import urlparse, unquote
from flask_login import UserMixin
from flask_mail import Mail
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from itsdangerous import URLSafeTimedSerializer, SignatureExpired
import os
import pytz
import uuid
import smtplib
import base64

app = Flask(__name__)

app.config["MAIL_SERVER"] = "smtp.googlemail.com"
app.config["MAIL_PORT"] = 465
app.config["MAIL_USERNAME"] = "edonfejzullai69@gmail.com"
app.config["MAIL_PASSWORD"] = "yzga rxuu rbkc imoa"
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True
app.config['JSON_AS_ASCII'] = False

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///project.db"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

app.config['SECRET_KEY'] = 'secretkey'

app.config['UPLOAD_FOLDER'] = 'static'

mail = Mail(app)

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

s = URLSafeTimedSerializer('Mysecretkey')

login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'
login_manager.init_app(app)

def get_current_time_utc_plus_1():
    tz = pytz.timezone('Europe/Paris')
    return datetime.now(tz).replace(microsecond=0)

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.Text, unique=True, nullable=False)
    email = db.Column(db.Text, unique=True, nullable=False)
    password = db.Column(db.Text, nullable=False)
    admin = db.Column(db.Boolean, default=False)
    verified = db.Column(db.Boolean, default=False)
    city = db.Column(db.Text, nullable=True)
    address = db.Column(db.Text, nullable=True)
    zip = db.Column(db.Integer, nullable=True)
    phone = db.Column(db.Text, nullable=True)

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.Text, nullable=False)
    price = db.Column(db.Integer, nullable=False)
    image = db.Column(db.Text, nullable=False)
    category_id = db.Column(db.Integer, nullable=False)
    supplier_id = db.Column(db.Integer, nullable=False)

class Category(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.Text, nullable=False)

class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, nullable=False)
    order_name = db.Column(db.Text, nullable=False)
    order_quantity = db.Column(db.Integer, nullable=False, default=1)
    order_client = db.Column(db.Text, nullable=False)
    order_price = db.Column(db.Integer, nullable=False)
    order_date = db.Column(db.DateTime, nullable=False, default=get_current_time_utc_plus_1())
    order_finish_date = db.Column(db.DateTime, nullable=True)
    order_status = db.Column(db.Text, nullable=False, default="Processing")
    order_method = db.Column(db.Text, nullable=False)
    order_userid = db.Column(db.Integer, nullable=False)

class Suppliers(db.Model):
    supplier_id = db.Column(db.Integer, primary_key=True)
    supplier_name = db.Column(db.Text, nullable=False)
    supplier_phone = db.Column(db.Text, nullable=True)
    supplier_address = db.Column(db.Text, nullable=True)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def url_has_allowed_host_and_scheme(url, allowed_hosts, require_https=False):
    if url is None or not url.strip():
        return False

    if allowed_hosts is None:
        allowed_hosts = set()
    elif isinstance(allowed_hosts, str):
        allowed_hosts = {allowed_hosts}

    # Parse the given URL
    parsed_url = urlparse(url)
    url_host = parsed_url.hostname
    url_scheme = parsed_url.scheme

    # Check if the URL host and scheme match the allowed hosts and scheme
    return (
        url_host in allowed_hosts and
        (not require_https or url_scheme == 'https') and
        url_scheme in ['http', 'https']
    )

@app.route('/')
def home():
    page = request.args.get('page', 1, type=int)
    per_page = 3
    products = Product.query.order_by(desc(Product.id)).paginate(page=page, per_page=per_page)
    categories = Category.query.all()

    return render_template('index.html', products=products, categories=categories, cart_items=get_cart_count())

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))

    error = None

    if request.method == 'POST':
        form_password = request.form['password']
        form_email = request.form['email']
        form_username = request.form['username']

        if form_username and form_password and form_email:
            if User.query.filter_by(username=form_username).first():
                error = 'Username already taken'
            
            elif User.query.filter_by(email=form_email).first():
                error = 'Email already taken'
            
            else:
                bcrypt_password = bcrypt.generate_password_hash(form_password)

                token = s.dumps(form_email, salt='email-confirm')
                link = url_for('confirm_email', token=token, _external=True)

                with open('static/spartan_logo.png', 'rb') as f:
                    logo_data = f.read()

                logo_base64 = base64.b64encode(logo_data).decode('utf-8')

                msg_title = 'Spartan Shop, account verification'
                msg_sender = "edonfejzullai69@gmail.com"
                    
                with app.app_context():
                    msg_body = render_template('verify_email.html', link=link, logo_base64=logo_base64)
                    send_email(msg_title, msg_sender, form_email, msg_body.encode('utf-8'))

                register = User(username=form_username, email=form_email, password=bcrypt_password, verified=False)
                db.session.add(register)
                db.session.commit()

                error = 'Successfully registered, activate your account by clicking the link sent to your e-mail'
                flash(error, 'success')

                return redirect(url_for('home'))

        else:
            error = 'Fill out the form'
        flash(error, 'danger')
    return render_template('register.html')

@app.route('/request_token', methods=['GET', 'POST'])
def request_token():
    if current_user.is_authenticated:
        return redirect(url_for('home'))

    if request.method == 'POST':
        form_email = request.form['email']

        token = s.dumps(form_email, salt='email-confirm')
        link = url_for('confirm_email', token=token, _external=True)

        with open('static/spartan_logo.png', 'rb') as f:
            logo_data = f.read()

            logo_base64 = base64.b64encode(logo_data).decode('utf-8')

            msg_title = 'Spartan Shop, account verification'
            msg_sender = "edonfejzullai69@gmail.com"
                    
        with app.app_context():
            msg_body = render_template('verify_email.html', link=link, logo_base64=logo_base64)
            send_email(msg_title, msg_sender, form_email, msg_body.encode('utf-8'))

        error = 'A new token has been sent to your e-mail. Click it to verify your account'
        flash(error, 'warning')

        return redirect(url_for('home'))

    return render_template("token_request.html")

@app.route('/confirm_email/<token>')
def confirm_email(token):
    if current_user.is_authenticated:
        return redirect(url_for('home'))

    try:
        email = s.loads(token, salt='email-confirm', max_age=86400)
        user = User.query.filter_by(email=email).first()

        if user.verified == True:
            return redirect(url_for('login'))
        
        else:
            user.verified = True
            db.session.commit()
    except:
        return render_template('token_expired.html')
    return render_template('token_verified.html')
    
@app.route('/login', methods=['GET', 'POST'])
def login():
    logout_user()
    session.clear()

    error = None

    if current_user.is_authenticated:
        return redirect(url_for('home'))

    next_page_encoded = request.args.get('next')

    if request.method == 'POST':
        password = request.form['password']
        username = request.form['username']

        user = User.query.filter_by(username=username).first()
        if user:
            if check_password_hash(user.password, password):
                if user.verified:
                    login_user(user)

                    next_page_encoded = request.form.get('next')

                    if next_page_encoded != 'None':
                        next_page = unquote(next_page_encoded)

                        allowed_hosts = {'127.0.0.1'}

                        check_url = 'https://127.0.0.1' + next_page
                        if not url_has_allowed_host_and_scheme(check_url, allowed_hosts, require_https=False):
                             return abort(400)
                        return redirect(next_page)
                    else:
                        return redirect(url_for('home'))
                else:
                    error = "Your account isn't verified, a verification link was sent to your e-mail!"
            else:
                error = 'Incorrect password'
        else:
            error = "Username doesn't exist"

        flash(error, 'danger')
    return render_template('login.html')

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    
    if request.method == 'POST':
        email = request.form['email']

        user = User.query.filter_by(email=email).first()

        if not user:
            flash('E-mail not found, make sure you enter an existing email.', 'danger')
            return render_template('forgot_password.html')

        else:
            token = s.dumps(email, salt='email-confirm')
            link = url_for('password_reset', token=token, _external=True)

            with open('static/spartan_logo.png', 'rb') as f:
                    logo_data = f.read()

            logo_base64 = base64.b64encode(logo_data).decode('utf-8')

            msg_title = 'Spartan Shop, requested password change'
            msg_sender = "edonfejzullai69@gmail.com"
                
            with app.app_context():
                msg_body = render_template('reset_password_email.html', link=link, logo_base64=logo_base64)
                send_email(msg_title, msg_sender, user.email, msg_body.encode('utf-8'))  # Encode the email body as UTF-8
            
            flash('An e-mail with instructions to reset your password has been sent, check your inbox', 'success')
            return redirect(url_for('home'))
        
    return render_template('forgot_password.html')

@app.route('/password_reset/<token>', methods=['GET', 'POST'])
def password_reset(token):
    if current_user.is_authenticated:
        return redirect(url_for('home'))

    try:
        email_token = s.loads(token, salt='email-confirm', max_age=300)
        user = User.query.filter_by(email=email_token).first()

        if request.method == 'POST':
            form_password = request.form['password']

            user.password = bcrypt.generate_password_hash(form_password)
            db.session.commit()
            flash('Your password has been successfully reset, login using your new password', 'success')
            return redirect(url_for('login'))

        else:
            return render_template('password_reset.html', token=token)

    except:
        return render_template('token_expired.html')

@app.route("/logout")
@login_required
def logout():
    logout_user()
    session.clear()
    return redirect(url_for('home'))

def is_current_user_admin():
    return current_user.admin

@app.route('/add_user', methods=['POST'])
@login_required
def add_user():
    if not is_current_user_admin():
        flash('You have to be an admin to access this site', 'warning')
        return redirect(url_for('home'))

    error = ""

    username = request.form['username']
    email = request.form['email']
    password = request.form['password']
    admin = request.form['admin']

    if User.query.filter_by(username=username).first():
        error = 'Username already taken'
        flash(error, 'danger')
            
    elif User.query.filter_by(email=email).first():
        error = 'Email already taken'
        flash(error, 'danger')

        
    if error == "":
        register = User(username=username, email=email, password=bcrypt.generate_password_hash(password), admin=True if admin=='yes' else False)
        db.session.add(register)
        db.session.commit()

        flash('Successfully created new user','success')

    return redirect(url_for('admin_users'))

@app.route('/delete_product/<int:product_id>')
@login_required
def delete_product(product_id):
    if not is_current_user_admin():
        flash('You have to be an admin to access this site', 'warning')
        return redirect(url_for('home'))

    product = Product.query.filter_by(id=product_id).first()

    if product:
        remove_from_cart(product_id)
        db.session.delete(product)
        db.session.commit()

    return redirect(url_for('admin'))

@app.route('/add_product', methods=['POST'])
@login_required
def add_product():
    if not is_current_user_admin():
        flash('You have to be an admin to access this site', 'warning')
        return redirect(url_for('home'))

    name = request.form['product_name']
    price = request.form['product_price']
    category_name = request.form['product_category']
    supplier_name = request.form['product_supplier']
    image = request.files['product_image']

    category = Category.query.filter_by(name=category_name).first()
    supplier = Suppliers.query.filter_by(supplier_name=supplier_name).first()

    if not category:
        flash('Category does not exist', 'error')
        return redirect(url_for('admin'))
    
    if not supplier:
        flash('Supplier does not exist', 'error')
        return redirect(url_for('admin'))

    # Save the uploaded file directly to the UPLOAD_FOLDER
    filename = secure_filename(image.filename)
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    image.save(file_path)
    image.close()

    new_product = Product(name=name, price=price, image=filename, category_id=category.id, supplier_id=supplier.supplier_id)
    db.session.add(new_product)
    db.session.commit()

    return redirect(url_for('admin'))

def save_uploaded_file(file, new_filename):
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], new_filename)
    file.save(file_path)
    return file_path

@app.route('/update_product/<int:product_id>', methods=['POST'])
@login_required
def update_product(product_id):
    if not is_current_user_admin():
        flash('You have to be an admin to access this site', 'warning')
        return redirect(url_for('home'))

    product = Product.query.get(product_id)
    if not product:
        flash('Product does not exist', 'error')
        return redirect(url_for('admin'))

    name = request.form['product_name']
    price = request.form['product_price']
    category_name = request.form['product_category']
    supplier_name = request.form['product_supplier']
    image = request.files['product_image']

    if name:
        product.name = name

    if price:
        product.price = price

    if category_name:
        category = Category.query.filter_by(name=category_name).first()
        if category:
            product.category_id = category.id

    if supplier_name:
        supplier = Suppliers.query.filter_by(supplier_name=supplier_name).first()
        if supplier:
            product.supplier_id = supplier.supplier_id

    if image:
        image_filename = secure_filename(image.filename)
        # Generate a new unique filename for the image
        new_image_filename = str(uuid.uuid4()) + "_" + image_filename
        save_uploaded_file(image, new_image_filename)

        # Update the product with the new image filename
        product.image = new_image_filename

    db.session.commit()

    return redirect(url_for('admin'))

def get_next_order_id():
    max_order_id = db.session.query(db.func.max(Order.order_id)).scalar()
    if max_order_id is None:
        return 1
    else:
        return max_order_id + 1

@app.route('/empty_cart')
@login_required
def empty_cart():
    session.pop('cart')
    return redirect(url_for('view_cart'))

@app.route('/fillout', methods=['GET', 'POST'])
@login_required
def fillout():
    error = ""

    cart = session.get('cart', [])

    if not cart:
        error = "Cart is empty"
        flash(error, 'warning')
        return redirect(url_for('home'))

    if request.method == 'POST':
        name = request.form['cardName']
        number = request.form['cardNumber']
        cvv = request.form['cardCvv']
        method = request.form['cardMethod']
        
        city = request.form['city']
        address = request.form['address']
        zip_code = request.form['zip_code']
        phone_number = request.form['phone_number']

        if not name.replace(' ', '').isalpha():
            error = "The name musn't include any digits"

        if not number.replace(' ', '').isdigit():
            error = "The credit card numbers mustn't contain any letters"

        if not len(number) == 19:
            error = "The credit card must have 16 digits"
        
        if not cvv.isdigit():
            error = "The CVV number mustn't contain any letters"

        if not len(cvv) == 3:
            error = "The CVV number must have 3 digits"

        if error:
            flash(error, 'danger')
            return redirect(url_for('fillout'))

        current_user.city = city
        current_user.address = address
        current_user.zip = zip_code
        current_user.phone = phone_number

        userid = current_user.id
        next_order_id = get_next_order_id()

        for item in cart:
            newOrder = Order(order_id=next_order_id,order_name=item["name"], order_quantity=item["quantity"],order_client=current_user.username, order_price=item["price"], order_method=method, order_userid=userid)
            db.session.add(newOrder)
        db.session.commit()
        
        flash('Order successfully completed', 'success')
        session.pop('cart', None)

        return redirect(url_for('home'))

    return render_template('fillout.html', cart=cart, user=current_user)

@app.route('/my_orders')
@login_required
def my_orders():
    if not current_user.is_authenticated:
        flash('You have to be logged in', 'warning')
        return redirect(url_for('home'))

    page = request.args.get('page', 1, type=int)
    per_page = 3
    orders = Order.query.filter_by(order_userid=current_user.id).order_by(desc(Order.id)).paginate(page=page, per_page=per_page)

    return render_template('my_orders.html', orders=orders)

@app.route('/my_orders_search', methods=['GET', 'POST'])
@login_required
def my_orders_search():
    if not current_user.is_authenticated:
        flash('You have to be logged in', 'warning')
        return redirect(url_for('home'))

    page = request.args.get('page', 1, type=int)
    per_page = 3

    orders_all = Order.query.filter_by(order_userid=current_user.id).order_by(desc(Order.id)).paginate(page=page, per_page=per_page)

    if request.method == 'POST':
        action = request.form.get('action')

        if action == 'search':
            search_query = request.form.get('q')

            filtered_orders = Order.query.filter_by(order_userid=current_user.id).filter(Order.order_name.like(f'%{search_query}%')).order_by(desc(Order.id)).paginate(page=page, per_page=per_page)

            return render_template('my_orders.html', orders=filtered_orders)
        
        elif action == 'reset':
            return redirect(url_for('my_orders_search'))

    return render_template('my_orders.html', orders=orders_all)

@app.route('/orders')
@login_required
def orders():
    if not is_current_user_admin():
        flash('You have to be an admin to access this site', 'warning')
        return redirect(url_for('home'))

    page = request.args.get('page', 1, type=int)
    per_page = 3
    orders = Order.query.order_by(desc(Order.id)).paginate(page=page, per_page=per_page)

    return render_template('orders.html', orders=orders)

@app.route('/orders_search', methods=['GET', 'POST'])
@login_required
def orders_search():
    if not is_current_user_admin():
        flash('You have to be an admin to access this site', 'warning')
        return redirect(url_for('home'))

    page = request.args.get('page', 1, type=int)
    per_page = 3

    orders_all = Order.query.order_by(desc(Order.id)).paginate(page=page, per_page=per_page)

    if request.method == 'POST':
        action = request.form.get('action')

        if action == 'search':
            search_query = request.form.get('q')

            # Filter orders by search query
            filtered_orders = Order.query.filter(Order.order_name.like(f'%{search_query}%')).order_by(desc(Order.id)).paginate(page=page, per_page=per_page)

            return render_template('orders.html', orders=filtered_orders)
        
        elif action == 'reset':
            return redirect(url_for('orders_search'))

    return render_template('orders.html', orders=orders_all)
        
@app.route('/orders_search_by_client', methods=['GET', 'POST'])
@login_required
def orders_search_by_client():
    if not is_current_user_admin():
        flash('You have to be an admin to access this site', 'warning')
        return redirect(url_for('home'))

    page = request.args.get('page', 1, type=int)
    per_page = 3

    all_orders = Order.query.order_by(desc(Order.id)).paginate(page=page, per_page=per_page)

    if request.method == 'POST':
        client_id = request.form.get('client_id')

        # Filter orders by client_id
        client_orders = Order.query.filter_by(order_userid=client_id).order_by(desc(Order.id)).paginate(page=page, per_page=per_page)

        return render_template('orders.html', orders=client_orders)
    
    return render_template('orders.html', orders=all_orders)

def send_email(subject, sender, recipient, body):
    msg = MIMEMultipart()
    msg['From'] = sender
    msg['To'] = recipient
    msg['Subject'] = subject

    msg.attach(MIMEText(body, 'html', 'utf-8'))  # Specify UTF-8 encoding for the body

    # SMTP settings
    server = smtplib.SMTP('smtp.googlemail.com', 587)
    server.starttls()
    server.login(sender, 'yzga rxuu rbkc imoa')

    server.sendmail(sender, recipient, msg.as_string())
    server.quit()


@app.route('/update_order_status', methods=['POST', 'GET'])
@login_required
def update_order_status():
    if not is_current_user_admin():
        flash('You have to be an admin to access this site', 'warning')
        return redirect(url_for('home'))
    
    if request.method == 'POST':
        new_status = request.form['status']
        id = request.form['id']

        current_order = Order.query.filter_by(order_id=id).first()
        user = User.query.filter_by(id=current_order.order_userid).first()

        orders = Order.query.filter_by(order_id=id).all()

        if new_status != 'Delete':
            if current_order.order_status != 'Finished':

                with open('static/spartan_logo.png', 'rb') as f:
                    logo_data = f.read()

                logo_base64 = base64.b64encode(logo_data).decode('utf-8')

                if len(orders) > 1:
                    for order in orders:
                        order.order_status = new_status

                    if new_status == 'Finished':
                        for order in orders:
                            order.order_finish_date = get_current_time_utc_plus_1()

                else:
                    current_order.order_status = new_status

                    if new_status == 'Finished':
                        current_order.order_finish_date = get_current_time_utc_plus_1()

                client = User.query.filter_by(id=current_order.order_userid).first()

                msg_title = 'Spartan Shop, order status has changed'
                msg_sender = "edonfejzullai69@gmail.com"
                
                with app.app_context():
                    msg_body = render_template('status_email.html', orders=orders, status=new_status, username=client.username, logo_base64=logo_base64)
                    send_email(msg_title, msg_sender, user.email, msg_body.encode('utf-8'))  # Encode the email body as UTF-8

        else:
            for order in orders:
                db.session.delete(order)
            db.session.commit()
            
        db.session.commit()

    return redirect(url_for('orders'))

@app.route('/update_user/<int:user_id>', methods=['POST'])
@login_required
def update_user(user_id):
    if not is_current_user_admin():
        flash('You have to be an admin to access this site', 'warning')
        return redirect(url_for('home'))

    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        admin = request.form['admin']

        user = User.query.filter_by(id=user_id).first()

        changes = False
        if username:
            user.username = username
            changes = True

        if email:
            user.email = email
            changes = True

        if password:
            user.password = bcrypt.generate_password_hash(password)
            changes = True

        if admin:
            changes = True
            if admin == 'yes':
                user.admin = True
            else:
                user.admin = False

        if changes:
            db.session.commit()

        return redirect(url_for('admin_users'))

@app.route('/delete_user/<int:user_id>')
@login_required
def delete_user(user_id):
    if not is_current_user_admin():
        flash('You have to be an admin to access this site', 'warning')
        return redirect(url_for('home'))

    user = User.query.filter_by(id=user_id).first()

    if user:
        db.session.delete(user)
        db.session.commit()

    return redirect(url_for('admin_users'))

@app.route('/account', methods=['GET', 'POST'])
@login_required
def account():
    if request.method == 'POST':
        password = request.form['password']
        username = request.form['username']
        email = request.form['email']

        if username:
            query = User.query.filter_by(username=username).first()
            if query and query.id != current_user.id:
                flash('Username already taken', 'danger')
                return redirect(url_for('account'))
            
        if email:
            query = User.query.filter_by(email=email).first()
            if query and query.id != current_user.id:
                flash('Email already taken', 'danger')
                return redirect(url_for('account'))
        
        current_user.username = username if username else current_user.username
        current_user.email = email if email else current_user.email
        current_user.password = password if password else current_user.password
        db.session.commit()
        flash('You successfully updated your info', 'success')

        return redirect(url_for('home'))
        
    return render_template('account.html')

@app.route('/add_to_cart/<int:product_id>')
@login_required
def add_to_cart(product_id):
    product = Product.query.get(product_id)
    
    if product:
        cart = session.get('cart', [])

        # Check if the product is already in the cart
        product_in_cart = next((item for item in cart if item['id'] == product.id), None)

        # If the product is not in the cart, add it
        if product_in_cart:
            for item in cart:
                if item['id'] == product.id:
                    if 'quantity' in item:
                        quantity = item['quantity'] + 1
                        item['quantity'] = quantity
                    else:
                        item['quantity'] = 1
        else:
            cart.append({'id': product.id, 'name': product.name, 'price': int(product.price), 'image': product.image, 'quantity': 1})

        session['cart'] = cart
        flash('Product added to the cart', 'success')

    return redirect(url_for('home'))

@app.route('/quantity_up/<int:product_id>')
@login_required
def quantity_up(product_id):
    cart = session.get('cart', [])

    for item in cart:
        if item['id'] == product_id:
            # Check if 'quantity' key exists
            if 'quantity' in item:
                item['quantity'] = item['quantity'] + 1
    session['cart'] = cart
    return redirect(url_for('view_cart'))

@app.route('/quantity_down/<int:product_id>')
@login_required
def quantity_down(product_id):
    cart = session.get('cart', [])
    for item in cart:
        if item['id'] == product_id:
            # Check if 'quantity' key exists and use max function to prevent negative values
            if 'quantity' in item:
                item['quantity'] = max(1, item['quantity'] - 1)
    session['cart'] = cart

    return redirect(url_for('view_cart'))

def get_cart_count():
    cart = session.get('cart', [])

    if cart:
        return len(cart)
    else:
        return 0

@app.route('/cart')
@login_required
def view_cart():
    cart = session.get('cart', [])
    return render_template('cart.html', cart=cart)

@app.route('/remove_from_cart/<int:product_id>')
@login_required
def remove_from_cart(product_id):
    cart = session.get('cart', [])

    for item in cart:  # Iterate over cart, not session
        if item['id'] == product_id:  # Use product_id instead of hardcoding 1
            cart.remove(item)
            break

    session['cart'] = cart  # Update the 'cart' key in the session with the modified cart

    return redirect(url_for('view_cart'))

# admin products search filter
@app.route('/admin_product_search', methods=['GET', 'POST'])
@login_required
def admin_product_search():
    if not is_current_user_admin():
        flash('You have to be an admin to access this site', 'warning')
        return redirect(url_for('home'))

    if request.method == 'POST':
        search_query = request.form.get('q')

        # Filter products by search query
        products = Product.query.filter(Product.name.like(f'%{search_query}%')).all()

        # store all products for later to render
        products_all = []

        # loop through all products found
        for product in products:
            # add each product to the main object
            products_all.append(product)

        categories = Category.query.all()
        suppliers = Suppliers.query.all()

        return render_template('admin_index.html', products=products_all, categories=categories, suppliers=suppliers)

@app.route('/admin_user_search', methods=['GET', 'POST'])
@login_required
def admin_user_search():
    if not is_current_user_admin():  
        flash('You have to be an admin to access this site', 'warning')
        return redirect(url_for('home'))

    if request.method == 'POST':
        search_query = request.form.get('q')

        # Filter users by search query
        users = User.query.filter(User.username.like(f'%{search_query}%')).all()

        # store all users for later to render
        users_all = []

        # loop through all users found
        for user in users:
            # add each user to the main object
            users_all.append(user)

        # Render the template with users
        return render_template('admin_users.html', users=users_all)

@app.route('/admin_supplier_search', methods=['POST'])
@login_required
def admin_supplier_search():
    if not is_current_user_admin():  
        flash('You have to be an admin to access this site', 'warning')
        return redirect(url_for('home'))

    if request.method == 'POST':
        search_query = request.form.get('q')

        suppliers = Suppliers.query.filter(Suppliers.supplier_name.like(f'%{search_query}%')).all()

        suppliers_all = []

        for supplier in suppliers:
            suppliers_all.append(supplier)

        products = Product.query.all()
 
        return render_template('admin_suppliers.html', products=products, suppliers=suppliers_all)

@app.route('/admin_category_search', methods=['POST'])
@login_required
def admin_category_search():
    if not is_current_user_admin():  
        flash('You have to be an admin to access this site', 'warning')
        return redirect(url_for('home'))

    if request.method == 'POST':
        search_query = request.form.get('q')

        # Filter categories by search query
        categories = Category.query.filter(Category.name.like(f'%{search_query}%')).all()

        # store all categories for later to render
        categories_all = []

        # loop through all categories found
        for category in categories:
            # add each category to the main object
            categories_all.append(category)

        products = Product.query.all()

        # Render the template with categories 
        return render_template('admin_categories.html', products=products, categories=categories_all)

# original admin panel index with all products
@app.route('/admin', methods=['GET', 'POST'])
@login_required
def admin():
    user = User.query.filter_by(username=current_user.username).first()
    if user.admin == False:
        flash('You have to be an admin to access this site', 'warning')
        return redirect(url_for('home'))
    
    products = Product.query.all()
    categories = Category.query.all()
    suppliers = Suppliers.query.all()
    return render_template('admin_index.html', products=products, categories=categories, suppliers=suppliers)

@app.route('/admin_users', methods=['GET', 'POST'])
@login_required
def admin_users():
    user = User.query.filter_by(username=current_user.username).first()
    if user.admin == False:
        flash('You have to be an admin to access this site', 'warning')
        return redirect(url_for('home'))

    users = User.query.all()
    return render_template('admin_users.html', users=users)

@app.route('/admin_categories', methods=['GET', 'POST'])
@login_required
def admin_categories():
    user = User.query.filter_by(username=current_user.username).first()
    if user.admin == False:
        flash('You have to be an admin to access this site', 'warning')
        return redirect(url_for('home'))

    categories = Category.query.all()
    products = Product.query.all()
    return render_template('admin_categories.html', products=products, categories=categories)

@app.route('/admin_suppliers', methods=['GET', 'POST'])
@login_required
def admin_suppliers():
    user = User.query.filter_by(username=current_user.username).first()
    if user.admin == False:
        flash('You have to be an admin to access this site', 'warning')
        return redirect(url_for('home'))

    suppliers = Suppliers.query.all()
    products = Product.query.all()
    return render_template('admin_suppliers.html', products=products, suppliers=suppliers)

@app.route('/update_supplier/<int:supplier_id>', methods=['POST'])
@login_required
def update_supplier(supplier_id):
    if not is_current_user_admin():
        flash('You have to be an admin to access this site', 'warning')
        return redirect(url_for('home'))

    if request.method == 'POST':
        supplier_name = request.form['supplier_name']
        supplier_phone = request.form['supplier_phone']
        supplier_address = request.form['supplier_address']

        supplier = Suppliers.query.filter_by(supplier_id=supplier_id).first()

        changes = False
        if supplier_name:
            supplier.supplier_name = supplier_name
            changes = True

        if supplier_address:
            supplier.supplier_address = supplier_address
            changes = True

        if supplier_phone:
            supplier.supplier_phone = supplier_phone
            changes = True    

        if changes:
            db.session.commit()

        return redirect(url_for('admin_suppliers'))

@app.route('/add_supplier', methods=['POST'])
@login_required
def add_supplier():
    if not is_current_user_admin():
        flash('You have to be an admin to access this site', 'warning')
        return redirect(url_for('home'))

    supplier_name = request.form['supplier_name']
    supplier_phone = request.form['supplier_phone']
    supplier_address = request.form['supplier_address']

    new_supplier = Suppliers(supplier_name=supplier_name, supplier_phone=supplier_phone, supplier_address=supplier_address)
    db.session.add(new_supplier)
    db.session.commit()

    return redirect(url_for('admin_suppliers'))

@app.route('/delete_supplier/<int:supplier_id>')
@login_required
def delete_supplier(supplier_id):
    supplier = Suppliers.query.filter_by(supplier_id=supplier_id).first()

    if supplier:
        db.session.delete(supplier)
        db.session.commit()

    return redirect(url_for('admin_categories'))


@app.route('/update_category/<int:category_id>', methods=['POST'])
@login_required
def update_category(category_id):
    if not is_current_user_admin():
        flash('You have to be an admin to access this site', 'warning')
        return redirect(url_for('home'))

    if request.method == 'POST':
        category_name = request.form['category_name']

        category = Category.query.filter_by(id=category_id).first()

        changes = False
        if category_name:
            category.name = category_name
            changes = True

        if changes:
            db.session.commit()

        return redirect(url_for('admin_categories'))

@app.route('/add_category', methods=['POST'])
@login_required
def add_category():
    if not is_current_user_admin():
        flash('You have to be an admin to access this site', 'warning')
        return redirect(url_for('home'))

    category_name = request.form['category_name']

    new_category = Category(name=category_name)
    db.session.add(new_category)
    db.session.commit()

    return redirect(url_for('admin_categories'))

@app.route('/delete_category/<int:category_id>')
@login_required
def delete_category(category_id):
    category = Category.query.filter_by(id=category_id).first()

    if category:
        db.session.delete(category)
        db.session.commit()

    return redirect(url_for('admin_categories'))

with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True)