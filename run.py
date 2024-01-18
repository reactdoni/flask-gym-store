from flask import Flask, render_template, request, redirect, flash, url_for, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, current_user, logout_user, login_required
from werkzeug.utils import secure_filename
import os
import secrets

app = Flask(__name__)

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///project.db"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'secretkey'

db = SQLAlchemy(app)

login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(15), nullable=False)
    admin = db.Column(db.Boolean, default=False)

    def is_authenticated(self):
        return True

    def is_active(self):
        return True
    
    def get_id(self):
        return str(self.id)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.Text, nullable=False)
    price = db.Column(db.Integer, nullable=False)
    image = db.Column(db.String(20), nullable=False)

@app.route('/')
def home():
    products = Product.query.all()
    return render_template('index.html', products=products, cart_items=update_cart())

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        form_password = request.form['password']
        form_email = request.form['email']
        form_username = request.form['username']

        if form_username and form_password and form_email:
            if User.query.filter_by(username=form_username).first():
                return 'Username already taken'
            
            elif User.query.filter_by(email=form_email).first():
                return 'Email already taken'
            
            register = User(username=form_username, email=form_email, password=form_password)
            db.session.add(register)
            db.session.commit()

            return redirect(url_for('home'))

        else:
            return 'Fill out the form'
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))

    if request.method == 'POST':
        password = request.form['password']
        username = request.form['username']

        user = User.query.filter_by(username=username).first()
        if user:
            if password == user.password:
                login_user(user)
                return redirect(url_for('home'))
            else:
                return 'Incorrect password!'
        else:
            return 'Username not found'
    return render_template('login.html')

@app.route("/logout")
@login_required
def logout():
    logout_user()
    session.clear()
    return redirect(url_for('home'))

@app.route('/add_product', methods=['POST'])
@login_required
def add_product():
    name = request.form['product_name']
    price = request.form['product_price']
    image = request.form['product_image']

    if not name or not price:
        return 'Enter name and price'
    
    if not isinstance(int(price), int):
        return 'Price has to be an integer'
    
    new_product = Product(name=name, price=price, image=image)
    db.session.add(new_product)
    db.session.commit()

    return redirect(url_for('admin'))

@app.route('/add_user', methods=['POST'])
@login_required
def add_user():
    username = request.form['username']
    email = request.form['email']
    password = request.form['password']
    admin = request.form['admin']

    if User.query.filter_by(username=username).first():
        return 'Username already taken'
            
    elif User.query.filter_by(email=email).first():
        return 'Email already taken'
    
    register = User(username=username, email=email, password=password, admin=True if admin=='yes' else False)
    db.session.add(register)
    db.session.commit()
    
    return redirect(url_for('admin_users'))

@app.route('/delete_product/<int:product_id>')
@login_required
def delete_product(product_id):
    product = Product.query.filter_by(id=product_id).first()

    if product:
        remove_from_cart(product_id)
        db.session.delete(product)
        db.session.commit()

    return redirect(url_for('admin'))

def save_picture(form_picture):
     random_hex = secrets.token_hex(8)
     _, f_ext = os.path.splitext(form_picture.filename)
     picture_fn = random_hex + f_ext
     picture_path = os.path.join(app.root_path, 'static/', picture_fn)
     form_picture.save(picture_path)

     return picture_fn

@app.route('/update_product/<int:product_id>', methods=['POST'])
@login_required
def update_product(product_id):
    if request.method == 'POST':
        name = request.form['product_name']
        price = request.form['product_price']
        
        img = ""

        # Check if the file is included in the request
        if 'product_image' in request.files:
            image = request.files['product_image']
            img = save_picture(image)

        product = Product.query.filter_by(id=product_id).first()

        changes = False
        if name:
            product.name = name
            changes = True

        if price:
            product.price = price
            changes = True

        if image:
            product.image = img
            changes = True

        if changes:
            db.session.commit()

        return redirect(url_for('admin'))
    
@app.route('/update_user/<int:user_id>', methods=['POST'])
@login_required
def update_user(user_id):
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['password']
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
            user.password = password
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
            user_query = User.query.filter_by(username=username).first()
            if user_query:
                return 'Username is already in use, pick another one'
            
        if email:
            email_query = User.query.filter_by(email=email).first()
            if email_query:
                return 'Email is already in use, pick another one'
        
        current_user.username = username if username else current_user.username
        current_user.email = email if email else current_user.email
        current_user.password = password if password else current_user.password
        db.session.commit()
        flash('You were successfully logged in', 'success')

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

        if product_in_cart:
            # If the product is already in the cart, you may want to update its quantity or handle it as needed
            flash('Product is already in the cart', 'warning')
        else:
            # If the product is not in the cart, add it
            cart.append({'id': product.id, 'name': product.name, 'price': int(product.price), 'image': product.image})
            session['cart'] = cart
            update_cart()
            flash('Product added to the cart', 'success')

    return redirect(url_for('home'))

def update_cart():
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
def remove_from_cart(product_id):
    cart = session.get('cart', [])

    for item in cart:  # Iterate over cart, not session
        if item['id'] == product_id:  # Use product_id instead of hardcoding 1
            cart.remove(item)
            break

    session['cart'] = cart  # Update the 'cart' key in the session with the modified cart

    return redirect(url_for('view_cart'))

@app.route('/admin', methods=['GET', 'POST'])
@login_required
def admin():
    user = User.query.filter_by(username=current_user.username).first()
    if user.admin == False:
        return 'You have to be an admin to access this site'
    
    products = Product.query.all()
    return render_template('admin_index.html', products=products)

@app.route('/admin_users', methods=['GET', 'POST'])
@login_required
def admin_users():
    user = User.query.filter_by(username=current_user.username).first()
    if user.admin == False:
        return 'You have to be an admin to access this site'

    users = User.query.all()
    return render_template('admin_users.html', users=users)

if __name__ == '__main__':
    app.run(debug=True)