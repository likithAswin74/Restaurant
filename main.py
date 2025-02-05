from flask import Flask, render_template, redirect, url_for, flash, abort, session, request
from flask_bootstrap import Bootstrap5
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user
# the current_user acts as a object for the particular user of the user table who has logged in .
# with the current_user we can able to access the attributes of the user table of the current user who is logged in.
from forms import RegisterForm, LoginForm, ForgotPasswordForm, VerifyOtpForm, NewPasswordForm, ContactForm, ConfirmForm
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship, DeclarativeBase, Mapped, mapped_column
from sqlalchemy import Integer, String, Text, Float
from functools import wraps
import random
import time
import smtplib
import os
# used to remove the spaces in the parameters from the route
from urllib.parse import unquote

# enables a admin interface like django to add the contents in the database
from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView

from werkzeug.security import generate_password_hash, check_password_hash


CART_ITEMS_COUNT = 0


def admin_only(function):
    @wraps(function)
    def decorated_function(*args, **kwargs):
        # Check if the user is authenticated
        if not current_user.is_authenticated:
            return abort(403)  # Return Forbidden if the user is not authenticated
        # If id is not 1 then return abort with 403 error
        if current_user.id != 1:
            return abort(403)
        # Otherwise continue with the route function
        return function(*args, **kwargs)
    return decorated_function


app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get("RESTAURANT_FLASK_SECRETKEY")
Bootstrap5(app)

#os.environ.get("RESTAURANT_FLASK_SECRETKEY")
# TODO: Configure Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)


# every time it is called when request is made
# Create a user_loader callback
@login_manager.user_loader
def load_user(user_id):
    return db.get_or_404(Users, user_id)
    # it checks the user id in the session and that userid is present in the database.
# For every subsequent request, Flask-Login calls the user_loader function to load the user object associated with the user_id stored in the session.
# The load_user function retrieves the User from the database based on the stored user_id. This allows you to access the current user in the request using current_user.


# CREATE DATABASE
class Base(DeclarativeBase):
    pass


# configuring and initilizing the database
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("RESTAURANT_DB_URI")
db = SQLAlchemy(model_class=Base)
db.init_app(app)
admin = Admin(app, name='MyRestaurant', template_mode='bootstrap3')  # admin obj for admin panel with name MyRestaurant


# TODO: Create a User table for all your registered users.
# CONFIGURE TABLES
class Users(UserMixin, db.Model):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(100), unique=True)
    password: Mapped[str] = mapped_column(String(100))
    name: Mapped[str] = mapped_column(String(100))

    #     # ***************parent Relationship *************#
    #     # refers to the instance of the Cart class
    #     # List["items 1", "items 2"] one user can have a list of items in cart.
    cart_items = db.relationship('Cart', back_populates='cart_user')


# database for Non-veg
class Items(db.Model):
    __tablename__ = "items"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[int] = mapped_column(String(100), nullable=False)
    price: Mapped[int] = mapped_column(Float)
    category: Mapped[int] = mapped_column(String(50), nullable=False)  # Category of the item (e.g., 'Biriyani')
    image_url: Mapped[int] = mapped_column(String(255))


class Veg(db.Model):
    __tablename__ = "Veg"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[int] = mapped_column(String(100), nullable=False)
    price: Mapped[int] = mapped_column(Float)
    category: Mapped[int] = mapped_column(String(50), nullable=False)  # Category of the item (e.g., 'Biriyani')
    image_url: Mapped[int] = mapped_column(String(255))


class DessertJuice(db.Model):
    __tablename__ = "Dessert&Juice"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[int] = mapped_column(String(100), nullable=False)
    price: Mapped[int] = mapped_column(Float)
    category: Mapped[int] = mapped_column(String(50), nullable=False)  # Category of the item (e.g., 'Biriyani')
    image_url: Mapped[int] = mapped_column(String(255))


class ChipsSnacks(db.Model):
    __tablename__ = "Chips&Snacks"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[int] = mapped_column(String(100), nullable=False)
    price: Mapped[int] = mapped_column(Float)
    category: Mapped[int] = mapped_column(String(50), nullable=False)  # Category of the item (e.g., 'Biriyani')
    image_url: Mapped[int] = mapped_column(String(255))


class Cart(db.Model):
    __tablename__ = "Cart"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[int] = mapped_column(String(100), nullable=False)
    price: Mapped[int] = mapped_column(Float)
    image_url: Mapped[int] = mapped_column(String(255))

    # *************** Relationship with User Class *************#
    user_id: Mapped[int] = mapped_column(Integer, db.ForeignKey("users.id"))
    # cart_user refers to the instance of the users class we can use this to access the attributes of the users class eg.author.email
    cart_user = db.relationship('Users', back_populates='cart_items')


class OTP(db.Model):
    __tablename__ = "OTP"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_email: Mapped[int] = mapped_column(String(100), nullable=False)
    otp: Mapped[int] = mapped_column(String(20), nullable=False)
    timestamp: Mapped[int] = mapped_column(Float, nullable=False)


# creating the tables in the database
with app.app_context():
    db.create_all()


# allows only the admin to access the /admin route
class AdminModelView(ModelView):
    @admin_only
    def is_accessible(self):
        return current_user.is_authenticated and current_user.id == 1
    # this function returns true if the current_user is authenticated and current_user id is 1 else it returns false
    # if it is true then it shows the admin panel with the database eg: MyRestaurant Home Items.
    # if it is false then it shows the admin panel without the database. MyRestaurant Home.


# This creates a new administrative interface for the User model. The first parameter, User, is the model you want to manage. The second parameter, db.session, is the SQLAlchemy session used for database transactions.
# ModelView creates an interface in the /admin panel to manage (view, add, edit, delete) your database models.
admin.add_view(AdminModelView(Items, db.session))  # this calls the functions inside the class AdminModelView
admin.add_view(AdminModelView(Veg, db.session))
admin.add_view(AdminModelView(DessertJuice, db.session))
admin.add_view(AdminModelView(ChipsSnacks, db.session))


@app.route("/register", methods=['POST', 'GET'])
def register():
    register_form = RegisterForm()
    if register_form.validate_on_submit():
        # checking that the email is already exists. if it is then we need to send the flash message and redirect page to login
        email = register_form.email.data

        # Find user by email entered.
        email_in_database = db.session.execute(db.select(Users).where(Users.email == email)).scalar()

        if email_in_database:
            # user already exists
            flash("You've already signed up with that email, log in instead!")
            return redirect(url_for('login'))  # flash message is sent along with this router.

        # hashing and salting the password entered by the user
        hashed_password = generate_password_hash(password=register_form.password.data,
                                                 method="pbkdf2:sha256",
                                                 salt_length=8)
        # entering the new user to the database
        new_user = Users(
            email=register_form.email.data,
            password=hashed_password,
            name=register_form.name.data
        )
        db.session.add(new_user)
        db.session.commit()

        # Log in and authenticate user after adding details to database.
        login_user(new_user)  # Logs in a user by saving their ID in the session.

        return redirect(url_for("home"))

    # passing true or false if the user is authenticated
    return render_template("register.html", form=register_form, logged_in=current_user.is_authenticated)


@app.route("/login", methods=['POST', 'GET'])
def login():
    login_form = LoginForm()
    if login_form.validate_on_submit():
        email = login_form.email.data
        password = login_form.password.data

        # finds the user by email entered
        user = db.session.execute(db.select(Users).where(Users.email == email)).scalar()

        # if the user is not present then send a flash message with that route
        if not user:
            flash("That mail does not exist. please try again!")
            return redirect(url_for("login"))

            # Check stored password hash against entered password hashed. if it is not same then send a flash message
        elif not check_password_hash(user.password, password):
            flash("Password incorrect please try again!")
            return redirect(url_for("login"))

            # if the email and password are entered correctly
        else:
            login_user(user)  # Logs in a user by saving their ID in the session.
            return redirect(url_for('home'))

    return render_template("login.html", form=login_form, logged_in=current_user.is_authenticated)


@app.route('/logout')
def logout():
    global CART_ITEMS_COUNT
    CART_ITEMS_COUNT = 0
    logout_user()  # logout the user by removing the user id from the session
    return redirect(url_for('home'))


@app.route("/")
def home():
    global CART_ITEMS_COUNT
    # if the user is authenticated then take all the cart items count belongs to user.and it is shown on the nav bar
    if current_user.is_authenticated:
        cart_items = current_user.cart_items
        CART_ITEMS_COUNT = len(cart_items)
    return render_template("index.html", cart_items_count=CART_ITEMS_COUNT, logged_in=current_user.is_authenticated)


@app.route('/foods/<name>')
def foods(name):
    global CART_ITEMS_COUNT

    # only allows the user when he is logged in.
    if not current_user.is_authenticated:
        flash("First Log in and try again!")
        return redirect(url_for("login"))

    # if the user is authenticated then take all the cart items count belongs to user.and it is shown on the nav bar
    if current_user.is_authenticated:
        cart_items = current_user.cart_items
        CART_ITEMS_COUNT = len(cart_items)

    items_by_category = {}
    categories = []
    database_name = None
    
    if name == "Non-Veg":
        database_name = Items
        categories = ['Biriyani', 'Rice and Noodles', 'Grills', 'Sea Items', 'Buckets', 'Parotta and Gravy']  # Categories to display
        # eg: {'Biriyani': [<Items 1>, <Items 4>], 'Rice and Noodles': [<Items 2>], 'Grills': [<Items 3>]}

    if name == "Veg":
        database_name = Veg
        categories = ['Rice', 'Tiffins', 'Gravy']

    if name == "Desserts&Juices":
        database_name = DessertJuice
        categories = ['Juice', 'Fresh Juice', 'Ice Cream', 'Desserts']

    if name == "Chips&Snacks":
        database_name = ChipsSnacks
        categories = ['Chips', 'Fast Foods', 'Pastries']

    for category in categories:
        # getting the items from the database with their category.and stored in dictionary.
        items_by_category[category] = db.session.execute(db.select(database_name).where(database_name.category == category)).scalars().all()

    return render_template("foods.html", food_name=name,
                           items_by_category=items_by_category,
                           cart_items_count=CART_ITEMS_COUNT,
                           logged_in=current_user.is_authenticated)


# cart function
@app.route('/cart', methods=['POST', 'GET'])
def cart():
    global CART_ITEMS_COUNT
    # this is the form when the order now button is clicked . the pop up will show this form. till then it is hidden.
    # this form is submitted then it goes to order_now route.
    confirm_form = ConfirmForm()

    # only allows the user when he is logged in.
    if not current_user.is_authenticated:
        flash("First Log in and try again!")
        return redirect(url_for("login"))

    # if the user is authenticated then take all the cart items count belongs to user.and it is shown on the nav bar
    if current_user.is_authenticated:
        cart_items = current_user.cart_items
        CART_ITEMS_COUNT = len(cart_items)

    # storing all the objects of the cart
    cart_items = current_user.cart_items  # gives the cart items belongs to the user
    # eg [<Cart 1>, <Cart 2>]

    # adds all the prices of the items in the cart and stores it in the total
    total = sum(item.price for item in cart_items)

    return render_template("cart.html", items=cart_items,
                           total=total,
                           form=confirm_form,
                           cart_items_count=CART_ITEMS_COUNT,
                           logged_in=current_user.is_authenticated)


@app.route('/delete/<int:id>')
def cart_items_delete(id):
    global CART_ITEMS_COUNT
    CART_ITEMS_COUNT -= 1
    # getting the id of the item to delete the item from the cart
    item_to_delete = db.get_or_404(Cart, id)
    db.session.delete(item_to_delete)
    db.session.commit()

    return redirect(url_for('cart'))


@app.route('/add_to_cart/<int:item_id>/<item_category>')
def add_to_cart(item_id, item_category):
    # Decode the category to handle spaces. in this if the category is tiffin it works perfectly
    # if the category is rice and noodles then the url takes the spaces as %20 which is rice%20and%20noodles
    # to remove the the value unquote is used so that the category will be rice and noodles
    item_category = unquote(item_category)
    database_name = None
    print(item_id)
    print(item_category)
    # checking the item category to fetch the parent category
    # eg : item category is Grills it belongs to Non-veg
    # storing the database name in database_name variable
    name = None
    # storing the name that is to pass to the foods route
    if item_category in ['Biriyani', 'Rice and Noodles', 'Grills', 'Sea Items', 'Buckets', 'Parotta and Gravy']:
        name = "Non-Veg"
        database_name = Items

    if item_category in ['Rice', 'Tiffins', 'Gravy']:
        name = "Veg"
        database_name = Veg

    if item_category in ['Juice', 'Fresh Juice', 'Ice Cream', 'Desserts']:
        name = "Desserts&Juices"
        database_name = DessertJuice

    if item_category in ['Chips', 'Fast Foods', 'Pastries']:
        name = "Chips&Snacks"
        database_name = ChipsSnacks

    # fetches the item which is added to cart
    # if the add to cart item is cocacola then it belongs to Juice category which is in DessertJuice database
    # with the help of the database name and the item id we can fetch the item
    item_to_cart = db.get_or_404(database_name, item_id)
    new_item = Cart(
        name=item_to_cart.name,
        price=item_to_cart.price,
        image_url=item_to_cart.image_url,
        user_id=current_user.id
    )
    db.session.add(new_item)
    db.session.commit()

    return redirect(url_for('foods', name=name))


# forgot password route sends the otp to the email entered in the email field
@app.route('/forgot_password', methods=['POST', 'GET'])
def forgot_password():
    forgot_password_form = ForgotPasswordForm()  # Form for email and getOTP
    verifyotp_form = VerifyOtpForm()  # Form for otp enter and submit

    otp_verified = False  # To track OTP verification status

    # If the first form (forgot password) is submitted
    if forgot_password_form.validate_on_submit():
        # storing the email in the session
        session['entered_email'] = forgot_password_form.email.data

        # checking that the entered email is in the user database. if no then sending the flash message
        email_in_db = db.session.execute(db.select(Users).where(Users.email == session['entered_email'])).scalar()

        if email_in_db is None:
            flash("Enter the correct Email")
            return render_template("forgot_password.html", forgot=forgot_password_form, verify_otp=verifyotp_form,
                                   otp_verified=otp_verified)

        # Generate OTP and send it (you can add your OTP generation logic here)
        # Store OTP and timestamp in session or database
        otp_generated = random.randint(100000, 999999)

        # storing the otp in the database
        current_timestamp = time.time()
        new_otp = OTP(
            user_email=forgot_password_form.email.data,
            otp=otp_generated,
            timestamp=current_timestamp
        )
        db.session.add(new_otp)
        db.session.commit()

        # You can send OTP to the user via email here
        email = os.environ.get("RESTAURANT_EMAIL")
        password = os.environ.get("RESTAURANT_PASSWORD")

        with smtplib.SMTP("smtp.gmail.com", 587) as connection:
            connection.starttls()
            connection.login(user=email, password=password)
            msg = f"subject:OTP verification\n\n The OTP to change the password is {otp_generated}. The OTP is valid for 1 minute"
            connection.sendmail(from_addr=email, to_addrs=forgot_password_form.email.data,
                                msg=msg)

        otp_verified = True  # OTP not verified yet
        return render_template("forgot_password.html", forgot=forgot_password_form, verify_otp=verifyotp_form,
                               otp_verified=otp_verified)


    # If the second form (verify otp) is submitted and OTP is valid
    if verifyotp_form.validate_on_submit():
        # taking the otp in the database with the email entered stored in the session
        otp_obj = db.session.execute(db.select(OTP).where(OTP.user_email == session.get('entered_email'))).scalar()

        # Check OTP verification status if it is correct then delete otp from database and redirect to change the new_password route
        if otp_obj and str(otp_obj.otp) == verifyotp_form.otp.data and time.time() - otp_obj.timestamp <= 60:
            db.session.delete(otp_obj)
            db.session.commit()
            return redirect(url_for("new_password"))
        else:
            if otp_obj:  # Ensure the object exists before attempting deletion
                db.session.delete(otp_obj)
                db.session.commit()
            session.pop('entered_email', None)  # Clear email from session
            flash("Invalid OTP or OTP expired. Try Again!")
            return redirect(url_for('forgot_password'))

    return render_template("forgot_password.html", forgot=forgot_password_form, verify_otp=verifyotp_form,
                           otp_verified=otp_verified)


@app.route("/new_password", methods=['POST', 'GET'])
def new_password():
    new_password_form = NewPasswordForm()

    if new_password_form.validate_on_submit():
        # checking the new_password and the confirm_password is same.
        verified_email = session['entered_email']

        if new_password_form.new_password.data == new_password_form.confirm_password.data:
            # hashing the password and changing the passwprd for the user in the database
            hashed_password = generate_password_hash(password=new_password_form.new_password.data,
                                                     method="pbkdf2:sha256",
                                                     salt_length=8)
            user_obj = db.session.execute(db.select(Users).where(Users.email == verified_email)).scalar()
            user_obj.password = hashed_password
            db.session.commit()
            # Clear the email from the session after success
            session.pop('entered_email', None)
            flash("password changed successfully")
            return redirect(url_for("login"))

        else:
            flash("new password and current password is not the same")
            return redirect(url_for("new_password"))

    return render_template("new_password.html", new_password_form=new_password_form)


@app.route('/about_us')
def about_us():
    # checking the user is authenticated so that if authenticated we can hide the login and register button
    if current_user.is_authenticated:
        return render_template("aboutus.html",logged_in=current_user.is_authenticated,
                               cart_items_count=CART_ITEMS_COUNT)

    # if the user is not authenticated show the login and register button
    return render_template("aboutus.html",
                           cart_items_count=CART_ITEMS_COUNT)


@app.route('/contact', methods=['GET', 'POST'])
def contact_us():

    # only allows the user when he is logged in.
    if not current_user.is_authenticated:
        flash("First Log in and try again!")
        return redirect(url_for("login"))

    form = ContactForm()

    if form.validate_on_submit():
        # sending the message the user given in the contact form to us through email
        email = os.environ.get("RESTAURANT_EMAIL")
        password = os.environ.get("RESTAURANT_PASSWORD")

        with smtplib.SMTP("smtp.gmail.com", 587) as connection:
            connection.starttls()
            connection.login(user=email, password=password)
            # sending the name and the message of the user to our email
            msg = f"subject:Message from{form.name.data}\n\n {form.message.data}"
            connection.sendmail(from_addr=email, to_addrs=email,
                                msg=msg)

        # sending the success message as a flash
        flash('Thank you for your message! We will get back to you soon.', 'success')
        return redirect(url_for('contact_us'))

    return render_template('contactus.html', form=form, logged_in=current_user.is_authenticated,
                           cart_items_count=CART_ITEMS_COUNT)


@app.route('/order_now', methods=['POST'])
def order_now():
    if request.method == 'POST':
        # getting all the form details

        name = request.form.get("name")
        entered_email = request.form.get("email")
        ph_no = request.form.get("phone")
        address = request.form.get("address")
        payment_proof = request.files.get('payment_proof')

        # getting the items from the cart to show the owner what items has the user ordered.

        cart_items = current_user.cart_items
        # storing the names of the items in the list
        item_names = [items.name for items in cart_items]

        # joining the items names using join method because it is in list
        only_items_names = ", ".join(item_names)

        email = os.environ.get("RESTAURANT_EMAIL")
        password = os.environ.get("RESTAURANT_PASSWORD")

        # sending the mail to the owner what the user orders
        with smtplib.SMTP("smtp.gmail.com", 587) as connection:
            connection.starttls()
            connection.login(user=email, password=password)
            # sending the name and the message of the user to our email
            connection.sendmail(from_addr=email, to_addrs=email,
                                msg=f"Subject: Order Details from {name}\n\n"
                                    f"Items Ordered: {only_items_names}\n\n"
                                    f"Name: {name}\n"
                                    f"Email: {entered_email}\n"
                                    f"Phone: {ph_no}\n"
                                    f"Address: {address}\n"
                                    f"Payment Proof: {payment_proof}"
                                )

        with smtplib.SMTP("smtp.gmail.com", 587) as connection:
            connection.starttls()
            connection.login(user=email, password=password)
            msg=f"Subject: Order confirmation from Cozy Corner Restaurant\n\nYour order has been placed and will be delivered to you shortly.\nItems Ordered: {only_items_names}"

            connection.sendmail(from_addr=email, to_addrs=entered_email,
                                msg=msg)

        # Flashing a success message after order is confirmed
        flash("Your order has been successfully placed! You will receive a confirmation email shortly.", "success")

        # Deleting the cart items for the user after the order is confirmed
        for item in cart_items:
            db.session.delete(item)  # Assuming `db.session.delete()` removes the item from the database
        db.session.commit()  # Committing the changes to the database

        # Redirecting to cart page
        return redirect(url_for('cart'))


if __name__ == "__main__":
    app.run(debug=True)
