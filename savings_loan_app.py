from flask import Flask, render_template, request, redirect, url_for, flash, session, Response
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_socketio import SocketIO, emit
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import sqlite3
import os
import logging
import re
import csv
import io
from sqlalchemy import inspect
import json
import socket

# Configure logging
logging.basicConfig(level=logging.INFO, filename='savings_loan_app.log')
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///savings_loan.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
socketio = SocketIO(app)

# Database Models
class User(UserMixin, db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    role = db.Column(db.String(20), nullable=False)  # admin or staff
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)

class Customer(db.Model):
    __tablename__ = 'customer'
    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(100), nullable=False)
    bvn = db.Column(db.String(11), unique=True, nullable=False)
    location = db.Column(db.String(100), nullable=False)
    phone_number = db.Column(db.String(15), nullable=False)
    next_of_kin = db.Column(db.String(100), nullable=False)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

class Loan(db.Model):
    __tablename__ = 'loan'
    id = db.Column(db.Integer, primary_key=True)
    customer_id = db.Column(db.Integer, db.ForeignKey('customer.id'), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    balance = db.Column(db.Float, nullable=False)
    status = db.Column(db.String(20), default='active')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

class Savings(db.Model):
    __tablename__ = 'savings'
    id = db.Column(db.Integer, primary_key=True)
    customer_id = db.Column(db.Integer, db.ForeignKey('customer.id'), nullable=False)
    amount = db.Column(db.Float, default=0.0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Transaction(db.Model):
    __tablename__ = 'transaction'
    id = db.Column(db.Integer, primary_key=True)
    customer_id = db.Column(db.Integer, db.ForeignKey('customer.id'), nullable=False)
    loan_id = db.Column(db.Integer, db.ForeignKey('loan.id'), nullable=True)
    savings_id = db.Column(db.Integer, db.ForeignKey('savings.id'), nullable=True)
    type = db.Column(db.String(20), nullable=False)
    amount = db.Column(db.Float, nullable=True)
    payment_type = db.Column(db.String(20), nullable=True)
    details = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

class SavedFilter(db.Model):
    __tablename__ = 'saved_filter'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    filters = db.Column(db.Text, nullable=False)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

# Initialize database
def init_db():
    try:
        with app.app_context():
            inspector = inspect(db.engine)
            required_tables = ['user', 'customer', 'loan', 'savings', 'transaction', 'saved_filter']
            existing_tables = inspector.get_table_names()
            if not all(table in existing_tables for table in required_tables):
                db.create_all()
                logger.info("Database tables created successfully")
                if not db.session.query(User).first():
                    admin = User(username='admin', password=generate_password_hash('admin123'), role='admin')
                    db.session.add(admin)
                    db.session.commit()
                    logger.info("Default admin user created")
            else:
                logger.info("Database tables already exist, no changes made")
    except Exception as e:
        logger.error(f"Error initializing database: {str(e)}")
        raise

# Check database file accessibility
def check_db_access():
    db_path = 'savings_loan.db'
    try:
        if not os.path.exists(db_path):
            logger.warning(f"Database file {db_path} does not exist. Creating new database file...")
            open(db_path, 'a').close()
            init_db()
            return True
        if not os.access(db_path, os.R_OK | os.W_OK):
            logger.error(f"Database file {db_path} is not readable or writable")
            return False
        return True
    except Exception as e:
        logger.error(f"Error checking or creating database file {db_path}: {str(e)}")
        return False

# Validation functions
def validate_password(password):
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    if not re.search(r"[A-Za-z]", password):
        return False, "Password must contain at least one letter"
    if not re.search(r"[0-9]", password):
        return False, "Password must contain at least one number"
    return True, ""

def validate_phone_number(phone_number):
    pattern = r'^\+?\d{10,15}$'
    if not re.match(pattern, phone_number):
        return False, "Phone number must be 10-15 digits, optionally starting with +"
    return True, ""

def validate_bvn(bvn):
    if not re.match(r'^\d{11}$', bvn):
        return False, "BVN must be exactly 11 digits"
    return True, ""

def sanitize_for_json(text):
    if text is None:
        return ""
    text = str(text)
    text = text.replace("'", "\\'").replace('"', '\\"').replace('\\', '\\\\')
    text = ''.join(c for c in text if ord(c) >= 32)
    return text

# Smart recommendation logic
def get_recommendation(customer_id):
    try:
        customer = db.session.get(Customer, customer_id)
        if not customer:
            logger.error(f"Customer {customer_id} not found in get_recommendation")
            return {"type": "error", "amount": 0, "message": "Customer not found."}

        savings = db.session.query(Savings).filter_by(customer_id=customer_id).first()
        loans = db.session.query(Loan).filter_by(customer_id=customer_id, status='active').all()

        savings_amount = 0.0
        if savings:
            try:
                savings_amount = float(savings.amount) if savings.amount is not None else 0.0
            except (TypeError, ValueError) as e:
                logger.error(f"Invalid savings amount for customer {customer_id}: {savings.amount}, Type: {type(savings.amount)}")
                savings_amount = 0.0

        total_loan_balance = 0.0
        if not loans or not isinstance(loans, (list, tuple)):
            logger.info(f"No valid loans for customer {customer_id}: {loans}, Type: {type(loans)}")
        else:
            for loan in loans:
                try:
                    balance = float(loan.balance) if loan.balance is not None else 0.0
                    total_loan_balance += balance
                except (TypeError, ValueError) as e:
                    logger.error(f"Invalid balance for loan ID {loan.id} of customer {customer_id}: {loan.balance}, Type: {type(loan.balance)}")
                    continue

        if savings_amount > 1000 and total_loan_balance > 0:
            return {
                "type": "loan_payment",
                "amount": min(savings_amount * 0.2, total_loan_balance),
                "message": "Consider paying off a portion of your loan with excess savings."
            }
        elif savings_amount < 500:
            return {
                "type": "savings_deposit",
                "amount": 500 - savings_amount,
                "message": "Boost your savings with a deposit to reach a safer threshold."
            }
        return {"type": "none", "amount": 0, "message": "Your finances are on track!"}
    except Exception as e:
        logger.error(f"Error in get_recommendation for customer {customer_id}: {str(e)}")
        return {"type": "error", "amount": 0, "message": "An error occurred while generating recommendation."}

# Socket.IO event handlers
@socketio.on('connect')
def handle_connect():
    logger.info(f"Client connected: {request.sid}")

@socketio.on('disconnect')
def handle_disconnect():
    logger.info(f"Client disconnected: {request.sid}")

def broadcast_transaction(transaction):
    try:
        customer = db.session.get(Customer, transaction.customer_id)
        user = db.session.get(User, transaction.created_by)
        transaction_data = {
            'id': transaction.id,
            'type': transaction.type.capitalize(),
            'customer_name': customer.full_name if customer else 'Unknown',
            'amount': round(transaction.amount, 2) if transaction.amount is not None else 'N/A',
            'details': transaction.details or 'N/A',
            'created_by': user.username if user else 'Unknown',
            'created_at': transaction.created_at.strftime('%Y-%m-%d %H:%M:%S')
        }
        socketio.emit('new_transaction', transaction_data, namespace='/')
        logger.info(f"Broadcasted transaction: {transaction_data}")
    except Exception as e:
        logger.error(f"Error broadcasting transaction: {str(e)}")

# Routes
@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = db.session.query(User).filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('dashboard'))
        flash('Invalid credentials', 'error')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.role == 'admin':
        total_customers = db.session.query(Customer).count()
        total_loans = db.session.query(Loan).count()
        total_savings = db.session.query(Savings).count()
        recent_transactions = db.session.query(Transaction).order_by(Transaction.created_at.desc()).limit(5).all()
        transactions_with_customer = [
            {
                'id': transaction.id,
                'type': transaction.type,
                'amount': transaction.amount,
                'details': transaction.details,
                'customer_name': db.session.get(Customer, transaction.customer_id).full_name if db.session.get(Customer, transaction.customer_id) else 'Unknown',
                'created_at': transaction.created_at
            }
            for transaction in recent_transactions
        ]
        customers = db.session.query(Customer).all()
        customers_with_details = [
            {
                'id': customer.id,
                'full_name': customer.full_name,
                'bvn': customer.bvn,
                'location': customer.location,
                'phone_number': customer.phone_number,
                'next_of_kin': customer.next_of_kin,
                'created_by_username': db.session.get(User, customer.created_by).username if customer.created_by and db.session.get(User, customer.created_by) else 'Unknown'
            }
            for customer in customers
        ]
        return render_template(
            'admin_dashboard.html',
            total_customers=total_customers,
            total_loans=total_loans,
            total_savings=total_savings,
            transactions=transactions_with_customer,
            customers=customers_with_details
        )
    else:
        customers = db.session.query(Customer).all()
        customers_with_details = [
            {
                'id': customer.id,
                'full_name': customer.full_name,
                'bvn': customer.bvn,
                'location': customer.location,
                'phone_number': customer.phone_number,
                'next_of_kin': customer.next_of_kin,
                'created_by_username': db.session.get(User, customer.created_by).username if customer.created_by and db.session.get(User, customer.created_by) else 'Unknown'
            }
            for customer in customers
        ]
        return render_template('staff_dashboard.html', customers=customers_with_details)

@app.route('/search_customers', methods=['GET', 'POST'])
@login_required
def search_customers():
    if request.method == 'POST':
        search_query = request.form.get('search_query', '').strip()
        if not search_query:
            flash('Please enter a search term', 'error')
            return redirect(url_for('dashboard'))
        try:
            customers = db.session.query(Customer).filter(
                db.or_(
                    Customer.full_name.ilike(f'%{search_query}%'),
                    Customer.bvn.ilike(f'%{search_query}%')
                )
            ).all()
            customers_with_details = [
                {
                    'id': customer.id,
                    'full_name': customer.full_name,
                    'bvn': customer.bvn,
                    'location': customer.location,
                    'phone_number': customer.phone_number,
                    'next_of_kin': customer.next_of_kin,
                    'created_by_username': db.session.get(User, customer.created_by).username if customer.created_by and db.session.get(User, customer.created_by) else 'Unknown'
                }
                for customer in customers
            ]
            return render_template(
                'staff_dashboard.html' if current_user.role != 'admin' else 'admin_dashboard.html',
                customers=customers_with_details,
                search_query=search_query,
                total_customers=db.session.query(Customer).count(),
                total_loans=db.session.query(Loan).count(),
                total_savings=db.session.query(Savings).count(),
                transactions=db.session.query(Transaction).order_by(Transaction.created_at.desc()).limit(5).all() if current_user.role == 'admin' else []
            )
        except Exception as e:
            logger.error(f"Error searching customers: {str(e)}")
            flash('An error occurred while searching. Please try again.', 'error')
            return redirect(url_for('dashboard'))
    return redirect(url_for('dashboard'))

@app.route('/create_staff', methods=['GET', 'POST'])
@login_required
def create_staff():
    if current_user.role != 'admin':
        flash('Unauthorized', 'error')
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        is_valid, message = validate_password(password)
        if not is_valid:
            flash(message, 'error')
            return redirect(url_for('create_staff'))
        if db.session.query(User).filter_by(username=username).first():
            flash('Username already exists. Please choose a different username.', 'error')
            return redirect(url_for('create_staff'))
        try:
            user = User(
                username=username,
                password=generate_password_hash(password),
                role='staff',
                created_by=current_user.id
            )
            db.session.add(user)
            db.session.commit()
            flash('Staff created successfully', 'success')
            return redirect(url_for('dashboard'))
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error creating staff: {str(e)}")
            flash('An error occurred while creating the staff. Please try again.', 'error')
            return redirect(url_for('create_staff'))
    return render_template('create_staff.html')

@app.route('/edit_staff/<int:staff_id>', methods=['GET', 'POST'])
@login_required
def edit_staff(staff_id):
    if current_user.role != 'admin':
        flash('Unauthorized', 'error')
        return redirect(url_for('dashboard'))
    staff = db.session.get(User, staff_id)
    if not staff:
        flash('Staff not found', 'error')
        return redirect(url_for('list_staff'))
    if request.method == 'POST':
        username = request.form['username']
        password = request.form.get('password', '')
        existing_user = db.session.query(User).filter_by(username=username).first()
        if existing_user and existing_user.id != staff_id:
            flash('Username already exists. Please choose a different username.', 'error')
            return redirect(url_for('edit_staff', staff_id=staff_id))
        if password:
            is_valid, message = validate_password(password)
            if not is_valid:
                flash(message, 'error')
                return redirect(url_for('edit_staff', staff_id=staff_id))
        try:
            staff.username = username
            if password:
                staff.password = generate_password_hash(password)
            db.session.commit()
            flash('Staff updated successfully', 'success')
            return redirect(url_for('list_staff'))
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error updating staff: {str(e)}")
            flash('An error occurred while updating the staff. Please try again.', 'error')
            return redirect(url_for('edit_staff', staff_id=staff_id))
    return render_template('edit_staff.html', staff=staff)

@app.route('/delete_staff/<int:staff_id>', methods=['POST'])
@login_required
def delete_staff(staff_id):
    if current_user.role != 'admin':
        flash('Unauthorized', 'error')
        return redirect(url_for('dashboard'))
    staff = db.session.get(User, staff_id)
    if not staff:
        flash('Staff not found', 'error')
        return redirect(url_for('list_staff'))
    if staff.id == current_user.id:
        flash('Cannot delete your own account', 'error')
        return redirect(url_for('list_staff'))
    if staff.role == 'admin' and db.session.query(User).filter_by(role='admin').count() == 1:
        flash('Cannot delete the last admin account', 'error')
        return redirect(url_for('list_staff'))
    try:
        db.session.delete(staff)
        db.session.commit()
        flash('Staff deleted successfully', 'success')
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error deleting staff: {str(e)}")
        flash('An error occurred while deleting the staff. Please try again.', 'error')
    return redirect(url_for('list_staff'))

@app.route('/list_staff')
@login_required
def list_staff():
    if current_user.role != 'admin':
        flash('Unauthorized', 'error')
        return redirect(url_for('dashboard'))
    staff_users = db.session.query(User).filter_by(role='staff').all()
    staff_with_details = [
        {
            'id': staff.id,
            'username': staff.username,
            'role': staff.role,
            'created_by_username': db.session.get(User, staff.created_by).username if staff.created_by and db.session.get(User, staff.created_by) else 'N/A'
        }
        for staff in staff_users
    ]
    return render_template('list_staff.html', staff_users=staff_with_details)

@app.route('/staff_activities/<int:staff_id>')
@login_required
def staff_activities(staff_id):
    if current_user.role != 'admin':
        flash('Unauthorized', 'error')
        return redirect(url_for('dashboard'))
    staff = db.session.get(User, staff_id)
    if not staff:
        flash('Staff not found', 'error')
        return redirect(url_for('list_staff'))
    transactions = db.session.query(Transaction).filter_by(created_by=staff_id).order_by(Transaction.created_at.desc()).all()
    transactions_with_details = [
        {
            'id': transaction.id,
            'type': transaction.type,
            'amount': transaction.amount,
            'details': transaction.details,
            'customer_name': db.session.get(Customer, transaction.customer_id).full_name if db.session.get(Customer, transaction.customer_id) else 'Unknown',
            'created_at': transaction.created_at
        }
        for transaction in transactions
    ]
    return render_template('staff_activities.html', staff=staff, transactions=transactions_with_details)

@app.route('/create_customer', methods=['GET', 'POST'])
@login_required
def create_customer():
    if current_user.role != 'admin' and current_user.role != 'staff':
        flash('Unauthorized', 'error')
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        bvn = request.form['bvn']
        if db.session.query(Customer).filter_by(bvn=bvn).first():
            flash('BVN already exists. Please use a different BVN.', 'error')
            return redirect(url_for('create_customer'))
        phone_number = request.form['phone_number']
        is_valid_phone, phone_message = validate_phone_number(phone_number)
        if not is_valid_phone:
            flash(phone_message, 'error')
            return redirect(url_for('create_customer'))
        is_valid_bvn, bvn_message = validate_bvn(bvn)
        if not is_valid_bvn:
            flash(bvn_message, 'error')
            return redirect(url_for('create_customer'))
        try:
            customer = Customer(
                full_name=sanitize_for_json(request.form['full_name']),
                bvn=bvn,
                location=request.form['location'],
                phone_number=phone_number,
                next_of_kin=sanitize_for_json(request.form['next_of_kin']),
                created_by=current_user.id
            )
            db.session.add(customer)
            db.session.commit()
            transaction = Transaction(
                customer_id=customer.id,
                type='customer_creation',
                details=json.dumps({'full_name': customer.full_name, 'bvn': customer.bvn}),
                created_by=current_user.id
            )
            db.session.add(transaction)
            db.session.commit()
            broadcast_transaction(transaction)
            flash('Customer created successfully', 'success')
            return redirect(url_for('dashboard'))
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error creating customer: {str(e)}")
            flash('An error occurred while creating the customer. Please try again.', 'error')
            return redirect(url_for('create_customer'))
    return render_template('create_customer.html')

@app.route('/edit_customer/<int:customer_id>', methods=['GET', 'POST'])
@login_required
def edit_customer(customer_id):
    if current_user.role != 'admin' and current_user.role != 'staff':
        flash('Unauthorized', 'error')
        return redirect(url_for('dashboard'))
    customer = db.session.get(Customer, customer_id)
    if not customer:
        flash('Customer not found', 'error')
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        full_name = sanitize_for_json(request.form['full_name'])
        bvn = request.form['bvn']
        location = request.form['location']
        phone_number = request.form['phone_number']
        next_of_kin = sanitize_for_json(request.form['next_of_kin'])

        is_valid_phone, phone_message = validate_phone_number(phone_number)
        if not is_valid_phone:
            flash(phone_message, 'error')
            return redirect(url_for('edit_customer', customer_id=customer_id))
        is_valid_bvn, bvn_message = validate_bvn(bvn)
        if not is_valid_bvn:
            flash(bvn_message, 'error')
            return redirect(url_for('edit_customer', customer_id=customer_id))

        existing_bvn = db.session.query(Customer).filter_by(bvn=bvn).first()
        if existing_bvn and existing_bvn.id != customer_id:
            flash('BVN already exists. Please use a different BVN.', 'error')
            return redirect(url_for('edit_customer', customer_id=customer_id))

        try:
            changes = {}
            if customer.full_name != full_name:
                changes['full_name'] = f"{customer.full_name} -> {full_name}"
            if customer.bvn != bvn:
                changes['bvn'] = f"{customer.bvn} -> {bvn}"
            if customer.location != location:
                changes['location'] = f"{customer.location} -> {location}"
            if customer.phone_number != phone_number:
                changes['phone_number'] = f"{customer.phone_number} -> {phone_number}"
            if customer.next_of_kin != next_of_kin:
                changes['next_of_kin'] = f"{customer.next_of_kin} -> {next_of_kin}"

            if changes:
                transaction = Transaction(
                    customer_id=customer_id,
                    type='customer_update',
                    details=json.dumps(changes),
                    created_by=current_user.id
                )
                db.session.add(transaction)

            customer.full_name = full_name
            customer.bvn = bvn
            customer.location = location
            customer.phone_number = phone_number
            customer.next_of_kin = next_of_kin
            db.session.commit()
            if changes:
                broadcast_transaction(transaction)
            flash('Customer updated successfully', 'success')
            return redirect(url_for('dashboard'))
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error updating customer: {str(e)}")
            flash('An error occurred while updating the customer. Please try again.', 'error')
            return redirect(url_for('edit_customer', customer_id=customer_id))
    return render_template('edit_customer.html', customer=customer)

@app.route('/delete_customer/<int:customer_id>', methods=['POST'])
@login_required
def delete_customer(customer_id):
    if current_user.role != 'admin' and current_user.role != 'staff':
        flash('Unauthorized', 'error')
        return redirect(url_for('dashboard'))
    customer = db.session.get(Customer, customer_id)
    if not customer:
        flash('Customer not found', 'error')
        return redirect(url_for('dashboard'))
    active_loans = db.session.query(Loan).filter_by(customer_id=customer_id, status='active').count()
    savings = db.session.query(Savings).filter_by(customer_id=customer_id).first()
    if active_loans > 0:
        flash('Cannot delete customer with active loans', 'error')
        return redirect(url_for('dashboard'))
    if savings and savings.amount > 0:
        flash('Cannot delete customer with non-zero savings balance', 'error')
        return redirect(url_for('dashboard'))
    try:
        transaction = Transaction(
            customer_id=customer_id,
            type='customer_deletion',
            details=json.dumps({'full_name': customer.full_name, 'bvn': customer.bvn}),
            created_by=current_user.id
        )
        db.session.add(transaction)
        if savings:
            db.session.delete(savings)
        db.session.delete(customer)
        db.session.commit()
        broadcast_transaction(transaction)
        flash('Customer deleted successfully', 'success')
        return redirect(url_for('dashboard'))
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error deleting customer: {str(e)}")
        flash('An error occurred while deleting the customer. Please try again.', 'error')
        return redirect(url_for('dashboard'))

@app.route('/create_loan/<int:customer_id>', methods=['GET', 'POST'])
@login_required
def create_loan(customer_id):
    if current_user.role != 'admin' and current_user.role != 'staff':
        flash('Unauthorized', 'error')
        return redirect(url_for('dashboard'))
    customer = db.session.get(Customer, customer_id)
    if not customer:
        flash('Customer not found', 'error')
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        try:
            amount = float(request.form['amount'])
            if amount <= 0:
                flash('Loan amount must be greater than zero', 'error')
                return redirect(url_for('create_loan', customer_id=customer_id))
            loan = Loan(customer_id=customer_id, amount=amount, balance=amount, created_by=current_user.id)
            db.session.add(loan)
            db.session.commit()
            transaction = Transaction(
                customer_id=customer_id,
                loan_id=loan.id,
                type='loan_creation',
                amount=amount,
                created_by=current_user.id
            )
            db.session.add(transaction)
            db.session.commit()
            broadcast_transaction(transaction)
            flash('Loan created successfully', 'success')
            return redirect(url_for('view_customer', customer_id=customer_id))
        except ValueError:
            flash('Invalid loan amount', 'error')
            return redirect(url_for('create_loan', customer_id=customer_id))
    return render_template('create_loan.html', customer=customer)

@app.route('/make_payment/<int:loan_id>', methods=['GET', 'POST'])
@login_required
def make_payment(loan_id):
    loan = db.session.get(Loan, loan_id)
    if not loan:
        flash('Loan not found', 'error')
        return redirect(url_for('dashboard'))
    customer = db.session.get(Customer, loan.customer_id)
    savings = db.session.query(Savings).filter_by(customer_id=loan.customer_id).first()
    savings_balance = savings.amount if savings else 0.0
    if request.method == 'POST':
        payment_source = request.form.get('payment_source')
        try:
            amount = float(request.form['amount'])
            payment_type = request.form['payment_type']
            if amount <= 0:
                flash('Payment amount must be greater than zero', 'error')
                return redirect(url_for('make_payment', loan_id=loan_id))
            if amount > loan.balance:
                flash('Payment amount exceeds loan balance', 'error')
                return redirect(url_for('view_customer', customer_id=loan.customer_id))
            if payment_source == 'savings' and (not savings or amount > savings_balance):
                flash('Insufficient savings balance', 'error')
                return redirect(url_for('view_customer', customer_id=loan.customer_id))
            loan.balance -= amount
            if loan.balance == 0:
                loan.status = 'paid'
            if payment_source == 'savings':
                savings.amount -= amount
                transaction = Transaction(
                    customer_id=loan.customer_id,
                    loan_id=loan.id,
                    savings_id=savings.id,
                    type='savings_withdrawal',
                    amount=amount,
                    payment_type='savings',
                    created_by=current_user.id
                )
                db.session.add(transaction)
            transaction = Transaction(
                customer_id=loan.customer_id,
                loan_id=loan.id,
                type='loan_payment',
                amount=amount,
                payment_type=payment_type,
                created_by=current_user.id
            )
            db.session.add(transaction)
            db.session.commit()
            broadcast_transaction(transaction)
            flash('Payment recorded successfully', 'success')
            return redirect(url_for('view_customer', customer_id=loan.customer_id))
        except ValueError:
            flash('Invalid payment amount', 'error')
            return redirect(url_for('make_payment', loan_id=loan_id))
    return render_template('make_payment.html', loan=loan, customer=customer, savings_balance=savings_balance)

@app.route('/deposit_savings/<int:customer_id>', methods=['GET', 'POST'])
@login_required
def deposit_savings(customer_id):
    customer = db.session.get(Customer, customer_id)
    if not customer:
        flash('Customer not found', 'error')
        return redirect(url_for('dashboard'))
    savings = db.session.query(Savings).filter_by(customer_id=customer_id).first()
    if request.method == 'POST':
        try:
            amount = float(request.form['amount'])
            if amount <= 0:
                flash('Deposit amount must be greater than zero', 'error')
                return redirect(url_for('deposit_savings', customer_id=customer_id))
            if not savings:
                savings = Savings(customer_id=customer_id, amount=0)
                db.session.add(savings)
            savings.amount += amount
            transaction = Transaction(
                customer_id=customer_id,
                savings_id=savings.id,
                type='savings_deposit',
                amount=amount,
                created_by=current_user.id
            )
            db.session.add(transaction)
            db.session.commit()
            broadcast_transaction(transaction)
            flash('Savings deposit recorded successfully', 'success')
            return redirect(url_for('view_customer', customer_id=customer_id))
        except ValueError:
            flash('Invalid deposit amount', 'error')
            return redirect(url_for('deposit_savings', customer_id=customer_id))
    return render_template('deposit_savings.html', customer=customer)

@app.route('/view_customer/<int:customer_id>')
@login_required
def view_customer(customer_id):
    try:
        customer = db.session.get(Customer, customer_id)
        if not customer:
            flash('Customer not found', 'error')
            return redirect(url_for('dashboard'))

        loans = db.session.query(Loan).filter_by(customer_id=customer_id).all()
        logger.info(f"Loans for customer {customer_id}: {loans}, Type: {type(loans)}")
        savings = db.session.query(Savings).filter_by(customer_id=customer_id).first()
        transactions = db.session.query(Transaction).filter_by(customer_id=customer_id).order_by(Transaction.created_at.desc()).all()
        recommendation = get_recommendation(customer_id)

        return render_template('view_customer.html', customer=customer, loans=loans, savings=savings, transactions=transactions, recommendation=recommendation)
    except Exception as e:
        logger.error(f"Error viewing customer {customer_id}: {str(e)}")
        flash('An error occurred. Please try again or contact support.', 'error')
        return redirect(url_for('dashboard'))

@app.route('/customer_dashboard')
@login_required
def customer_dashboard():
    try:
        if current_user.role != 'customer':
            flash('Access denied. Customers only.', 'error')
            return redirect(url_for('dashboard'))

        customer_id = current_user.id
        loans = db.session.query(Loan).filter_by(customer_id=customer_id, status='active').all()
        savings = db.session.query(Savings).filter_by(customer_id=customer_id).first()
        transactions = db.session.query(Transaction).filter_by(customer_id=customer_id).order_by(Transaction.created_at.desc()).limit(5).all()
        total_loans_balance = sum(loan.balance for loan in loans) if loans else 0.0
        savings_balance = savings.amount if savings else 0.0
        recommendation = get_recommendation(customer_id)

        return render_template('customer_dashboard.html', total_loans_balance=total_loans_balance, savings_balance=savings_balance, recent_transactions=transactions, recommendation=recommendation)
    except Exception as e:
        logger.error(f"Error loading customer dashboard: {str(e)}")
        flash('An error occurred. Please try again or contact support.', 'error')
        return redirect(url_for('dashboard'))

@app.route('/audit_logs', methods=['GET', 'POST'])
@login_required
def audit_logs():
    if current_user.role != 'admin':
        flash('Unauthorized', 'error')
        return redirect(url_for('dashboard'))
    try:
        transactions = db.session.query(Transaction).order_by(Transaction.created_at.desc()).all()
        transactions_with_details = [
            {
                'id': transaction.id,
                'type': transaction.type,
                'amount': transaction.amount,
                'details': transaction.details,
                'customer_name': db.session.get(Customer, transaction.customer_id).full_name if db.session.get(Customer, transaction.customer_id) else 'Unknown',
                'created_by': db.session.get(User, transaction.created_by).username if db.session.get(User, transaction.created_by) else 'Unknown',
                'created_at': transaction.created_at
            }
            for transaction in transactions
        ]
        if request.method == 'POST' and request.form.get('export_audit') == 'csv':
            output = io.StringIO()
            writer = csv.writer(output)
            writer.writerow(['Transaction ID', 'Type', 'Amount', 'Details', 'Customer Name', 'Created By', 'Created At'])
            for transaction in transactions_with_details:
                writer.writerow([
                    transaction['id'],
                    transaction['type'],
                    transaction['amount'] if transaction['amount'] is not None else 'N/A',
                    transaction['details'] if transaction['details'] else 'N/A',
                    transaction['customer_name'],
                    transaction['created_by'],
                    transaction['created_at'].strftime('%Y-%m-%d %H:%M:%S')
                ])
            output.seek(0)
            return Response(
                output.getvalue(),
                mimetype='text/csv',
                headers={'Content-Disposition': 'attachment;filename=audit_logs.csv'}
            )
        return render_template('audit_logs.html', transactions=transactions_with_details)
    except Exception as e:
        logger.error(f"Error in audit_logs route: {str(e)}")
        flash('An error occurred while loading audit logs. Please try again.', 'error')
        return redirect(url_for('dashboard'))

@app.route('/reports', methods=['GET', 'POST'])
@login_required
def reports():
    if current_user.role != 'admin':
        flash('Unauthorized', 'error')
        return redirect(url_for('dashboard'))

    if not check_db_access():
        logger.error("Database file is inaccessible")
        flash("Database file is inaccessible. Please check file permissions or disk space.", 'error')
        return redirect(url_for('dashboard'))

    max_retries = 2
    retry_count = session.get('reports_retry_count', 0)

    if retry_count >= max_retries:
        logger.error(f"Max retries ({max_retries}) reached for database initialization in reports route")
        flash("Unable to initialize database after multiple attempts. Please check the database file and try again.", 'error')
        session['reports_retry_count'] = 0
        return redirect(url_for('dashboard'))

    try:
        inspector = inspect(db.engine)
        required_tables = ['user', 'customer', 'loan', 'savings', 'transaction', 'saved_filter']
        existing_tables = inspector.get_table_names()
        missing_tables = [table for table in required_tables if table not in existing_tables]

        if missing_tables:
            logger.error(f"Missing tables: {', '.join(missing_tables)}. Attempting to create tables...")
            session['reports_retry_count'] = retry_count + 1
            init_db()
            flash(f"Database tables created due to missing tables: {', '.join(missing_tables)}", 'success')
            return redirect(url_for('reports'))

        session['reports_retry_count'] = 0

        saved_filters = db.session.query(SavedFilter).filter_by(created_by=current_user.id).all()

        start_date = request.form.get('start_date')
        end_date = request.form.get('end_date')
        customer_name = request.form.get('customer_name', '').strip()
        bvn = request.form.get('bvn', '').strip()
        loan_status = request.form.get('loan_status', '')
        transaction_type = request.form.get('transaction_type', '')
        min_amount = request.form.get('min_amount', '')
        max_amount = request.form.get('max_amount', '')
        filter_logic = request.form.get('filter_logic', 'AND')
        save_filter = request.form.get('save_filter', '')
        filter_name = request.form.get('filter_name', '').strip()
        load_filter_id = request.form.get('load_filter')
        report_type = request.form.get('report_type', 'customer')

        if load_filter_id:
            saved_filter = db.session.get(SavedFilter, int(load_filter_id))
            if saved_filter:
                filters = json.loads(saved_filter.filters)
                customer_name = filters.get('customer_name', '')
                bvn = filters.get('bvn', '')
                loan_status = filters.get('loan_status', '')
                transaction_type = filters.get('transaction_type', '')
                min_amount = filters.get('min_amount', '')
                max_amount = filters.get('max_amount', '')
                start_date = filters.get('start_date', '')
                end_date = filters.get('end_date', '')
                filter_logic = filters.get('filter_logic', 'AND')
                flash(f"Loaded saved filter: {saved_filter.name}", 'success')

        if save_filter and filter_name:
            try:
                filters = {
                    'customer_name': customer_name,
                    'bvn': bvn,
                    'loan_status': loan_status,
                    'transaction_type': transaction_type,
                    'min_amount': min_amount,
                    'max_amount': max_amount,
                    'start_date': start_date,
                    'end_date': end_date,
                    'filter_logic': filter_logic
                }
                existing_filter = db.session.query(SavedFilter).filter_by(name=filter_name, created_by=current_user.id).first()
                if existing_filter:
                    flash('Filter name already exists. Please choose a different name.', 'error')
                else:
                    saved_filter = SavedFilter(name=filter_name, filters=json.dumps(filters), created_by=current_user.id)
                    db.session.add(saved_filter)
                    db.session.commit()
                    flash(f"Filter '{filter_name}' saved successfully", 'success')
            except Exception as e:
                db.session.rollback()
                logger.error(f"Error saving filter: {str(e)}")
                flash('An error occurred while saving the filter. Please try again.', 'error')

        customer_report = []
        staff_report = []
        transaction_report = []
        customer_chart_data = {}
        staff_chart_data = {}
        transaction_chart_data = {}

        if report_type == 'customer':
            customer_query = (
                db.session.query(
                    Customer.id,
                    Customer.full_name,
                    db.func.count(Loan.id).label('loan_count'),
                    db.func.sum(Loan.amount).label('total_loans'),
                    Savings.amount.label('total_savings')
                )
                .outerjoin(Loan, Customer.id == Loan.customer_id)
                .outerjoin(Savings, Customer.id == Savings.customer_id)
            )

            if customer_name:
                customer_query = customer_query.filter(Customer.full_name.ilike(f'%{customer_name}%'))
            if bvn:
                customer_query = customer_query.filter(Customer.bvn.ilike(f'%{bvn}%'))
            if loan_status:
                customer_query = customer_query.filter(Loan.status == loan_status)
            if start_date and end_date:
                customer_query = customer_query.filter(Loan.created_at.between(start_date, end_date))
            if transaction_type:
                customer_query = customer_query.join(Transaction, Customer.id == Transaction.customer_id).filter(Transaction.type == transaction_type)

            if filter_logic == 'OR' and (customer_name or bvn or loan_status or transaction_type):
                customer_query = (
                    db.session.query(
                        Customer.id,
                        Customer.full_name,
                        db.func.count(Loan.id).label('loan_count'),
                        db.func.sum(Loan.amount).label('total_loans'),
                        Savings.amount.label('total_savings')
                    )
                    .outerjoin(Loan, Customer.id == Loan.customer_id)
                    .outerjoin(Savings, Customer.id == Savings.customer_id)
                    .outerjoin(Transaction, Customer.id == Transaction.customer_id)
                    .filter(
                        db.or_(
                            Customer.full_name.ilike(f'%{customer_name}%') if customer_name else True,
                            Customer.bvn.ilike(f'%{bvn}%') if bvn else True,
                            Loan.status == loan_status if loan_status else True,
                            Transaction.type == transaction_type if transaction_type else True
                        )
                    )
                )
                if start_date and end_date:
                    customer_query = customer_query.filter(Loan.created_at.between(start_date, end_date))

            customer_query = customer_query.group_by(Customer.id, Customer.full_name, Savings.amount)
            customer_report = [
                (row.id, sanitize_for_json(row.full_name), row.loan_count, row.total_loans or 0, row.total_savings or 0)
                for row in customer_query.all()
            ]
            customer_chart_data = {
                'labels': [row[1] for row in customer_report],
                'loans': [float(row[3]) if row[3] is not None else 0 for row in customer_report],
                'savings': [float(row[4]) if row[4] is not None else 0 for row in customer_report]
            }

        elif report_type == 'staff':
            staff_query = (
                db.session.query(
                    User.id,
                    User.username,
                    db.func.count(Transaction.id).label('transaction_count'),
                    db.func.sum(Transaction.amount).label('total_amount')
                )
                .outerjoin(Transaction, User.id == Transaction.created_by)
            )
            if transaction_type:
                staff_query = staff_query.filter(Transaction.type == transaction_type)
            if min_amount:
                staff_query = staff_query.filter(Transaction.amount >= float(min_amount))
            if max_amount:
                staff_query = staff_query.filter(Transaction.amount <= float(max_amount))
            staff_query = staff_query.group_by(User.id, User.username)
            staff_report = [
                (row.id, sanitize_for_json(row.username), row.transaction_count, row.total_amount or 0)
                for row in staff_query.all()
            ]
            staff_chart_data = {
                'labels': [row[1] for row in staff_report],
                'transactions': [int(row[2]) for row in staff_report],
                'amounts': [float(row[3]) if row[3] is not None else 0 for row in staff_report]
            }

        elif report_type == 'transaction':
            transaction_query = (
                db.session.query(
                    Transaction.id,
                    Transaction.type,
                    Transaction.amount,
                    Transaction.details,
                    Customer.full_name,
                    User.username.label('created_by'),
                    Transaction.created_at
                )
                .join(Customer, Transaction.customer_id == Customer.id)
                .join(User, Transaction.created_by == User.id)
            )
            if customer_name:
                transaction_query = transaction_query.filter(Customer.full_name.ilike(f'%{customer_name}%'))
            if transaction_type:
                transaction_query = transaction_query.filter(Transaction.type == transaction_type)
            if start_date and end_date:
                transaction_query = transaction_query.filter(Transaction.created_at.between(start_date, end_date))
            if min_amount:
                transaction_query = transaction_query.filter(Transaction.amount >= float(min_amount))
            if max_amount:
                transaction_query = transaction_query.filter(Transaction.amount <= float(max_amount))

            if filter_logic == 'OR' and (customer_name or transaction_type):
                transaction_query = (
                    db.session.query(
                        Transaction.id,
                        Transaction.type,
                        Transaction.amount,
                        Transaction.details,
                        Customer.full_name,
                        User.username.label('created_by'),
                        Transaction.created_at
                    )
                    .join(Customer, Transaction.customer_id == Customer.id)
                    .join(User, Transaction.created_by == User.id)
                    .filter(
                        db.or_(
                            Customer.full_name.ilike(f'%{customer_name}%') if customer_name else True,
                            Transaction.type == transaction_type if transaction_type else True
                        )
                    )
                )
                if start_date and end_date:
                    transaction_query = transaction_query.filter(Transaction.created_at.between(start_date, end_date))
                if min_amount:
                    transaction_query = transaction_query.filter(Transaction.amount >= float(min_amount))
                if max_amount:
                    transaction_query = transaction_query.filter(Transaction.amount <= float(max_amount))

            transaction_query = transaction_query.order_by(Transaction.created_at.desc())
            transaction_report = [
                (
                    row.id,
                    row.type,
                    row.amount if row.amount is not None else 'N/A',
                    row.details if row.details else 'N/A',
                    row.full_name,
                    row.created_by,
                    row.created_at.strftime('%Y-%m-%d %H:%M:%S')
                )
                for row in transaction_query.all()
            ]
            transaction_chart_data = {
                'labels': [row[4] for row in transaction_report],
                'amounts': [float(row[2]) if row[2] != 'N/A' else 0 for row in transaction_report]
            }

        logger.info("Customer chart data: %s", json.dumps(customer_chart_data))
        logger.info("Staff chart data: %s", json.dumps(staff_chart_data))
        logger.info("Transaction chart data: %s", json.dumps(transaction_chart_data))

        export_type = request.form.get('export_type')
        if export_type in ['customer_csv', 'staff_csv', 'transaction_csv']:
            output = io.StringIO()
            writer = csv.writer(output)
            if export_type == 'customer_csv':
                writer.writerow(['Customer Name', 'Number of Loans', 'Total Loan Amount', 'Total Savings'])
                for row in customer_report:
                    writer.writerow([row[1], row[2], row[3], row[4]])
                filename = 'customer_report.csv'
            elif export_type == 'staff_csv':
                writer.writerow(['Staff Username', 'Number of Transactions', 'Total Amount'])
                for row in staff_report:
                    writer.writerow([row[1], row[2], row[3]])
                filename = 'staff_report.csv'
            else:
                writer.writerow(['Transaction ID', 'Type', 'Amount', 'Details', 'Customer Name', 'Created By', 'Created At'])
                for row in transaction_report:
                    writer.writerow(row)
                filename = 'transaction_history.csv'
            output.seek(0)
            return Response(
                output.getvalue(),
                mimetype='text/csv',
                headers={'Content-Disposition': f'attachment;filename={filename}'}
            )

        return render_template(
            'reports.html',
            customer_report=customer_report,
            staff_report=staff_report,
            transaction_report=transaction_report,
            customer_chart_data=customer_chart_data,
            staff_chart_data=staff_chart_data,
            transaction_chart_data=transaction_chart_data,
            start_date=start_date,
            end_date=end_date,
            customer_name=customer_name,
            bvn=bvn,
            loan_status=loan_status,
            transaction_type=transaction_type,
            min_amount=min_amount,
            max_amount=max_amount,
            filter_logic=filter_logic,
            saved_filters=saved_filters,
            report_type=report_type
        )

    except sqlite3.OperationalError as e:
        logger.error(f"Database error in reports route: {str(e)}")
        flash(f"Database error: {str(e)}. Attempting to reinitialize database...", 'error')
        session['reports_retry_count'] = retry_count + 1
        init_db()
        return redirect(url_for('reports'))
    except Exception as e:
        logger.error(f"Unexpected error in reports route: {str(e)}")
        flash(f"Unexpected error: {str(e)}. Please try again or contact support.", 'error')
        return redirect(url_for('dashboard'))

if __name__ == '__main__':
    try:
        if check_db_access():
            init_db()
        local_ip = socket.gethostbyname(socket.gethostname())
        print(f"Running on http://{local_ip}:5000/")
        socketio.run(app, host='0.0.0.0', port=5000, debug=True)
    except Exception as e:
        logger.error(f"Failed to start application: {str(e)}")
        print(f"Error: Failed to start application: {str(e)}")