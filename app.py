import csv
import os
import json
from datetime import datetime
from flask import Flask, render_template, redirect, url_for, request, flash, jsonify, send_file, Response, make_response, render_template_string, abort
from tinydb import TinyDB, Query
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_bcrypt import Bcrypt
from weasyprint import HTML  # For PDF generation
from collections import defaultdict
from datetime import datetime, timedelta
import io
from functools import wraps
from werkzeug.utils import secure_filename
from datetime import datetime

delivery_log = TinyDB('delivery_log.json')
return_log = TinyDB("return_log.json")

# Initialize Flask App
app = Flask(__name__)
app.secret_key = "your_secret_key"  # Change this to a strong secret key
bcrypt = Bcrypt(app)

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

# -------------------- Database Setup --------------------
db = TinyDB('database.json')
Item = Query()
USER_DB_FILE = "users.json"

# -------------------- Logging System --------------------
def log_inventory_action(action_type, item_name, username, note=""):
    now = datetime.now()
    log_entry = {
        "item": item_name,
        "action": action_type,
        "user": username,
        "reason": note,
        "date": now.strftime("%d-%m-%Y"),
        "time": now.strftime("%H:%M:%S")
    }

    try:
        with open("logs.json", "r") as file:
            logs = json.load(file)
    except (FileNotFoundError, json.JSONDecodeError):
        logs = []

    logs.append(log_entry)

    with open("logs.json", "w") as file:
        json.dump(logs, file, indent=4)


@app.route('/activity_log')
@login_required
def activity_log():
    if current_user.role != "admin":
        return render_template("access_denied.html")

    try:
        with open("logs.json", "r") as file:
            logs = json.load(file)
    except (FileNotFoundError, json.JSONDecodeError):
        logs = []

    logs = sorted(logs, key=lambda x: x["timestamp"], reverse=True)  # Latest first
    return render_template("activity_log.html", logs=logs)

# -------------------- Delivery Log --------------------
def log_delivery(item_name, quantity, address, status, driver_id):
    delivery_log.insert({
        "item_name": item_name,
        "quantity": quantity,
        "address": address,
        "status": status,  # delivered or returned
        "date": datetime.today().strftime('%d-%m-%Y'),
        "time": datetime.now().strftime('%H:%M:%S'),
        "driver_id": driver_id
    })

# -------------------- Access based Roles --------------------
def role_required(*roles):
    def wrapper(f):
        @wraps(f)
        def decorated_view(*args, **kwargs):
            if not current_user.is_authenticated:
                return redirect(url_for('login'))
            if current_user.role not in roles:
                return render_template("access_denied.html")
            return f(*args, **kwargs)
        return decorated_view
    return wrapper

# -------------------- User Management --------------------
def load_users():
    """Loads users from the JSON database."""
    if not os.path.exists(USER_DB_FILE):
        return {}
    with open(USER_DB_FILE, "r") as file:
        return json.load(file)

def save_users(users):
    """Saves users to the JSON database."""
    with open(USER_DB_FILE, "w") as file:
        json.dump(users, file, indent=4)

# Define User Class for Flask-Login
class User(UserMixin):
    def __init__(self, username, role):
        self.id = username
        self.role = role

@login_manager.user_loader
def load_user(username):
    users = load_users()
    if username in users:
        return User(username, users[username]["role"])
    return None

# -------------------- Authentication Routes --------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        users = load_users()

        print(f"Attempting login - Username: {username}")  # Debugging
        print(f"Stored users: {users}")  # Debugging

        if username in users:
            stored_hashed_pw = users[username]["password"]
            print(f"Stored hash: {stored_hashed_pw}")  # Debugging

            if bcrypt.check_password_hash(stored_hashed_pw, password):
                print("Password matched!")  # Debugging
                user = User(username, users[username]["role"])
                login_user(user)
                flash("Login successful!", "success")
                return redirect(url_for("home"))
            else:
                print("Password mismatch!")  # Debugging
        else:
            print("Username not found!")  # Debugging

        flash("Invalid username or password!", "danger")

    return render_template("login.html")

@app.route("/logout")
def logout():
    """Handles user logout."""
    logout_user()
    flash("Logged out successfully.", "info")
    return redirect(url_for("login"))

# -------------------- Admin Panel --------------------
@app.route("/admin", methods=["GET", "POST"])
@login_required  # Ensures only logged-in users can access
@role_required('admin')
def admin():
    """Admin panel for managing users."""
    
    # Ensure user is logged in before checking role
    if not current_user.is_authenticated:
        flash("You must be logged in to access this page.", "danger")
        return redirect(url_for("login"))

    # Ensure only admins can access
    if current_user.role != "admin":
        flash("Access denied! Admins only.", "danger")
        return redirect(url_for("inventory"))

    users = load_users()

    if request.method == "POST":
        new_username = request.form["username"]
        new_password = request.form["password"]
        role = request.form["role"]

        if new_username in users:
            flash("User already exists!", "danger")
        else:
            hashed_pw = bcrypt.generate_password_hash(new_password).decode("utf-8")
            users[new_username] = {"password": hashed_pw, "role": role}
            save_users(users)
            flash("User added successfully!", "success")
    
    return render_template("admin.html", users=users)

@app.route("/remove_user/<username>", methods=["POST"])
@login_required
def remove_user(username):
    """Allows an admin to remove a user's access."""
    if current_user.role != "admin":
        flash("Access denied! Admins only.", "danger")
        return redirect(url_for("admin"))

    users = load_users()

    if username in users:
        del users[username]  # Remove the user from the dictionary
        save_users(users)  # Save the updated users.json
        flash(f"User '{username}' has been removed.", "success")
    else:
        flash("User not found!", "danger")

    return redirect(url_for("admin"))

# -------------------- Product Track Log --------------------
@app.route("/product_track_log")
@login_required
@role_required("admin", "manager")
def product_track_log():
    try:
        with open("logs.json", "r") as file:
            logs = json.load(file)
    except (FileNotFoundError, json.JSONDecodeError):
        logs = []

    return render_template("product_track_log.html", logs=logs)
# -------------------- Inventory Management --------------------
@app.route("/inventory")
@login_required
def inventory():
    sort_by = request.args.get("sort", "name")
    order = request.args.get("order", "asc")
    search_query = request.args.get("search", "").lower()

    items = db.all()

    # Filter by search query
    if search_query:
        items = [item for item in items if search_query in item.get("name", "").lower()]

    # Sorting
    def sort_key(item):
        return item.get(sort_by, "")

    items = sorted(items, key=sort_key, reverse=(order == "desc"))

    return render_template("inventory.html", items=items, sort_by=sort_by, order=order, search_query=search_query)


@app.route('/inventory_stats')
@login_required
def inventory_stats():
    """Returns inventory statistics for the dashboard graphs."""
    try:
        items = db.all()

        # Prepare category stock data
        category_stock = {}
        for item in items:
            category = item.get("category", "Unknown")
            category_stock[category] = category_stock.get(category, 0) + item.get("quantity", 0)

        # Prepare stock trend data
        stock_trend = {}
        for item in items:
            date_added = item.get("date", "Unknown")
            stock_trend[date_added] = stock_trend.get(date_added, 0) + item.get("quantity", 0)

        return jsonify({
            "category_stock": category_stock,
            "stock_trend": stock_trend,
            "low_stock_count": sum(1 for item in items if item.get("quantity", 0) <= item.get("threshold", 0)),
            "low_stock_items": [{"name": item["name"], "quantity": item["quantity"], "last_refilled": item.get("date", "N/A")} for item in items if item.get("quantity", 0) <= item.get("threshold", 0)]
        })

    except Exception as e:
        print("Error in /inventory_stats:", str(e))  # Debugging
        return jsonify({"error": "Failed to load inventory stats"}), 500

@app.route('/monthly_summary')
@login_required
def monthly_summary():
    if current_user.role != "admin":
        return render_template("access_denied.html")
    return render_template('monthly_summary.html')


@app.route('/monthly_summary_data')
@login_required
def monthly_summary_data():
    if current_user.role != "admin":
        return jsonify({"error": "Access denied"}), 403
    try:
        items = db.all()

        # Get current month and year
        today = datetime.today()
        current_month = today.strftime('%m')
        current_year = today.strftime('%Y')

        total_items = 0
        category_count = defaultdict(int)
        trend = defaultdict(int)
        low_stock_items = []
        unique_categories = set()

        for item in items:
            date_str = item.get("date", "")
            try:
                item_date = datetime.strptime(date_str, "%d-%m-%Y")
                if item_date.strftime("%m") == current_month and item_date.strftime("%Y") == current_year:
                    total_items += item.get("quantity", 0)
                    category = item.get("category", "Unknown")
                    unique_categories.add(category)
                    category_count[category] += item.get("quantity", 0)
                    day_label = item_date.strftime("%d-%b")
                    trend[day_label] += item.get("quantity", 0)
            except:
                continue  # Skip if date is invalid

            # Low stock logic (regardless of month)
            if item.get("quantity", 0) <= item.get("threshold", 0):
                low_stock_items.append({
                    "name": item.get("name", ""),
                    "quantity": item.get("quantity", 0),
                    "threshold": item.get("threshold", 0),
                    "date": item.get("date", "N/A")
                })

        return jsonify({
            "total_items": total_items,
            "unique_categories": len(unique_categories),
            "low_stock_count": len(low_stock_items),
            "low_stock_items": low_stock_items,
            "category_data": category_count,
            "trend_data": trend
        })

    except Exception as e:
        print("Error in /monthly_summary_data:", str(e))
        return jsonify({"error": "Could not process summary data"}), 500

@app.route("/add_item_web", methods=["POST"])
@login_required
@role_required('admin', 'manager', 'receiving_clerk', 'putaway_specialist')
def add_item_web():
    """Handles adding new inventory items."""
    name = request.form.get("name")
    quantity = int(request.form.get("quantity"))
    category = request.form.get("category")
    threshold = int(request.form.get("threshold"))
    date_added = datetime.today().strftime('%d-%m-%Y')
    time_added = datetime.now().strftime('%H:%M:%S')

    if db.search(Item.name == name):
        return "Error: Item already exists!", 400

    db.insert({
        "name": name,
        "quantity": quantity,
        "category": category,
        "threshold": threshold,
        "date": date_added,
        "time": time_added,
        "status": "received"
    })
    log_inventory_action("add", name, current_user.id) # Logging the action
    return redirect(url_for('inventory'))

@app.route("/update_item_web/<name>", methods=["GET", "POST"])
@login_required
@role_required("admin", "manager")
def update_item_web(name):
    item = db.get(Item.name == name)
    if not item:
        return "Error: Item not found!", 404

    if request.method == 'GET':
        return render_template('update.html', item=item)

    elif request.method == 'POST':
        new_name = request.form.get("name").strip()
        quantity = request.form.get("quantity").strip()
        category = request.form.get("category").strip()
        location = request.form.get("location").strip()
        status = request.form.get("status")

        if not quantity.isdigit():
            return "Error: Quantity must be a number!", 400

        updated_date = datetime.today().strftime('%d-%m-%Y')
        updated_time = datetime.now().strftime('%H:%M:%S')

        # Update item fields
        db.update({
            "name": new_name,
            "quantity": int(quantity),
            "category": category,
            "location": location,
            "status": status,
            "date": updated_date,
            "time": updated_time
        }, Item.name == name)

        log_inventory_action("update", new_name, current_user.id)
        return redirect(url_for('inventory'))


@app.route("/delete_item/<name>", methods=["POST"])
@login_required
@role_required('admin', 'manager')
def delete_item(name):
    """Handles deleting inventory items."""
    db.remove(Item.name == name)
    return redirect(url_for('inventory'))
# -------------------- ORDER-ID --------------------
def generate_order_id():
    today = datetime.now().strftime("%Y%m%d")
    existing_orders = db.search(Item.date == datetime.now().strftime("%d-%m-%Y"))
    order_count = len({entry.get("order_id") for entry in existing_orders if entry.get("order_id")})
    next_seq = str(order_count + 1).zfill(3)
    return f"ORD-{today}-{next_seq}"

# -------------------- Receiving Clerk — Scan & Validate Deliveries --------------------
@app.route("/receiving", methods=["GET", "POST"])
@login_required
@role_required("receiving_clerk")
def receiving():
    if request.method == "POST":
        item_name = request.form["name"]
        quantity = int(request.form["quantity"])
        category = request.form.get("category", "N/A")
        storage = request.form.get("storage_location", "N/A")

        now = datetime.now()
        date = now.strftime("%d-%m-%Y")
        time = now.strftime("%H:%M:%S")

        # ✅ Generate Order ID
        order_id = generate_order_id()
        print("✅ Generated Order ID:", order_id)

        # ✅ Insert item with order_id
        db.insert({
            "name": item_name,
            "quantity": quantity,
            "category": category,
            "storage_location": storage,
            "status": "received",
            "date": date,
            "time": time,
            "order_id": order_id
        })

        flash(f"Item '{item_name}' added successfully under Order ID: {order_id}", "success")
        return redirect(url_for("receiving"))

    return render_template("receiving.html")


# -------------------- Putaway Specialist – Store Items into Assigned Slots --------------------
@app.route("/putaway", methods=["GET", "POST"])
@login_required
@role_required("putaway_specialist")
def putaway():
    uncategorized_items = db.search(Item.category == "Uncategorized")

    if request.method == "POST":
        item_name = request.form.get("name")
        new_category = request.form.get("category")
        location = request.form.get("location")

        db.update({"category": new_category, "location": location, "status": "ready"}, Item.name == item_name)
        log_inventory_action("putaway", item_name, current_user.id)
        return redirect(url_for("putaway"))

    return render_template("putaway.html", items=uncategorized_items)

# -------------------- Order Picker — View Pick List & Mark Items as Picked --------------------
@app.route("/pick_items", methods=["GET", "POST"])
@login_required
@role_required("order_picker")
def pick_items():
    ready_items = db.search(Item.status == "ready")

    if request.method == "POST":
        item_name = request.form.get("name")
        db.update({"status": "picked"}, Item.name == item_name)
        log_inventory_action("picked", item_name, current_user.id)
        return redirect(url_for("pick_items"))

    return render_template("pick_items.html", items=ready_items)

# -------------------- Packer — Pack and Label Picked Items --------------------
@app.route("/pack_items", methods=["GET", "POST"])
@login_required
@role_required("packer")
def pack_items():
    picked_items = db.search(Item.status == "picked")

    if request.method == "POST":
        item_name = request.form.get("name")
        db.update({"status": "packed"}, Item.name == item_name)
        log_inventory_action("packed", item_name, current_user.id)
        return redirect(url_for("pack_items"))

    return render_template("pack_items.html", items=picked_items)

# -------------------- Shipping Coordinator — Confirm Dispatch --------------------
@app.route("/ship_items", methods=["GET", "POST"])
@login_required
@role_required("shipping_coordinator")
def ship_items():
    packed_items = db.search(Item.status == "packed")

    if request.method == "POST":
        item_id = int(request.form.get('item_id'))
        assigned_quantity = int(request.form.get('assigned_quantity', 0))
        address = request.form.get('address', '').strip()

        item = db.get(doc_id=item_id)
        if item:
            available_qty = int(item.get("quantity", 0))
            if 0 < assigned_quantity <= available_qty:
                db.update({
                    "assigned_quantity": assigned_quantity,
                    "address": address,
                    "status": "shipped",
                    "date": datetime.today().strftime('%d-%m-%Y'),
                    "time": datetime.now().strftime('%H:%M:%S')
                }, doc_ids=[item_id])
                log_inventory_action("shipped", item.get("name"), current_user.id)
                flash(f"Item '{item.get('name')}' shipped with {assigned_quantity} units to '{address}'.", "success")
            else:
                flash("Assigned quantity exceeds available quantity.", "danger")
        else:
            flash("Item not found.", "danger")

        return redirect(url_for("ship_items"))

    return render_template("ship_items.html", items=packed_items)


# -------------------- Delivery Driver — View Shipped Items & Mark as Delivered --------------------
@app.route('/deliveries', methods=['GET', 'POST'])
@login_required
@role_required('delivery_driver')
def deliveries():
    if request.method == 'POST':
        item_id = int(request.form.get('item_id'))
        action = request.form.get('action')
        reason = request.form.get('reason', '').strip()

        item = db.get(doc_id=item_id)
        if item and item.get("status") == "shipped":
            current_qty = int(item.get("quantity", 0))
            assigned_qty = int(item.get("assigned_quantity", 0))

            if action == "delivered":
                if assigned_qty <= current_qty:
                    db.update({
                        "quantity": current_qty - assigned_qty,
                        "status": "delivered",
                        "date": datetime.today().strftime('%d-%m-%Y'),
                        "time": datetime.now().strftime('%H:%M:%S')
                    }, doc_ids=[item_id])

                    log_delivery(item["name"], assigned_qty, item.get("address", ""), "delivered", current_user.id)
                    log_inventory_action("delivered", item["name"], current_user.id)
                    flash(f"Item '{item['name']}' delivered successfully.", "success")
                else:
                    flash("Assigned quantity exceeds available stock.", "danger")

            elif action == "returned":
                db.update({
                    "status": "returned",
                    "return_reason": reason,
                    "date": datetime.today().strftime('%d-%m-%Y'),
                    "time": datetime.now().strftime('%H:%M:%S')
                }, doc_ids=[item_id])

                log_delivery(item["name"], assigned_qty, item.get("address", ""), "returned", current_user.id)
                log_inventory_action("returned", item["name"], current_user.id, reason)
                flash(f"Item '{item['name']}' marked as returned. Reason: {reason}", "warning")

            else:
                flash("Invalid action selected.", "danger")
        else:
            flash("Item not found or not marked as shipped.", "danger")

        return redirect(url_for('deliveries'))

    items = db.search(Item.status == "shipped")
    return render_template('deliveries.html', items=items)

# -------------------- Delivery History --------------------
@app.route("/delivery_history")
@login_required
@role_required("admin", "manager", "shipping_coordinator")
def delivery_history():
    history = delivery_log.all()
    print("Delivery Log History:", history)
    return render_template("delivery_history.html", history=history)


# -------------------- Returns Processor — Log Returns & Restock --------------------
@app.route('/returns', methods=['GET', 'POST'])
@login_required
@role_required('returns_processor')
def returns():
    if request.method == 'POST':
        
        item_id = int(request.form.get('item_id'))
        action = request.form.get('action')
        reason = request.form.get("reason", "")

        item = db.get(doc_id=item_id)
        if item and item.get("status") == "returned":
            if action == "restock":
                db.update({
                    "quantity": int(item["quantity"]) + int(item.get("assigned_quantity", 0)),
                    "status": "available",  # or "received" or whatever you use
                    "return_reason": "",
                    "assigned_quantity": 0
                }, doc_ids=[item_id])
                log_inventory_action("restocked", item["name"], current_user.id)
                flash(f"Item '{item['name']}' restocked successfully.", "success")

            elif action == "damaged":
                db.update({
                    "status": "damaged",
                    "return_reason": item.get("return_reason", "")
                }, doc_ids=[item_id])
                log_inventory_action("damaged", item["name"], current_user.id)
                flash(f"Item '{item['name']}' marked as damaged.", "danger")
            else:
                flash("Invalid action selected.", "danger")
            
            # ✅ Log this return to the return log
            return_log.insert({
                "item_name": item["name"],
                "quantity": item.get("assigned_quantity", 0),
                "return_reason": reason,
                "action": action,
                "date": datetime.today().strftime('%d-%m-%Y'),
                "time": datetime.now().strftime('%H:%M:%S'),
                "user_id": current_user.id
            })    

        return redirect(url_for('returns'))

    items = db.search(Item.status == "returned")
    return render_template("returns.html", items=items)

# -------------------- Return History --------------------
@app.route("/return_history")
@login_required
@role_required("admin", "manager", "returns_processor")
def return_history():
    history = return_log.all()  # assuming return_log = TinyDB("return_log.json")
    return render_template("return_history.html", history=history)

# --------------------Inventory Control Specialist — Manual Adjustments --------------------
@app.route("/adjust_inventory", methods=["GET", "POST"])
@login_required
@role_required("inventory_auditor")
def adjust_inventory():
    all_items = db.all()

    if request.method == "POST":
        item_name = request.form.get("name")
        qty = int(request.form.get("quantity"))
        operation = request.form.get("operation")
        reason = request.form.get("reason")

        current_item = db.get(Item.name == item_name)
        if not current_item:
            return redirect(url_for("adjust_inventory"))

        if operation == "add":
            new_qty = current_item["quantity"] + qty
        else:
            new_qty = max(current_item["quantity"] - qty, 0)

        db.update({"quantity": new_qty}, Item.name == item_name)
        log_inventory_action(f"{operation} {qty} ({reason})", item_name, current_user.id)
        return redirect(url_for("adjust_inventory"))

    return render_template("adjust_inventory.html", items=all_items)


@app.route("/cycle_count", methods=["GET", "POST"])
@login_required
@role_required("inventory_auditor")
def cycle_count():
    all_items = db.all()
    mismatches = []

    if request.method == "POST":
        item_name = request.form.get("name")
        counted_qty = int(request.form.get("counted_quantity"))

        item = db.get(Item.name == item_name)
        if item:
            if item["quantity"] != counted_qty:
                mismatches.append({
                    "name": item["name"],
                    "system_qty": item["quantity"],
                    "counted_qty": counted_qty
                })
            log_inventory_action(f"cycle count: counted {counted_qty}", item_name, current_user.id)

    return render_template("cycle_count.html", items=all_items, mismatches=mismatches)

# -------------------- Maintenance Technician — Equipment Maintenance --------------------
db_maintenance = TinyDB("maintenance_log.json")

@app.route("/maintenance", methods=["GET", "POST"])
@login_required
@role_required("maintenance_technician")
def maintenance():
    # Sample equipment list
    equipment_list = [
        {"id": 1, "name": "Conveyor Belt"},
        {"id": 2, "name": "Packing Arm"},
        {"id": 3, "name": "Barcode Scanner"},
        {"id": 4, "name": "Automated Rack Lifter"}
    ]

    if request.method == "POST":
        equipment_id = request.form.get("equipment_id")
        status = request.form.get("status")
        note = request.form.get("note", "")
        timestamp = datetime.now().strftime("%d-%m-%Y %H:%M:%S")

        db_maintenance.insert({
            "equipment_id": equipment_id,
            "status": status,
            "note": note,
            "timestamp": timestamp,
            "updated_by": current_user.id
        })

        return redirect(url_for("maintenance"))

    # Retrieve logs for viewing
    logs = db_maintenance.all()
    return render_template("maintenance.html", equipment=equipment_list, logs=logs)

# -------------------- Safety Supervisor — Safety Incident Log --------------------
db_safety = TinyDB("safety_log.json")

@app.route("/safety_log", methods=["GET", "POST"])
@login_required
@role_required("safety_supervisor")
def safety_log():
    if request.method == "POST":
        incident_type = request.form.get("incident_type")
        severity = request.form.get("severity")
        note = request.form.get("note", "")
        timestamp = datetime.now().strftime("%d-%m-%Y %H:%M:%S")

        db_safety.insert({
            "incident_type": incident_type,
            "severity": severity,
            "note": note,
            "timestamp": timestamp,
            "logged_by": current_user.id
        })
        return redirect(url_for("safety_log"))

    logs = db_safety.all()
    return render_template("safety_log.html", logs=logs)


# -------------------- Product Tracking --------------------
@app.route("/product_track")
@login_required
@role_required("admin", "manager", "shipping_coordinator")
def product_track():
    logs = db_log.all()
    return render_template("product_track.html", logs=logs)

# -------------------- Track Item --------------------
@app.route("/track_item")
@login_required
@role_required("admin", "manager")
def track_item():
    items = db.all()
    return render_template("track_item.html", items=items)

# -------------------- Trend Predction Data --------------------

@app.route('/trend_prediction_data')
@login_required
def trend_prediction_data():
    if current_user.role != "admin" and current_user.role != "manager":
        return jsonify({"error": "Access denied"}), 403

    try:
        items = db.all()

        # Last 3 months + 1 future month
        today = datetime.today()
        months = [(today.replace(day=1) - timedelta(days=30 * i)).strftime("%b-%Y") for i in reversed(range(3))]
        next_month = (today.replace(day=28) + timedelta(days=4)).replace(day=1)
        months.append(next_month.strftime("%b-%Y"))  # predicted demand month

        # {item_name: {month: total quantity used}}
        item_monthly_totals = defaultdict(lambda: defaultdict(int))

        for item in items:
            date_str = item.get("date", "")
            try:
                item_date = datetime.strptime(date_str, "%d-%m-%Y")
                month_key = item_date.strftime("%b-%Y")

                if month_key in months:
                    item_name = item.get("name", "Unknown").strip()
                    item_monthly_totals[item_name][month_key] += item.get("quantity", 0)
            except:
                continue

        prediction_data = {}

        for item_name, month_data in item_monthly_totals.items():
            # Get usage history
            history = [month_data.get(month, 0) for month in months[:-1]]  # past 3 months

            if len(history) >= 3:
                # WMA = (m1*1 + m2*2 + m3*3) / (1+2+3) = /6
                wma = round((history[0]*1 + history[1]*2 + history[2]*3) / 6)
                predicted_demand = wma
            elif len(history) == 2:
                # Weighted average for 2 months: (m1*1 + m2*2) / 3
                predicted_demand = round((history[0]*1 + history[1]*2) / 3)
            elif len(history) == 1:
                predicted_demand = history[0]
            else:
                predicted_demand = 0

            # Fill missing months
            for m in months[:-1]:
                if m not in month_data:
                    month_data[m] = 0

            # Add predicted month
            month_data[months[-1]] = predicted_demand

            # Get actual stock from DB
            current_item = db.get(Item.name.test(lambda n: n.strip().lower() == item_name.strip().lower()))
            current_qty = int(current_item.get("quantity", 0)) if current_item else 0

            # Predicted Stock = Next month forecasted demand
            month_data["Predicted Stock"] = predicted_demand

            # Restock Needed = forecasted demand - current stock
            restock_needed = max(predicted_demand - current_qty, 0)
            month_data["Restock Needed"] = restock_needed

            # Final sort with all 2 new columns at the end
            all_columns = months + ["Predicted Stock", "Restock Needed"]
            sorted_month_data = {month: month_data.get(month, 0) for month in all_columns}

            prediction_data[item_name] = sorted_month_data

        # Step 3: ABC Classification
        abc_data = []
        for name, data in prediction_data.items():
            demand = data.get("Predicted Stock", 0)
            abc_data.append((name, demand))

        # Sort items by predicted demand (descending)
        abc_data.sort(key=lambda x: x[1], reverse=True)
        total_demand = sum(x[1] for x in abc_data)

        a_limit = total_demand * 0.70
        b_limit = total_demand * 0.90

        cumulative = 0
        abc_map = {}

        for name, demand in abc_data:
            cumulative += demand
            if cumulative <= a_limit:
                abc_map[name] = "A"
            elif cumulative <= b_limit:
                abc_map[name] = "B"
            else:
                abc_map[name] = "C"

        # Add ABC classification to prediction_data
        for name in prediction_data:
            prediction_data[name]["ABC Class"] = abc_map.get(name, "C")  # Default to C


        # Filter high-priority restock alerts
        alert_items = []
        for name, data in prediction_data.items():
            restock = data.get("Restock Needed", 0)
            abc = data.get("ABC Class", "C")
            if restock > 0 and abc in ["A", "B"]:
                alert_items.append({
                    "name": name,
                    "restock": restock,
                    "class": abc
                })

        # Final response
        return jsonify({
            "months": months + ["Predicted Stock", "Restock Needed", "ABC Class"],
            "prediction_data": prediction_data,
            "alert_items": alert_items  # ⬅️ This is new!
        })



    except Exception as e:
        print("Error in /trend_prediction_data:", str(e))
        return jsonify({"error": "Trend prediction failed"}), 500

    
@app.route("/trend_prediction")
@login_required
def trend_prediction():
    if current_user.role != "admin":
        return render_template("access_denied.html")
    return render_template("trend_prediction.html")

# -------------------- ABC counts trend prediciton data --------------------
@app.route('/abc_counts')
@login_required
def get_abc_counts():
    try:
        items = db.all()

        # ABC Classification calculation
        from collections import defaultdict

        today = datetime.today()
        months = [(today.replace(day=1) - timedelta(days=30 * i)).strftime("%b-%Y") for i in reversed(range(3))]
        next_month = (today.replace(day=28) + timedelta(days=4)).replace(day=1)
        months.append(next_month.strftime("%b-%Y"))

        item_monthly_totals = defaultdict(lambda: defaultdict(int))

        for item in items:
            date_str = item.get("date", "")
            try:
                item_date = datetime.strptime(date_str, "%d-%m-%Y")
                month_key = item_date.strftime("%b-%Y")

                if month_key in months:
                    item_name = item.get("name", "Unknown").strip()
                    item_monthly_totals[item_name][month_key] += item.get("quantity", 0)
            except:
                continue

        prediction_data = {}
        for item_name, month_data in item_monthly_totals.items():
            history = [month_data.get(month, 0) for month in months[:-1]]
            if len(history) >= 3:
                wma = round((history[0]*1 + history[1]*2 + history[2]*3) / 6)
                predicted_demand = wma
            elif len(history) == 2:
                predicted_demand = round((history[0]*1 + history[1]*2) / 3)
            elif len(history) == 1:
                predicted_demand = history[0]
            else:
                predicted_demand = 0
            prediction_data[item_name] = predicted_demand

        # ABC Classification
        abc_data = sorted(prediction_data.items(), key=lambda x: x[1], reverse=True)
        total = sum(d for _, d in abc_data)
        a_limit = total * 0.7
        b_limit = total * 0.9

        abc_counts = {"A": 0, "B": 0, "C": 0}
        cumulative = 0
        for _, demand in abc_data:
            cumulative += demand
            if cumulative <= a_limit:
                abc_counts["A"] += 1
            elif cumulative <= b_limit:
                abc_counts["B"] += 1
            else:
                abc_counts["C"] += 1

        return jsonify(abc_counts)

    except Exception as e:
        print("Error in /abc_counts:", e)
        return jsonify({"error": "Failed to calculate ABC counts"}), 500

# -------------------- Add Missing Routes --------------------

@app.route('/add_item_form')
@login_required
def add_item_form():
    """Displays the Add Item page."""
    return render_template('add_item.html')

@app.route('/dashboard')
@login_required
@role_required("admin", "manager")  # Optional: apply your role system if used
def dashboard():
    items = db.all()
    
    # Initialize ABC counts
    abc_counts = {"A": 0, "B": 0, "C": 0}

    for item in items:
        abc = item.get("abc_class", "C")  # fallback to 'C' if not present
        abc_counts[abc] += 1

    return render_template('dashboard.html', abc_counts=abc_counts, items=items)



# -------------------- CSV Export & Import --------------------
@app.route("/export_csv")
@login_required
def export_csv():
    """Exports inventory data as CSV."""
    filename = "inventory_export.csv"
    with open(filename, mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(["Name", "Quantity", "Category", "Threshold", "Date Added", "Last Updated"])
        for item in db.all():
            writer.writerow([item["name"], item["quantity"], item["category"], item["threshold"], item.get("date", "N/A"), item.get("time", "N/A")])
    return send_file(filename, as_attachment=True)

@app.route("/import_csv", methods=["POST"])
@login_required
def import_csv():
    """Imports inventory data from CSV."""
    file = request.files.get('file')
    if not file or file.filename == '':
        return redirect(url_for('inventory'))

    file_path = "uploaded_inventory.csv"
    file.save(file_path)

    with open(file_path, mode='r') as file:
        reader = csv.DictReader(file)
        for row in reader:
            db.insert({
                "name": row["Name"],
                "quantity": int(row["Quantity"]),
                "category": row["Category"],
                "threshold": int(row["Threshold"]),
                "date": row["Date Added"],
                "time": row["Last Updated"]
            })

    os.remove(file_path)
    return redirect(url_for('inventory'))

# -------------------- PDF Report Generation --------------------
@app.route("/generate_pdf")
@login_required
def generate_pdf():
    """Generates an inventory PDF report."""
    items = db.all()
    html_content = render_template("inventory_pdf.html", items=items)
    pdf = HTML(string=html_content).write_pdf()

    response = Response(pdf, content_type='application/pdf')
    response.headers['Content-Disposition'] = 'inline; filename=inventory_report.pdf'
    return response

@app.route("/export_trend_pdf")
@login_required
def export_trend_pdf():
    if current_user.role != "admin":
        return render_template("access_denied.html")

    # Get prediction data
    try:
        from datetime import datetime
        today = datetime.today().strftime("%d-%m-%Y")

        items = db.all()
        months = [(datetime.today().replace(day=1) - timedelta(days=30 * i)).strftime("%b-%Y") for i in reversed(range(3))]
        next_month = (datetime.today().replace(day=28) + timedelta(days=4)).replace(day=1)
        months.append(next_month.strftime("%b-%Y"))

        # Collect item-wise monthly data
        item_monthly_totals = defaultdict(lambda: defaultdict(int))
        for item in items:
            try:
                date_obj = datetime.strptime(item.get("date", ""), "%d-%m-%Y")
                month_key = date_obj.strftime("%b-%Y")
                if month_key in months:
                    name = item.get("name", "Unknown").strip()
                    item_monthly_totals[name][month_key] += item.get("quantity", 0)
            except:
                continue

        prediction_data = {}
        for name, month_data in item_monthly_totals.items():
            history = [month_data.get(m, 0) for m in months[:-1]]
            if len(history) >= 2:
                avg_diff = (history[-1] - history[0]) / 2
                predicted = round(history[-1] + avg_diff)
            else:
                predicted = history[-1] if history else 0

            for m in months[:-1]:
                if m not in month_data:
                    month_data[m] = 0
            month_data[months[-1]] = predicted
            sorted_month_data = {m: month_data[m] for m in months}
            prediction_data[name] = sorted_month_data

        # Render the PDF using a simple HTML table
        rendered_html = render_template("trend_pdf.html", months=months, prediction_data=prediction_data, date=today)
        pdf_file = HTML(string=rendered_html).write_pdf()

        response = make_response(pdf_file)
        response.headers["Content-Type"] = "application/pdf"
        response.headers["Content-Disposition"] = f"inline; filename=Trend_Prediction_{today}.pdf"
        return response

    except Exception as e:
        print("PDF export error:", str(e))
        return "Error generating PDF", 500
    
# -------------------- Log Summary --------------------

@app.route('/log_summary')
@login_required
def log_summary():
    if current_user.role != "admin":
        return render_template("access_denied.html")

    try:
        with open("logs.json", "r") as file:
            logs = json.load(file)
    except (FileNotFoundError, json.JSONDecodeError):
        logs = []

    user_counts = {}
    item_counts = {}

    for log in logs:
        user = log["user"]
        item = log["item"]

        user_counts[user] = user_counts.get(user, 0) + 1
        item_counts[item] = item_counts.get(item, 0) + 1

    total_actions = len(logs)
    most_active_user = max(user_counts, key=user_counts.get, default="N/A")
    most_changed_item = max(item_counts, key=item_counts.get, default="N/A")

    return render_template("log_summary.html", user_counts=user_counts, item_counts=item_counts,
                           total_actions=total_actions,
                           most_active_user=most_active_user,
                           most_changed_item=most_changed_item)


# -------------------- ERP and API Endpoints --------------------
# 🔹 GET all inventory items (with doc_id)
@app.route("/api/inventory", methods=["GET"])
def api_get_inventory():
    items = db.all()
    data = []
    for item in items:
        item_data = item.copy()
        item_data["id"] = item.doc_id
        data.append(item_data)
    return jsonify(data), 200


# 🔹 GET a specific item by doc_id
@app.route("/api/inventory/<int:item_id>", methods=["GET"])
def api_get_item(item_id):
    item = db.get(doc_id=item_id)
    if item:
        item_data = item.copy()
        item_data["id"] = item_id
        return jsonify(item_data), 200
    return jsonify({"error": "Item not found"}), 404


# 🔹 POST (add new item)
@app.route("/api/inventory", methods=["POST"])
def api_add_item():
    data = request.json
    required_fields = ["name", "quantity", "date"]
    
    if not all(field in data for field in required_fields):
        return jsonify({"error": "Missing required fields"}), 400

    doc_id = db.insert(data)
    return jsonify({"message": "Item added", "id": doc_id}), 201


# 🔹 PUT (update an existing item by doc_id)
@app.route("/api/inventory/<int:item_id>", methods=["PUT"])
def api_update_item(item_id):
    if db.contains(doc_id=item_id):
        update_data = request.json
        db.update(update_data, doc_ids=[item_id])
        return jsonify({"message": "Item updated"}), 200
    return jsonify({"error": "Item not found"}), 404


# 🔹 DELETE (remove item by doc_id)
@app.route("/api/inventory/<int:item_id>", methods=["DELETE"])
def api_delete_item(item_id):
    if db.contains(doc_id=item_id):
        db.remove(doc_ids=[item_id])
        return jsonify({"message": "Item deleted"}), 200
    return jsonify({"error": "Item not found"}), 404

# -------------------- Data Ingestion from External Systems --------------------
UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# 🔹 CSV Upload Page (optional form)
@app.route("/upload_csv", methods=["GET", "POST"])
def upload_csv():
    if request.method == "POST":
        file = request.files.get("file")
        
        if not file:
            return "No file uploaded", 400

        if not file.filename.endswith(".csv"):
            return "Invalid file format. Please upload a .csv file.", 400

        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)

        try:
            with open(filepath, newline='', encoding='utf-8') as csvfile:
                reader = csv.DictReader(csvfile)
                for row in reader:
                    db.insert({
                        "name": row.get("name", "").strip(),
                        "quantity": int(row.get("quantity", 0)),
                        "date": row.get("date", ""),
                        "category": row.get("category", "uncategorized"),
                        "status": row.get("status", "received")
                    })
        except Exception as e:
            return f"Error processing file: {str(e)}", 500

        return "✅ CSV data uploaded and added to inventory!"

    # GET: show simple upload form
    return '''
        <h2>📤 Upload Inventory CSV</h2>
        <form method="POST" enctype="multipart/form-data">
            <input type="file" name="file" accept=".csv">
            <button type="submit">Upload</button>
        </form>
    '''

# -------------------- TinyDB Databases --------------------
db = TinyDB("database.json")
db_log = TinyDB("log.json")

# -------------------- Logging Utilities --------------------
def log_equipment_action(action, item_id):
    print(f"[{datetime.now().strftime('%H:%M:%S')}] Equipment: {action.upper()} Item ID {item_id}")

def log_api_event(action_type, message, item_id=None):
    db_log.insert({
        "timestamp": datetime.now().strftime("%d-%m-%Y %H:%M:%S"),
        "type": action_type,
        "message": message,
        "item_id": item_id
    })

# -------------------- API TOKEN SETUP --------------------
API_TOKEN = "supersecrettoken123"  # 🔐 Replace with your own secret

# -------------------- Token Decorator --------------------
def require_api_token(func):
    @wraps(func)
    def decorated_function(*args, **kwargs):
        token = request.headers.get("X-API-Token")
        if not token or token != API_TOKEN:
            return jsonify({"error": "Unauthorized. Invalid or missing API token."}), 403
        return func(*args, **kwargs)
    return decorated_function

# -------------------- Logging DB --------------------
db = TinyDB("database.json")
db_log = TinyDB("log.json")

# -------------------- Logging Utilities --------------------
def log_equipment_action(action, item_id):
    print(f"[{datetime.now().strftime('%H:%M:%S')}] Equipment: {action.upper()} Item ID {item_id}")

def log_api_event(action_type, message, item_id=None):
    db_log.insert({
        "timestamp": datetime.now().strftime("%d-%m-%Y %H:%M:%S"),
        "type": action_type,
        "message": message,
        "item_id": item_id
    })

# -------------------- API: PICK ITEM --------------------
@app.route("/api/equipment/pick_item", methods=["POST"])
@require_api_token
def api_pick_item():
    data = request.json
    item_id = data.get("item_id")
    if not item_id or not db.contains(doc_id=item_id):
        return jsonify({"error": "Item not found"}), 404
    db.update({"status": "picked"}, doc_ids=[item_id])
    log_equipment_action("pick", item_id)
    log_api_event("equipment", "Picked item via robot", item_id)
    return jsonify({"message": f"Item {item_id} picked successfully"}), 200

# -------------------- API: STORE ITEM --------------------
@app.route("/api/equipment/store_item", methods=["POST"])
@require_api_token
def api_store_item():
    data = request.json
    item_id = data.get("item_id")
    if not item_id or not db.contains(doc_id=item_id):
        return jsonify({"error": "Item not found"}), 404
    db.update({"status": "stored"}, doc_ids=[item_id])
    log_equipment_action("store", item_id)
    log_api_event("equipment", "Stored item via system", item_id)
    return jsonify({"message": f"Item {item_id} stored successfully"}), 200

# -------------------- API: PACK ITEM --------------------
@app.route("/api/equipment/pack_item", methods=["POST"])
@require_api_token
def api_pack_item():
    data = request.json
    item_id = data.get("item_id")
    if not item_id or not db.contains(doc_id=item_id):
        return jsonify({"error": "Item not found"}), 404
    db.update({"status": "packed"}, doc_ids=[item_id])
    log_equipment_action("pack", item_id)
    log_api_event("equipment", "Packed item via system", item_id)
    return jsonify({"message": f"Item {item_id} packed successfully"}), 200

# -------------------- API: IMPORT JSON --------------------
@app.route("/api/import_json", methods=["POST"])
@require_api_token
def api_import_json():
    try:
        data = request.json
        if not isinstance(data, list):
            return jsonify({"error": "JSON must be a list of items"}), 400

        inserted = 0
        for item in data:
            if all(k in item for k in ["name", "quantity", "date"]):
                db.insert({
                    "name": item["name"],
                    "quantity": int(item["quantity"]),
                    "date": item["date"],
                    "category": item.get("category", "uncategorized"),
                    "status": item.get("status", "received")
                })
                inserted += 1

        log_api_event("data_import", f"Bulk JSON import - {inserted} items")
        return jsonify({"message": f"{inserted} items imported successfully"}), 201

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# -------------------- API: VIEW LOGS --------------------
@app.route("/api/logs", methods=["GET"])
@require_api_token
def get_logs():
    return jsonify(db_log.all()), 200
# -------------------- Home Page --------------------
@app.route("/")
def home():
    """Redirects users to login page if not logged in, else show home."""
    if not current_user.is_authenticated:
        return redirect(url_for("login"))
    return render_template("home.html")


if __name__ == "__main__":
    app.run(debug=True)
