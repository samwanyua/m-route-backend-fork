from flask import Flask, request, make_response, jsonify
from flask_restful import Api
from flask_bcrypt import Bcrypt
from flask_migrate import Migrate
from flask_restful import Api
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity
from sqlalchemy.exc import IntegrityError
from models import db
from datetime import datetime, timezone, timedelta
from flask_cors import CORS
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash
import os
import re


from models import User,  RoutePlan, Location, Outlet, Notification, ActivityLog

load_dotenv()

app = Flask(__name__)

app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("SQLALCHEMY_DATABASE_URI")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["JWT_SECRET_KEY"] = os.getenv("SECRET_KEY")


db.init_app(app)
migrate = Migrate(app, db)
jwt = JWTManager(app)

bcrypt = Bcrypt(app)

api = Api(app)
CORS(app)

@app.route('/')
def index():
    return '<h1>Merchandiser Route App</h1>'

def log_activity(action, user_id):
    try:
        new_activity = ActivityLog(
            user_id=user_id,
            action=action
        )
        db.session.add(new_activity)
        db.session.commit()

    except Exception as err:
        db.session.rollback()
        print(f"Failed to log activity. Error: {err}")


@app.route('/signup', methods=['POST'])
def signup():
    data = request.get_json()

    # Confirm if there's data
    if not data:
        return jsonify({
            "message": "Invalid request",
            "successful": False,
            "status_code": 400
            }), 400

    # Extract required fields
    first_name = data.get('first_name')
    middle_name = data.get('middle_name')
    last_name = data.get('last_name')
    national_id_no = data.get('national_id_no')
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')

    # Check for required fields
    if not all([first_name, last_name, national_id_no, username, email, password]):
        return jsonify({
            'message': 'Missing required fields',
            "successful": False,
            "status_code": 400
            }), 400

    # Check if username or email already exist
    if User.query.filter((User.username == username) | (User.email == email)).first():
        return jsonify({
            'message': 'Username or email already exists',
            "successful": False,
            "status_code": 409
            }), 409

    # Extra checks for input data
    if not isinstance(first_name, str) or len(first_name) > 200:
        return jsonify({
            'message': 'First name must be a string and not more than 200 characters',
            "successful": False,
            "status_code": 400
            }), 400

    if middle_name and (not isinstance(middle_name, str) or len(middle_name) > 200):
        return jsonify({
            'message': 'Middle name must be a string and not more than 200 characters',
            "successful": False,
            "status_code": 400
            }), 400

    if not isinstance(last_name, str) or len(last_name) > 200:
        return jsonify({
            'message': 'Last name must be a string and not more than 200 characters',
            "successful": False,
            "status_code": 400
            }), 400

    if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
        return jsonify({
            'message': 'Invalid email address',
            "successful": False,
            "status_code": 400
            }), 400

    if not isinstance(password, str) or len(password) < 6:
        return jsonify({
            'message': 'Password must be a string and at least 6 characters long',
            "successful": False,
            "status_code": 400
            }), 400

    # Check if national ID is an integer
    if not isinstance(national_id_no, int):
        return jsonify({
            'message': 'National ID must be an integer',
            "successful": False,
            "status_code": 400
            }), 400

    # Hash the password before saving it
    hashed_password = generate_password_hash(password)

    # Create new user object
    new_user = User(
        first_name=first_name,
        middle_name=middle_name,
        last_name=last_name,
        national_id_no=national_id_no,
        username=username,
        email=email,
        password=hashed_password,
        role='merchandiser',  # merchandiser or manager or admin
    )

    access_token = create_access_token(identity=new_user.id)

    try:
        db.session.add(new_user)
        db.session.commit()
        log_activity('User signed up', new_user.id)
        return jsonify({
            "successful": True,
            "status_code": 201,
            "access_token": access_token,
            'message': 'User created successfully'
        }), 201

    except Exception as err:
        db.session.rollback()
        return jsonify({
            "message": f"Failed to create user. Error: {err}",
            "successful": False,
            "status_code": 400
            }), 400
    
    
@app.route('/user/users', methods=['GET'])
@jwt_required()
def users():
    users = User.query.all()

    if not users:
        return jsonify({
            "message":"No users found",
            "successful": False,
            "status_code": 404
            }), 404
    
    user_list = []
    for user in users:
        user_info = {
            'id': user.id,
            'first_name': user.first_name,
            'middle_name': user.middle_name,
            'last_name': user.last_name,
            'national_id_no': user.national_id_no,
            'username': user.username,
            'email': user.email,
            'role': user.role,
            'status': user.status,
            'created_at': user.created_at.strftime('%Y-%m-%d %H:%M:%S'),  # Convert to string
            'last_login': user.last_login.strftime('%Y-%m-%d %H:%M:%S'),  # Convert to string
            'last_password_change': user.last_password_change.strftime('%Y-%m-%d %H:%M:%S'),  # Convert to string
        }
        user_list.append(user_info)

    # user_id = get_jwt_identity()

    # log_activity('Viewed user list', user_id)

    return jsonify({
        "successful": True,
        "status_code": 200,
        'users': user_list
        }), 200

@app.route('/user/route-plans', methods=['GET', 'POST'])
@jwt_required()
def route_plan_details():
    if request.method == 'GET':
        route_plans = RoutePlan.query.all()
        if not route_plans:
            return jsonify({
                'message': 'No route plans found',
                "successful": False,
                "status_code": 404
                }), 404

        route_plan_list = []
        for route_plan in route_plans:
            route_plan_info = {
                'id': route_plan.id,
                'merchandiser_id': route_plan.merchandiser_id,
                'manager_id': route_plan.manager_id,
                'date_range': route_plan.date_range,
                'instructions': route_plan.instructions,
                'status': route_plan.status
            }
            route_plan_list.append(route_plan_info)

        user_id = get_jwt_identity()
        log_activity('Viewed merchandiser routes', user_id)

        return jsonify({
            "successful": True,
            "status_code": 200,
            'route_plans': route_plan_list
            }), 200

    elif request.method == 'POST':
        data = request.get_json()
        if not data:
            return jsonify({
                "message": "Invalid request, JSON data required",
                "successful": False,
                "status_code": 400
                }), 400

        # Extract required fields from the JSON data
        merchandiser_id = data.get('merchandiser_id')
        manager_id = data.get('manager_id')
        date_range = data.get('date_range')
        instructions = data.get('instructions')
        status = data.get('status')

        # Check for required fields
        if not all([merchandiser_id, manager_id, date_range, status]):
            return jsonify({
                'message': 'Missing required fields',
                "successful": False,
                "status_code": 400
                }), 400
        
        # Check if data adheres to model specifications
        if not isinstance(merchandiser_id, int) or not isinstance(manager_id, int):
            return jsonify({
                'message': 'Merchandiser ID and Manager ID must be integers',
                "successful": False,
                "status_code": 400
                }), 400

        if not isinstance(date_range, str) or len(date_range) > 20:
            return jsonify({
                'message': 'Date range must be a string and not exceed 20 characters',
                "successful": False,
                "status_code": 400
                }), 400

        if instructions and not isinstance(instructions, str):
            return jsonify({
                'message': 'Instructions must be a string',
                "successful": False,
                "status_code": 400
                }), 400

        if status not in ['complete', 'pending']:
            return jsonify({
                'message': 'Status must be either "complete" or "pending"',
                "successful": False,
                "status_code": 400
                }), 400


        # Create a new route plan object
        new_route_plan = RoutePlan(
            merchandiser_id=merchandiser_id,
            manager_id=manager_id,
            date_range=date_range,
            instructions=instructions,
            status=status
        )

        try:
            db.session.add(new_route_plan)
            db.session.commit()

            user_id = get_jwt_identity()
            log_activity('Created merchandiser routes', user_id)
            return jsonify({
                'message': 'Route plan created successfully',
                "successful": True,
                "status_code": 201
                }), 201
        except Exception as err:
            db.session.rollback()
            return jsonify({
                'error': f"Internal server error. Error: {err}",
                "successful": False,
                "status_code": 500
                }), 500

@app.route('/user/route-plans/<int:route_plan_id>', methods=['PUT'])
@jwt_required()
def update_route_plan(route_plan_id):
    data = request.get_json()

    route_plan = db.session.get(RoutePlan, route_plan_id)
    if not route_plan:
        return jsonify({'message': 'Route plan not found'}), 404
    
    # Check if data adheres to model specifications
    if 'merchandiser_id' in data:
        if not isinstance(data['merchandiser_id'], int):
            return jsonify({
                'message': 'Merchandiser ID must be an integer',
                "successful": False,
                "status_code": 400
                }), 400

    if 'manager_id' in data:
        if not isinstance(data['manager_id'], int):
            return jsonify({
                'message': 'Manager ID must be an integer',
                "successful": False,
                "status_code": 400
                }), 400

    if 'date_range' in data:
        if not isinstance(data['date_range'], str) or len(data['date_range']) > 20:
            return jsonify({
                'message': 'Date range must be a string and not exceed 20 characters',
                "successful": False,
                "status_code": 400
                }), 400

    if 'instructions' in data:
        if not isinstance(data['instructions'], str):
            return jsonify({
                'message': 'Instructions must be a string',
                "successful": False,
                "status_code": 400
                }), 400

    if 'status' in data:
        if data['status'] not in ['complete', 'pending']:
            return jsonify({
                'message': 'Status must be either "complete" or "pending"',
                "successful": False,
                "status_code": 400
                }), 400

    # Update route plan attributes
    route_plan.merchandiser_id = data.get('merchandiser_id', route_plan.merchandiser_id)
    route_plan.manager_id = data.get('manager_id', route_plan.manager_id)
    route_plan.date_range = data.get('date_range', route_plan.date_range)
    route_plan.instructions = data.get('instructions', route_plan.instructions)
    route_plan.status = data.get('status', route_plan.status)

    try:
        db.session.commit()

        user_id = get_jwt_identity()
        log_activity(f'Edited merchandiser route. Route id : {route_plan_id}', user_id)
        return jsonify({
            'message': 'Route plan updated successfully',
            "successful": True,
            "status_code": 200
            }), 200

    except Exception as err:

        db.session.rollback()
        return jsonify({
            'message': f"Internal server error. Error: {err}",
            "successful": False,
            "status_code": 500
            }), 500
    
@app.route('/user/locations', methods=['GET', 'POST'])
@jwt_required()
def location_details():
    if request.method == 'GET':
        locations = Location.query.all()
        if not locations:
            return jsonify({
                'message': 'No locations found',
                "successful": False,
                "status_code": 404
                }), 404

        location_list = []
        for location in locations:
            location_info = {
                'id': location.id,
                'merchandiser_id': location.merchandiser_id,
                'timestamp': location.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                'latitude': location.latitude,
                'longitude': location.longitude
            }
            location_list.append(location_info)

        user_id = get_jwt_identity()
        log_activity('Added location', user_id)

        return jsonify({
            "successful": True,
            "status_code": 200,
            'locations': location_list}), 200
    
    elif request.method == 'POST':
        data = request.get_json()

        # Extract required fields from the JSON data
        merchandiser_id = data.get('merchandiser_id')
        latitude = data.get('latitude')
        longitude = data.get('longitude')

        # Check for required fields
        if not all([merchandiser_id, latitude, longitude]):
            return jsonify({
                'message': 'Missing required fields',
                "successful": False,
                "status_code": 400
                }), 400
        
        # Check data types and range
        try:
            merchandiser_id = int(merchandiser_id)
            latitude = float(latitude)
            longitude = float(longitude)
        except ValueError:
            return jsonify({
                'message': 'Invalid data format',
                "successful": False,
                "status_code": 400
                }), 400

        # Check latitude and longitude range
        if not (-90 <= latitude <= 90) or not (-180 <= longitude <= 180):
            return jsonify({
                'message': 'Invalid latitude or longitude values',
                "successful": False,
                "status_code": 400
                }), 400

        # Create a new location object
        new_location = Location(
            merchandiser_id=merchandiser_id,
            timestamp=datetime.now(timezone.utc),
            latitude=latitude,
            longitude=longitude
        )

        try:
            db.session.add(new_location)
            db.session.commit()

            user_id = get_jwt_identity()
            log_activity('Added location', user_id)

            return jsonify({
                'message': 'Location created successfully',
                "successful": True,
                "status_code": 201
                }), 201
        
        except Exception as err:
            db.session.rollback()
            return jsonify({
                'message': f"Internal server error. Error: {err}",
                "successful": False,
                "status_code": 500
                }), 500
        

@app.route("/user/login", methods=["POST"])
def login_user():

    data = request.get_json()

    
    if not data:
        return jsonify({
            "message": "Invalid request",
            "successful": False,
            "status_code": 400
            }), 400
    
    email = data.get("email")
    password = data.get("password_hash")

    
    if not email or not password:
        return jsonify({
            "message": "Email and password required",
            "successful": False,
            "status_code": 400
            }), 400
    
    user = User.query.filter_by(email=email).first()

    
    if user:

        user_id = user.id

        if user.status == "blocked":
            
            return jsonify({
                "message": "Access denied, please contact system administrator",
                "successful": False,
                "status_code": 409
                }), 409
        
    
        if bcrypt.check_password_hash(user.password, password):

            if datetime.now(timezone.utc) - user.last_password_change.replace(tzinfo=timezone.utc) > timedelta(days=14):
                
                return jsonify({
                    "message": "Your password has expired. Please change it.",
                    "successful": False,
                    "status_code": 403
                    }), 403
            

            user_data = {
                "user_id": user.id,
                "role": user.role,
                "username": user.username,
                "email": user.email,
                "last_name": user.last_name,
                "avatar": user.avatar,
                "last_login": datetime.now(timezone.utc).isoformat()
                         }
            
            access_token = create_access_token(identity=user_data)
            user.last_login = datetime.now(timezone.utc)
            db.session.commit()

            

            log_activity(f'Logged in', user_id)
            return jsonify({
                "successful": True,
                "status_code": 201,
                "access_token": access_token,
                "message": "Login successful"
                            }), 201
        
        else:
            return jsonify({
                "message": "Invalid credentials",
                "successful": False,
                "status_code": 401
                }), 401
    else:
        return jsonify({
            "messager": "User not found",
            "successful": False,
            "status_code": 404
            }), 404
    
@app.route("/user/change-password", methods=["PUT"])
def change_password():
    
    data = request.get_json()

    if not data:
        return jsonify({"error": "Invalid request"}), 400
    
    old_password = data.get("old_password")
    new_password = data.get("new_password")
    email = data.get("email")
     

    if old_password == new_password:
        return jsonify({"message": "Old password and new password cannot be the same."}), 400

    if not old_password or not new_password or not email:
        return jsonify({"error": "Missing required fields."}), 400
    
    if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
        return jsonify({'message': 'Invalid email address'}), 400

    if not isinstance(old_password, str) or len(old_password) < 6:
        return jsonify({'message': 'Password must be a string and at least 6 characters long'}), 400
    
    if not isinstance(new_password, str) or len(new_password) < 6:
        return jsonify({'message': 'Password must be a string and at least 6 characters long'}), 400

    user = User.query.filter_by(email=email).first()
    

    if user:

        user_id = user.id

        if bcrypt.check_password_hash(user.password, old_password):

            hashed_new_password = bcrypt.generate_password_hash(new_password).decode('utf-8')

            user.password = hashed_new_password
            user.last_password_change = datetime.now(timezone.utc)
            db.session.commit()
            user_id = user_id

            log_activity(f'Changed password.', user_id)
            return jsonify({"message": "Password changed successfully"}), 201
        
        else:
            return jsonify({"error": "Invalid old password"}), 401
    else:
        return jsonify({"error": "User not found"}), 404


@app.route("/user/edit-profile-image/<int:id>", methods=["PUT"])
@jwt_required()
def edit_user_image(id):
    
    data = request.get_json()

    if not data:

        return jsonify({"message": "Invalid request"}), 400
    
    new_avatar = data.get("avatar")

    # Check if avatar data is provided and is of type bytes
    if new_avatar is not None and not isinstance(new_avatar, bytes):
        return jsonify({"message": "Avatar data must be in bytes format (BYTEA)"}), 400

    user = User.query.get(id)

    if user:
        
        user.avatar = new_avatar

        try:
            db.session.commit()
            log_activity('Change profile image', id)
            return jsonify({"message": "Profile image updated successfully"}), 201
        
        except Exception as e:
            db.session.rollback()
            return jsonify({"error": str(e)}), 500
        
    else:
        return jsonify({"error": "User not found"}), 404
    

@app.route("/user/get-logs", methods=["GET"])
# @jwt_required()
def get_users_activities():

    try:
        activity_logs = ActivityLog.query.all()

        if not activity_logs:
            return jsonify({"message": "No logs available"}), 400

        activity_logs_data = []

        for log in activity_logs:
            log_data = {
                "id": log.id,
                "user_id": log.user_id,
                "action": log.action,
                "timestamp": log.timestamp.strftime('%Y-%m-%d %H:%M:%S') 
            }
            activity_logs_data.append(log_data)
        
        # user_id = get_jwt_identity()
        user_id = 3
        log_activity('Viewed activity logs', user_id)

        return jsonify({"activity_logs": activity_logs_data}), 200
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/user/outlets", methods=["GET", "POST"])
@jwt_required()
def create_and_get_outlet_details():
    
    if request.method == "GET":

        try:
            outlets = Outlet.query.all()

            if not outlets:
                return jsonify({"message": "There are no outlets"}), 400
            
            outlet_list = []

            for outlet in outlets:
                outlet_details = {
                    "id": outlet.id,
                    "name": outlet.name,
                    "address": outlet.address,
                    "contact_info": outlet.contact_info
                }
                outlet_list.append(outlet_details)

            user_id = get_jwt_identity()
            # user_id = 3
            log_activity(f'Created outlet', user_id)

            return jsonify(outlet_list), 200

        except Exception as err:
            return jsonify({"message": f"Error: {err}"}), 500
        
        
    elif request.method == "POST":

        data = request.get_json()

        if not data:
            return jsonify({"message": "Invalid data"}), 400
        
        name = data.get("name")
        address = data.get("address")
        contact_info = data.get("contact_info")

        if not all([name, address, contact_info]):
            return jsonify({"message": "Missing required fields"}), 400
        
        if not isinstance(name, str) or len(name) > 100:
            return jsonify({'message': 'Name must be a string and not more than 100 characters'}), 400
        
        if not isinstance(address, str) or len(address) > 200:
            return jsonify({'message': 'Address must be a string and not more than 200 characters'}), 400
        
        if not isinstance(contact_info, str) or len(contact_info) > 100:
            return jsonify({'message': 'Contact info must be a string and not more than 100 characters'}), 400
        
        new_outlet = Outlet(
            name=name,
            address=address,
            contact_info=contact_info
        )
        
        try:

            db.session.add(new_outlet)
            db.session.commit()

            user_id = get_jwt_identity()
            # user_id = 3
            log_activity(f'Created outlet: {name}', user_id)

            return jsonify({"message": "Outlet created successfully"}), 201

        except Exception as err:

            db.session.rollback()
            return jsonify({"error": f"Error: {err}"}), 500


@app.route("/user/edit-outlet/<int:id>", methods=["PUT"])
@jwt_required()
def edit_outlet_details(id):
    
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "Invalid request"}), 400

        outlet = Outlet.query.get(id)
        
        if not outlet:
            return jsonify({"error": "Outlet not found"}), 404
        
        if 'name' in data:
            if not isinstance(data['name'], str) or len(data['name']) > 100:
                return jsonify({'message': 'Name must be a string and not exceed 100 characters'}), 400
            
        if 'address' in data:
            if not isinstance(data['address'], str) or len(data['address']) > 200:
                return jsonify({'message': 'Address must be a string and not exceed 200 characters'}), 400
            
        if 'contact_info' in data:
            if not isinstance(data['contact_info'], str) or len(data['contact_info']) > 100:
                return jsonify({'message': 'Contact info must be a string and not exceed 100 characters'}), 400

        # Update outlet attributes if provided in the request data
        if 'name' in data:
            outlet.name = data['name']
        if 'address' in data:
            outlet.address = data['address']
        if 'contact_info' in data:
            outlet.contact_info = data['contact_info']

        # Commit the changes to the database
        db.session.commit()

        user_id = get_jwt_identity()
        # user_id = 3
        log_activity('Created outlet', user_id)
        
        return jsonify({"message": "Outlet details updated successfully"}), 201
    
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500


@app.route("/user/notifications", methods=["GET", "POST"])
@jwt_required()
def manage_notifications():
    if request.method == "GET":
        try:
            user_id = get_jwt_identity()
            notifications = Notification.query.filter_by(recipient_id=user_id).all()

            if not notifications:
                return jsonify({"message": "No notifications found"}), 404

            notification_list = []
            for notification in notifications:
                notification_info = {
                    "id": notification.id,
                    "recipient_id": notification.recipient_id,
                    "content": notification.content,
                    "timestamp": notification.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                    "status": notification.status
                }
                notification_list.append(notification_info)

            log_activity('Viewed notifications', user_id)
            return jsonify(notification_list), 200

        except Exception as err:
            return jsonify({"error": str(err)}), 500

    elif request.method == "POST":
        data = request.get_json()

        if not data:
            return jsonify({"message": "Invalid data"}), 400

        recipient_id = data.get("recipient_id")
        content = data.get("content")

        if not all([recipient_id, content]):
            return jsonify({"message": "Missing required fields"}), 400
        
        # Check data types and formats
        if not isinstance(recipient_id, int):
            return jsonify({"message": "Recipient ID must be an integer"}), 400

        if not isinstance(content, str):
            return jsonify({"message": "Content must be a string"}), 400

        new_notification = Notification(
            recipient_id=recipient_id,
            content=content,
            timestamp=datetime.now(timezone.utc),
            status="unread"
        )

        try:
            db.session.add(new_notification)
            db.session.commit()

            user_id = get_jwt_identity()
            log_activity(f'Created notification: {content}', user_id)

            return jsonify({"message": "Notification created successfully"}), 201

        except Exception as err:
            db.session.rollback()
            return jsonify({"error": str(err)}), 500

@app.route("/user/notifications/<int:notification_id>", methods=["PUT", "DELETE"])
@jwt_required()
def update_or_delete_notification(notification_id):
    notification = Notification.query.get(notification_id)
    if not notification:
        return jsonify({"message": "Notification not found"}), 404

    if request.method == "PUT":
        data = request.get_json()
        if not data:
            return jsonify({"message": "Invalid data"}), 400

        status = data.get("status")
        if status not in ["read", "unread"]:
            return jsonify({"message": "Invalid status value"}), 400

        notification.status = status

        try:
            db.session.commit()

            user_id = get_jwt_identity()
            log_activity(f'Updated notification status: {notification_id}', user_id)

            return jsonify({"message": "Notification status updated successfully"}), 200

        except Exception as err:
            db.session.rollback()
            return jsonify({"error": str(err)}), 500

    elif request.method == "DELETE":
        try:
            db.session.delete(notification)
            db.session.commit()

            user_id = get_jwt_identity()
            log_activity(f'Deleted notification: {notification_id}', user_id)

            return jsonify({"message": "Notification deleted successfully"}), 200

        except Exception as err:
            db.session.rollback()
            return jsonify({"error": str(err)}), 500


if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5555, debug=True)




