from flask import Flask, request, jsonify, make_response
from flask_restful import Api
from flask_bcrypt import Bcrypt
from flask_migrate import Migrate
from flask_restful import Api
from flask_jwt_extended import JWTManager, jwt_required, get_jwt_identity, create_access_token, get_jwt, unset_jwt_cookies
from models import db
from datetime import datetime, timezone, timedelta
from flask_cors import CORS
from dotenv import load_dotenv
from sqlalchemy import func, and_
import smtplib
from email.mime.text import MIMEText
import json
import os
import re


from models import User,  RoutePlan, Location, Outlet, Notification, ActivityLog, Review

load_dotenv()

app = Flask(__name__)

app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("SQLALCHEMY_DATABASE_URI")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["JWT_SECRET_KEY"] = os.getenv("SECRET_KEY")
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(days=1)

app.config['SMTP_SERVER_ADDRESS'] = os.getenv("SMTP_SERVER_ADDRESS")
app.config['SMTP_USERNAME'] = os.getenv("SMTP_USERNAME")
app.config['SMTP_PASSWORD'] = os.getenv("SMTP_PASSWORD")
app.config['SMTP_PORT'] = os.getenv("SMTP_PORT")



db.init_app(app)
migrate = Migrate(app, db)
jwt = JWTManager(app)

bcrypt = Bcrypt(app)

api = Api(app)
CORS(app)

blacklist = set()

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
        return jsonify({
            'message': 'Activity logged successfully',
            "successful": True,
            "status_code": 201
        }), 201

    except Exception as err:
        db.session.rollback()
        print(f"Failed to log activity. Error: {err}")
        return jsonify({
            'message': f'Error {err}',
            "successful": False,
            "status_code": 500
        }), 500

@jwt.token_in_blocklist_loader
def check_if_token_in_blacklist(jwt_header, jwt_payload):
    jti = jwt_payload["jti"]
    return jti in blacklist

@app.route("/users/logout", methods=["POST"])
@jwt_required()
def logout_user():
    data = request.get_json()
    user_id = data.get("user_id")

    # Extract JTI from the token
    jti = get_jwt()["jti"]
    blacklist.add(jti)

    # Log the logout activity
    log_activity('Logout', user_id)

    # Create a response object
    response = make_response(jsonify({
        "message": "Logout successful.",
        "successful": True,
        "status_code": 201
    }))

    # Unset JWT cookies
    unset_jwt_cookies(response)

    return response, 201


@app.route('/users/signup', methods=['POST'])
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
    first_name = data.get('first_name').title() if data.get('first_name') else None
    middle_name = data.get('middle_name').title() if data.get('middle_name') else None
    last_name = data.get('last_name').title() if data.get('last_name') else None
    national_id_no = data.get('national_id_no')
    username = data.get('username').lower() if data.get('username') else None
    email = data.get('email').lower() if data.get('email') else None
    password = data.get('password')
    staff_no = data.get("staff_no")

    try:
        national_id_no = int(data.get('national_id_no'))
        staff_no = int(data.get('staff_no'))
    except (ValueError, TypeError):
        return jsonify({
            'message': 'National ID and Staff number must be integers',
            "successful": False,
            "status_code": 400
        }), 400


    if User.query.filter(User.staff_no == staff_no).first():
        return jsonify({
            'message': 'Staff number already assigned',
            "successful": False,
            "status_code": 400
            }), 400

    if User.query.filter(User.national_id_no == national_id_no).first():
        return jsonify({
            'message': 'Another user exists with the provided National ID Number',
            "successful": False,
            "status_code": 400
            }), 400

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

    # Hash the password before saving it
    hashed_password = bcrypt.generate_password_hash(password).decode("utf-8")

    # Create new user object
    new_user = User(
        first_name=first_name,
        middle_name=middle_name,
        last_name=last_name,
        national_id_no=national_id_no,
        username=username,
        email=email,
        password=hashed_password,
        staff_no = staff_no,
        role='merchandiser', 
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
            "status_code": 500
            }), 500


@app.route('/users', methods=['GET'])
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
            'last_name': user.last_name,
            'username': user.username,
            'email': user.email,
            'role': user.role,
            'status': user.status, 
            "staff_no": user.staff_no,
        }
        user_list.append(user_info)

    user_id = get_jwt_identity()
    log_activity('Viewed user list', user_id)

    return jsonify({
        "successful": True,
        "status_code": 200,
        'message': user_list
        }), 200


@app.route("/users/route-plans/<int:merchandiser_id>", methods=["GET"])
@jwt_required()
def get_merchandiser_route_plans(merchandiser_id):

    route_plans = RoutePlan.query.filter_by(merchandiser_id=merchandiser_id).all()

    if not route_plans:
        return jsonify({
            'message': 'You have not been assigned any routes',
            "successful": False,
            "status_code": 404
        }), 404
    
    route_plans_list = []

    for route in route_plans:
        route_plans_list.append({
            'merchandiser_id': route.merchandiser_id,
            'manager_id': route.manager_id,
            'date_range': route.date_range,
            'instructions': route.instructions,
            'status': route.status,
            "id": route.id
        })

    return jsonify({
        'message': route_plans_list,
        "successful": True,
        "status_code": 200
    }), 200


def send_email_to_merchandiser(data):

    staff_no = data.get('staff_no')
    manager_id = data.get('manager_id')
    date_range = data.get('date_range')
    instructions = data.get('instructions')
    status = data.get('status')

    manager = User.query.filter_by(id=manager_id).first()
    merchandiser = User.query.filter_by(staff_no=staff_no).first()
    if not manager:
        return  jsonify({
                "message": "Invalid manager",
                "successful": False,
                "status_code": 400
                }), 400

    subject = 'Route Plans'

    body = f"Greetings {merchandiser.first_name} {merchandiser.last_name}, I trust this mail finds you well.\n\n"

    body += "Here are the details of the route plans assigned to you:\n\n"
    body += f"{date_range}\n\n"
    body += f"{instructions}\n\n"
    body += f"{status}\n\n"

    
    body += f"Warm regards,\n"
    body += f"{manager.first_name} \n"
    body += f"Sales Manager\n"
    body += f"Merch Mate Group\n\n"

    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = f"{manager.first_name}{manager.last_name}@trial-jy7zpl9xj15l5vx6.mlsender.net"
    msg['To'] = merchandiser.email

    
    smtp_server = app.config['SMTP_SERVER_ADDRESS']
    smtp_port = app.config['SMTP_PORT']
    username = app.config['SMTP_USERNAME']
    password = app.config['SMTP_PASSWORD']

    with smtplib.SMTP(smtp_server, smtp_port) as server:
        server.starttls()
        server.login(username, password)
        server.sendmail(username, merchandiser.email, msg.as_string())


@app.route('/users/route-plans', methods=['GET', 'POST'])
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
            'message': route_plan_list
            }), 200

    elif request.method == 'POST':
        data = request.get_json()
        if not data:
            return jsonify({
                "message": "Invalid request",
                "successful": False,
                "status_code": 400
                }), 400

        # Extract required fields from the JSON data
        # merchandiser_id = data.get('merchandiser_id')
        manager_id = data.get('manager_id')
        date_range = data.get('date_range')
        instructions = data.get('instructions')
        status = data.get('status')
        staff_no = data.get("staff_no")

        # Check for required fields
        if not all([staff_no, manager_id, date_range, status]):
            return jsonify({
                'message': 'Missing required fields',
                "successful": False,
                "status_code": 400
                }), 400
        
        # Check if data adheres to model specifications
        if not isinstance(staff_no, int) or not isinstance(manager_id, int):
            return jsonify({
                'message': 'Staff number and Manager ID must be integers',
                "successful": False,
                "status_code": 400
                }), 400
        
        if not isinstance(date_range, dict):
            return jsonify({
                'message': 'Date range must be a dictionary',
                "successful": False,
                "status_code": 400
            }), 400

        start_date = date_range.get('start_date')
        end_date = date_range.get('end_date')

        if not all([start_date, end_date]):
            return jsonify({
                'message': 'Missing start_date or end_date in date_range',
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
        

        user = User.query.filter_by(staff_no=staff_no, role='merchandiser').first()

        if not user:
            return jsonify({
                'message': 'Invalid staff number or user is not a merchandiser',
                "successful": False,
                "status_code": 400
            }), 400


        # Create a new route plan object
        new_route_plan = RoutePlan(
            merchandiser_id=user.id,
            manager_id=manager_id,
            date_range=date_range,
            instructions=instructions,
            status=status
        )

        try:
            db.session.add(new_route_plan)
            db.session.commit()
            send_email_to_merchandiser(data)
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
                'message': f"Internal server error. Error: {err}",
                "successful": False,
                "status_code": 500
                }), 500


@app.route('/users/route-plans/<int:route_plan_id>', methods=['PUT'])
@jwt_required()
def update_route_plan(route_plan_id):

    data = request.get_json()

    route_plan = db.session.get(RoutePlan, route_plan_id)

    if not route_plan:
        return jsonify({
            'message': 'Route plan not found',
            "successful": False,
            "status_code": 404
            }), 404
    
    # Check if data adheres to model specifications
    if 'merchandiser_id' in data:
        if not isinstance(data['merchandiser_id'], int) or not isinstance(data["manager_id"], int):
            return jsonify({
                'message': 'Merchandiser and manager IDs must be an integer',
                "successful": False,
                "status_code": 400
                }), 400

    if 'date_range' in data:
        # Attempt to parse the date range string
        try:
            start_date = datetime.strptime(data['date_range']['start_date'], '%d/%m/%Y %I:%M %p')
            end_date = datetime.strptime(data['date_range']['end_date'], '%d/%m/%Y %I:%M %p')
            # Assign the parsed dates to the route plan
            route_plan.start_date = start_date
            route_plan.end_date = end_date
        except ValueError:
            return jsonify({
                'message': 'Invalid date format. Please provide dates in the format: "dd/mm/yyyy hh:mm am/pm"',
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
    route_plan.instructions = data.get('instructions', route_plan.instructions)
    route_plan.status = data.get('status', route_plan.status)
    route_plan.date_range= data.get('date_range', route_plan.date_range)

    try:
        db.session.commit()

        user_id = get_jwt_identity()
        log_activity(f'Edited merchandiser route. Route id : {route_plan_id}', user_id)
        return jsonify({
            'message': 'Route plan updated successfully',
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


@app.route('/users/locations', methods=['GET', 'POST'])
@jwt_required()
def location_details():
    if request.method == 'GET':
        # locations = Location.query.all()

        # Group locations by merchandiser_id and select the latest timestamp for each group
        latest_locations_subquery = db.session.query(Location.merchandiser_id,
                                                      func.max(Location.timestamp).label('latest_timestamp'))\
                                               .group_by(Location.merchandiser_id)\
                                               .subquery()

        # Join the subquery with the Location table to get the latest location details for each merchandiser
        latest_locations_query = db.session.query(Location)\
                                           .join(latest_locations_subquery,
                                                 and_(Location.merchandiser_id == latest_locations_subquery.c.merchandiser_id,
                                                      Location.timestamp == latest_locations_subquery.c.latest_timestamp))\
                                           .all()

        if not latest_locations_query:
            return jsonify({
                'message': 'No locations found',
                "successful": False,
                "status_code": 404
                }), 404

        location_list = []
        for location in latest_locations_query:
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
            'message': location_list}), 200
    
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
                'message': 'Merchandiser ID must be an integer, and latitude and longitude must be in decimals',
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
        

@app.route("/users/login", methods=["POST"])
def login_user():

    data = request.get_json()

    
    if not data:
        return jsonify({
            "message": "Invalid request",
            "successful": False,
            "status_code": 400
            }), 400
    
    email = data.get("email").lower() if data.get('email') else None
    password = data.get("password")

    
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
                    "message": "Your password has expired",
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
                "message": user_data
                            }), 201
        
        else:
            return jsonify({
                "message": "Invalid credentials",
                "successful": False,
                "status_code": 401
                }), 401
    else:
        return jsonify({
            "message": "You do not have an account, please signup.",
            "successful": False,
            "status_code": 404
            }), 404
    

@app.route("/users/change-password", methods=["PUT"])
def change_password():
    
    data = request.get_json()

    if not data:
        return jsonify({
            "message": "Invalid request",
            "successful": False,
            "status_code": 400
            }), 400
    
    old_password = data.get("old_password")
    new_password = data.get("new_password")
    email = data.get("email")

    # new_password must be string and length must be <= 120
     

    if not old_password or not new_password or not email:
        return jsonify({

            "message": "Missing required fields",
            "successful": False,
            "status_code": 400
            }), 400
    
    if old_password == new_password:
        return jsonify({

            "message": "Old password and new password cannot be the same",
            "successful": False,
            "status_code": 400
            }), 400

    if not isinstance(new_password, str) or len(new_password) < 6:
      
        return jsonify({
            'message': 'Password must be a string and at least 6 characters long',
            "successful": False,
            "status_code": 400
            }), 400

    user = User.query.filter_by(email=email).first()
    

    if user:

        user_id = user.id

        if bcrypt.check_password_hash(user.password, old_password):

            hashed_new_password = bcrypt.generate_password_hash(new_password).decode('utf-8')

            user.password = hashed_new_password
            user.last_password_change = datetime.now(timezone.utc)

            try:
                db.session.commit()
                user_id = user_id

                log_activity(f'Changed password.', user_id)
                return jsonify({
                    "message": "Password changed successfully",
                    "successful": True,
                    "status_code": 201
                                }), 201
            except Exception as err:
                db.session.rollback()
                return jsonify({
                    "message": f"Failed to change signature. Error{err}",
                    "successful": False,
                    "status_code": 500
                }), 500
          
        else:
            return jsonify({
                "message": "Invalid old password",
                "successful": False,
                "status_code": 401
                }), 401
    else:
        return jsonify({
            "message": "User not found",
            "successful": False,
            "status_code": 404
            }), 404

@app.route("/users/edit-profile-image/<int:id>", methods=["PUT"])
@jwt_required()
def edit_user_image(id):
    
    data = request.get_json()

    if not data:

        return jsonify({
            "message": "Invalid request",
            "successful": False,
            "status_code": 400
            }), 400
    
    new_avatar = data.get("avatar")

    # Check if avatar data is provided and is of type bytes
    if new_avatar is not None and not isinstance(new_avatar, bytes):
        return jsonify({
            "message": "Avatar data must be in bytes format (BYTEA)",
            "successful": False,
            "status_code": 400
            }), 400

    user = User.query.get(id)

    if user:
        
        user.avatar = new_avatar

        try:
            db.session.commit()
            log_activity('Change profile image', id)
            return jsonify({
                "message": "Profile image updated successfully",
                "successful": True,
                "status_code": 201
                }), 201
        
        except Exception as e:
            db.session.rollback()
            return jsonify({
                "message": f"Failed to update, error: {e}",
                "successful": False,
                "status_code": 500
                }), 500
        
    else:
        return jsonify({
            "message": "User not found",
            "successful": False,
            "status_code": 404

                        }), 404


@app.route("/users/get-logs", methods=["GET"])
@jwt_required()
def get_users_activities():

    try:
        activity_logs = ActivityLog.query.all()

        if not activity_logs:
            return jsonify({
                "message": "No logs available",
                "successful": False,
                "status_code": 400
                }), 400

        activity_logs_data = []

        for log in activity_logs:
            log_data = {
                "id": log.id,
                "user_id": log.user_id,
                "action": log.action,
                "timestamp": log.timestamp.strftime('%Y-%m-%d %H:%M:%S') 
            }
            activity_logs_data.append(log_data)
        
        user_id = get_jwt_identity()
        # user_id = 3
        log_activity('Viewed activity logs', user_id)

        return jsonify({

            "message": activity_logs_data,
            "successful": True,
            "status_code": 200
                        }), 200
    
    except Exception as e:
        return jsonify({
            "message": str(e),
            "successful": False,
            "status_code": 500
            }), 500


@app.route("/users/outlets", methods=["GET", "POST"])
@jwt_required()
def create_and_get_outlet_details():
    
    if request.method == "GET":

        try:
            outlets = Outlet.query.all()

            if not outlets:
                return jsonify({
                    "message": "There are no outlets",
                    "successful": False,

                    "status_code": 404
                                }), 404

            
            outlet_list = []

            for outlet in outlets:
                outlet_details = {
                    "id": outlet.id,
                    "name": outlet.name,
                    "address": outlet.address,
                    "contact_info": outlet.contact_info,
                    "street" : outlet.street
                }
                outlet_list.append(outlet_details)

            user_id = get_jwt_identity()
            # user_id = 3
            log_activity(f'Created outlet', user_id)

            return jsonify({
                "message": outlet_list,
                "successful": True,
                "status_code": 200
            }), 200

        except Exception as err:
            return jsonify({
                "message": f"Error: {err}",
                "successful": False,
                "status_code": 500
                }), 500
        
        
    elif request.method == "POST":

        data = request.get_json()

        if not data:
            return jsonify({
                "message": "Invalid data",
                "successful": False,
                "status_code": 400
                }), 400
        
        name = data.get("name")
        address = data.get("address")
        contact_info = data.get("contact_info")
        street = data.get("street")


        if not all([name, address, contact_info, street]):

            return jsonify({
                "message": "Missing required fields",
                "successful": False,
                "status_code": 400
                }), 400
        
        if not isinstance(name, str) or len(name) > 100:
            return jsonify({
                'message': 'Outlet name must be a string and not more than 100 characters',
                "successful": False,
                "status_code": 400
                }), 400
        
        if not isinstance(address, str) or len(address) > 200:
            return jsonify({
                'message': 'Address must be a string and not more than 200 characters',
                "successful": False,
                "status_code": 400
                }), 400
        
        if not isinstance(contact_info, str) or len(contact_info) > 100:
            return jsonify({
                'message': 'Contact info must be a string and not more than 100 characters',
                "successful": False,
                "status_code": 400
                }), 400
        
        if not isinstance(street, str) or len(street) > 200:
            return jsonify({
                'message': 'Street name must be a string of not more than 200 characters',
                "successful": False,
                "status_code": 400
                }), 400
        

        new_outlet = Outlet(
            name=name,
            address=address,
            contact_info=contact_info,
            street = street
        )
        
        try:

            db.session.add(new_outlet)
            db.session.commit()

            user_id = get_jwt_identity()
            # user_id = 3
            log_activity(f'Created outlet: {name}', user_id)

            return jsonify({
                "message": "Outlet created successfully",
                "successful": True,
                "status_code": 201
                }), 201

        except Exception as err:

            db.session.rollback()
            return jsonify({

                "message": f"Error: {err}",

                "successful": False,
                "status_code": 500
                }), 500


@app.route("/users/edit-outlet/<int:id>", methods=["PUT"])
@jwt_required()
def edit_outlet_details(id):
    
    try:
        data = request.get_json()

        if not data:
            return jsonify({
                "message": "Invalid request",
                "successful": False,
                "status_code": 400
                }), 400

        outlet = Outlet.query.get(id)
        
        if not outlet:
            return jsonify({
                "message": "Outlet not found",
                "successful": False,
                "status_code": 404
                }), 404
        
        if 'name' in data:
            if not isinstance(data['name'], str) or len(data['name']) > 100:
                return jsonify({
                    'message': 'Outlet name must be a string and not exceed 100 characters',
                    "successful": False,
                    "status_code": 400
                    }), 400
        if "street" in data:
            if not isinstance(data["street"], str) or len(data["street"]) > 200:
                return jsonify({
                    'message': 'Street name must be a string and not exceed 200 characters',
                    "successful": False,
                    "status_code": 400
                    }), 400
            
        if 'address' in data:
            if not isinstance(data['address'], str) or len(data['address']) > 200:
                return jsonify({
                    'message': 'Address must be a string and not exceed 200 characters',
                    "successful": False,
                    "status_code": 400
                    }), 400
            
        if 'contact_info' in data:
            if not isinstance(data['contact_info'], str) or len(data['contact_info']) > 100:
                return jsonify({
                    'message': 'Contact info must be a string and not exceed 100 characters',
                    "successful": False,
                    "status_code": 400
                    }), 400

        # Update outlet attributes if provided in the request data
        if 'name' in data:
            outlet.name = data['name']
        if 'address' in data:
            outlet.address = data['address']
        if 'contact_info' in data:
            outlet.contact_info = data['contact_info']
        if "street" in data:
            outlet.street = data["street"]

        # Commit the changes to the database
        db.session.commit()

        user_id = get_jwt_identity()
        # user_id = 3
        log_activity('Created outlet', user_id)
        
        return jsonify({
            "message": "Outlet details updated successfully",
            "successful": True,
            "status_code": 201
            }), 201
    
    except Exception as e:
        db.session.rollback()
        return jsonify({
            "message": str(e),
            "successful": False,
            "status_code": 500
            }), 500


@app.route("/users/notifications", methods=["GET", "POST"])
@jwt_required()
def manage_notifications():

    if request.method == "GET":
        try:
            user_id = get_jwt_identity()
            notifications = Notification.query.filter_by(recipient_id=user_id).all()

            if not notifications:
                return jsonify({
                    "message": "No notifications found",
                    "successful": False,
                    "status_code": 404
                    }), 404

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
            return jsonify({
                "message": notification_list,
                "successful": True,
                "status_code": 200
                }), 200

        except Exception as err:
            return jsonify({
                "message": str(err),
                "successful": False,
                "status_code": 500
                }), 500

    elif request.method == "POST":
        data = request.get_json()

        if not data:
            return jsonify({
                "message": "Invalid data",
                "successful": False,
                "status_code": 400
                            }), 400

        recipient_id = data.get("recipient_id")
        content = data.get("content")

        if not all([recipient_id, content]):

            return jsonify({
                "message": "Missing required fields",
                "successful": False,
                "status_code": 400
                }), 400
        
        # Check data types and formats
        if not isinstance(recipient_id, int):
            return jsonify({
                "message": "Recipient ID must be an integer",
                "successful": False,
                "status_code": 400
                }), 400

        if not isinstance(content, str):
            return jsonify({
                "message": "Content must be a string",
                "successful": False,
                "status_code": 400
                }), 400


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

            return jsonify({
                "message": "Notification created successfully",
                "successful": True,
                "status_code": 201
                }), 201

        except Exception as err:
            db.session.rollback()
            return jsonify({
                "message": str(err),
                "successful": False,
                "status_code": 500
                }), 500

@app.route("/users/notifications/<int:notification_id>", methods=["PUT", "DELETE"])
@jwt_required()
def update_or_delete_notification(notification_id):

    notification = Notification.query.get(notification_id)

    if not notification:
        return jsonify({
            "message": "Notification not found",
            "successful": False,
            "status_code": 404
                        }), 404

    if request.method == "PUT":
        
        data = request.get_json()
        if not data:
            return jsonify({
                "message": "Invalid data",
                "successful": False,
                "status_code": 400
                }), 400

        status = data.get("status")
        
        if status not in ["read", "unread"]:
            return jsonify({
                "message": "Invalid status value",
                "successful": False,
                "status_code": 400
                }), 400

        notification.status = status

        try:
            db.session.commit()

            user_id = get_jwt_identity()
            log_activity(f'Updated notification status: {notification_id}', user_id)

            return jsonify({
                "message": "Notification status updated successfully",
                "successful": True,
                "status_code": 201
                }), 201

        except Exception as err:
            db.session.rollback()
            return jsonify({
                "message": str(err),
                "successful": False,
                "status_code": 500
                }), 500

    elif request.method == "DELETE":
        try:
            db.session.delete(notification)
            db.session.commit()

            user_id = get_jwt_identity()
            log_activity(f'Deleted notification: {notification_id}', user_id)

            return jsonify({
                "message": "Notification deleted successfully",
                "successful": False,
                "status_code": 204
                }), 204

        except Exception as err:
            db.session.rollback()
            return jsonify({
                "message": str(err),
                "successful": False,
                "status_code": 500
                }), 500


@app.route("/users/get-reviews", methods=["GET"])
@jwt_required()
def get_reviews():

    reviews = Review.query.all()

    if not reviews:
        return jsonify({
            "message": "There are no reviews",
            "status_code": 404,
            "successful": False
        }), 404

    reviews_data = []

    for review in reviews:
        reviews_data.append({
            "id": review.id,
            "rating": review.rating,
            "comment": review.comment,
            "activity": review.activity
        })

    return jsonify({
        "message": reviews_data,
        "successful": True,
        "status_code": 200
    }), 200


@app.route("/users/create-reviews", methods=["POST"])
@jwt_required()
def create_reviews():
    
    data = request.get_json()

    if not data:

        return jsonify({
            "message": "Invalid data",
            "status_code": 400,
            "successful": False
        }), 400
    
    staff_no = data.get("staff_no")
    activity = data.get("activity")
    comment = data.get("commet")
    timestamp = data.get("timestamp")
    rating = data.get("rating")
    manager_id = data.get("manager_id")

    if not staff_no or not activity or not comment or not timestamp or not rating or not manager_id:
        return jsonify({
            "message": "Missing required fields",
            "status_code": 400,
            "successful": False
        }), 400
    
    if not isinstance(staff_no, int) or not isinstance(rating, int) or not isinstance(manager_id, str):
        return jsonify({
            "message": "Staff number, manager ID, and rating must be a numbers",
            "status_code": 400,
            "successful": False
        }), 400
    
    if not all(isinstance(value, str) for value in [activity, comment, timestamp]):
        return jsonify({
            "message": "Comment, and activity must be letters",
            "status_code": 400,
            "successful": False
        }), 400
    
    if len(activity) > 200:
        return jsonify({
            "message": "Activity must be less than 201 characters long",
            "status_code": 400,
            "successful": False
        }), 400
    
    merchandiser = User.query.filter(staff_no == staff_no).first()

    if not merchandiser:
        return jsonify({
            "message": "Invalid merchandiser",
            "status_code": 400,
            "successful": False
        }),400
    
    merchandiser_id = merchandiser.id

    new_review = Review(
        manager_id = manager_id,
        merchandiser_id = merchandiser_id,
        activity = activity,
        comment = comment,
        rating = rating,
        timestamp = timestamp
    )

    try:
        db.session.add(new_review)
        db.session.commit()
        return jsonify({
            "message": "Review added successfully",
            "status_code": 201,
            "successful": True
        }),201
    
    except Exception as err:
        db.session.rollback()
        return jsonify({
            "message": f"Error {err}",
            "status_code": 500,
            "successful": False
        }), 500
    


if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5555, debug=True)




