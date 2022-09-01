from flask import Flask, request, jsonify
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from pymongo import MongoClient
import datetime, hashlib

app = Flask(__name__)
jwt = JWTManager(app)
app.config["JWT_SECRET_KEY"] = 'so-secret'
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = datetime.timedelta(days=1)

uri = "mongodb://kevinguzman:kevinguzman@localhost:27017/?authSource=admin"
client = MongoClient(uri)
db = client["flask-api-mongodb"]
users_collection = db["users"]

@app.route("/api/v1/users", methods=["POST"])
def register():
    new_user = request.get_json()
    new_user["password"] = hashlib.sha256(new_user["password"].encode("utf-8")).hexdigest()
    doc = users_collection.find_one({"username": new_user["username"]})
    if not doc:
        users_collection.insert_one(new_user)
        return jsonify({"msg": "User created successfully"})
    else:
        return jsonify({"msg": "Username already exists"})

@app.route("/api/v1/login", methods=["POST"])
def login():
    login_details = request.get_json()
    user_from_db = users_collection.find_one({'username': login_details['username']})

    if user_from_db:
        encripted_password = hashlib.sha256(login_details["password"].encode("utf-8")).hexdigest()
        if encripted_password == user_from_db["password"]:
            access_token = create_access_token(identity=user_from_db["username"])
            return jsonify(access_token = access_token)
    return jsonify({"msg": "The username or password is incorrect"}), 401

@app.route("/api/v1/user", methods=["GET"])
@jwt_required()
def profile():
    current_user = get_jwt_identity()
    user_from_db = users_collection.find_one({"username": current_user})
    if user_from_db:
        del user_from_db['_id'], user_from_db["password"]
        return jsonify({'profile': user_from_db}), 200
    else:
        return jsonify({'msg': 'Profile not found'}), 404

if __name__ == "__main__":
    app.run(debug=True)