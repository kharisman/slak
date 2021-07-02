from flask import Flask ,jsonify,request
from flask_jwt_extended import create_access_token, get_jwt_identity, jwt_required, JWTManager
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt

app = Flask(__name__)
bcrypt = Bcrypt(app)

# Setup the Flask-JWT-Extended extension
app.config["JWT_SECRET_KEY"] = "coba_lah135465tfgyfgdffrer"  # Change this!
jwt = JWTManager(app)

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True

#avaible mysql , sql , postgree, sqlserver , ect
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root:mysql@localhost/qqqqq' 
db = SQLAlchemy(app)

#our model
class Profil(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    # nama = db.Column(db.String(100), unique = True)
    nama = db.Column(db.String(30))
    alamat = db.Column(db.String(30))


class Users(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    # nama = db.Column(db.String(100), unique = True)
    username = db.Column(db.String(225))
    password = db.Column(db.String(225))
    status = db.Column(db.Integer)

# Create a route to authenticate your users and return JWTs. The
# create_access_token() function is used to actually generate the JWT.
@app.route("/login", methods=["POST"])
def login():

    username = request.form.get("username", None)
    password = request.form.get("password", None)

    if username is None or password is None:
        return jsonify({"msg": "Bad username or password"}), 401

    user = Users.query.filter_by(username=username).first()
    if user is not None:
        cek  = bcrypt.check_password_hash(user.password, password) 
        print(cek)
        if cek is not True :
           return jsonify({"msg": "Password not match"}), 401 
    else:
        return jsonify({"msg": "username not found"}), 401
  
    access_token = create_access_token(identity=username)
    return jsonify(access_token=access_token)

@app.route("/register", methods=["POST"])
def register():
    username = request.form.get("username", None)
    password = request.form.get("password", None)
    if username is None or password is None:
        return jsonify({"msg": "Bad username or password"}), 401

    user = Users.query.filter_by(username=username).first()
    if user is not None:
        return jsonify({"msg": "Bad username aleready exist"}), 401
   
    pw_hash = bcrypt.generate_password_hash(password)
    
    save  = Users(username=username, password=pw_hash, status=1)
    db.session.add(save)   
    db.session.commit() 

    return jsonify({"msg": "Register Success !"}), 200


# Protect a route with jwt_required, which will kick out requests
# without a valid JWT present.
@app.route("/protected", methods=["GET"])
@jwt_required()
def protected():
    # Access the identity of the current user with get_jwt_identity
    current_user = get_jwt_identity()
    return jsonify(logged_in_as=current_user), 200


if __name__ == "__main__":
    app.run()
