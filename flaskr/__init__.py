import os

from flask import Flask
from flask_jwt_extended import JWTManager
from . import auth
from .db import db

from dotenv import load_dotenv

from .config import config

load_dotenv()

def create_app(test_config=None):
    # create and configure the app
    app = Flask(__name__, instance_relative_config=True)
    
    # Setup the Flask-JWT-Extended extension
    app.config["JWT_SECRET_KEY"] = os.getenv('JWT_SECRET_KEY')
    jwt = JWTManager(app)
    
    if test_config is None:
        # load the instance config, if it exists, when not testing
        # app.config.from_pyfile('config.py', silent=True)
        app.config.from_object(config[os.getenv("CONFIG_MODE")])
    else:
        # load the test config if passed in
        app.config.from_mapping(test_config)

    # ensure the instance folder exists
    try:
        os.makedirs(app.instance_path)
    except OSError:
        pass

    db.init_app(app)
    
    app.register_blueprint(auth.bp)
    
    with app.app_context():
        db.create_all()

    return app