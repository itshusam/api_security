from flask import Blueprint
from controllers.user_controller import login

auth_blueprint = Blueprint('auth_bp', __name__)

auth_blueprint.route('/login', methods=['POST'])(login)