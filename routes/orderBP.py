from flask import Blueprint, request
from controllers.order_controller import save, find_all

order_blueprint = Blueprint('order_bp', __name__)

order_blueprint.route('/', methods=['POST'])(save)

@order_blueprint.route('/', methods=['GET'])
def get_orders():
    page = request.args.get('page', default=1, type=int)
    per_page = request.args.get('per_page', default=10, type=int)
    return find_all(page, per_page)
