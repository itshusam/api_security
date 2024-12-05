from flask import Blueprint, request
from controllers.product_controller import save, find_all

product_blueprint = Blueprint('product_bp', __name__)

product_blueprint.route('/', methods=['POST'])(save)

@product_blueprint.route('/', methods=['GET'])
def get_products():
    page = request.args.get('page', default=1, type=int)
    per_page = request.args.get('per_page', default=10, type=int)
    return find_all(page, per_page)

