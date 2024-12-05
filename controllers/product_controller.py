from flask import request, jsonify
from models.schemas.product_schema import product_schema, products_schema
from services import productService
from marshmallow import ValidationError
from caching import cache
from utils import role_required

@role_required('admin')
def save():
    try:
        product_data = product_schema.load(request.json)
    except ValidationError as err:
        return jsonify(err.messages), 400

    product_save = productService.save(product_data)
    if product_save:
        return product_schema.jsonify(product_save), 201
    else:
        return jsonify({"message": "Fallback method error activated", "body": product_data}), 400

@cache.cached(timeout=60)
def find_all():
    page = request.args.get('page', default=1, type=int)
    per_page = request.args.get('per_page', default=10, type=int)

    paginated_products = productService.find_all(page, per_page)
  
    return jsonify({
        "products": products_schema.dump(paginated_products.items),
        "total": paginated_products.total,
        "page": paginated_products.page,
        "pages": paginated_products.pages
    }), 200
