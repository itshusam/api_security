from flask import request, jsonify
from models.schemas.production_schema import production_schema, productions_schema
from services import productionService
from marshmallow import ValidationError
from caching import cache
from utils import role_required

@role_required
def save():
    try:
        production_data = production_schema.load(request.json)
    except ValidationError as err:
        return jsonify(err.messages), 400

    production_save = productionService.save(production_data)
    if production_save:
        return production_schema.jsonify(production_save), 201
    else:
        return jsonify({"message": "Fallback method error activated", "body": production_data}), 400

@cache.cached(timeout=60)
def find_all():
    productions = productionService.find_all()
    return productions_schema.jsonify(productions), 200