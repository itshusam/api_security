from flask import Blueprint
from controllers.taskTwoController import (
    get_employee_performance,
    get_top_selling_products,
    get_customer_lifetime_value,
    get_production_efficiency
)

analytics_blueprint = Blueprint('analytics_bp', __name__)

analytics_blueprint.route('/employees/performance', methods=['GET'])(get_employee_performance)
analytics_blueprint.route('/products/top-selling', methods=['GET'])(get_top_selling_products)
analytics_blueprint.route('/customers/lifetime-value', methods=['GET'])(get_customer_lifetime_value)
analytics_blueprint.route('/production/efficiency', methods=['GET'])(get_production_efficiency)
