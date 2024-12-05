from marshmallow import fields
from schema import ma 

class EmployeeSchema(ma.Schema):
    id = fields.Integer(required=False)
    name = fields.String(required=True)
    position = fields.String(required=True)

    class Meta:
        fields = ("id", "name", "position")

employee_schema = EmployeeSchema()
employees_schema = EmployeeSchema(many=True)