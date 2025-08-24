# extract_model_info.py
import django
import os

# Setup Django environment (adjust settings module if different)
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "middleware/middleware/settings.py")
django.setup()

from django.apps import apps
from prettytable import PrettyTable

def get_models_info():
    """Iterate all installed apps and extract models, fields, and types"""
    all_models = apps.get_models()
    result = {}

    for model in all_models:
        model_name = model._meta.db_table
        result[model_name] = []
        for field in model._meta.get_fields():
            # Skip reverse relations
            if field.auto_created and not field.concrete:
                continue
            field_info = {
                "field_name": field.name,
                "field_type": field.get_internal_type(),
                "nullable": getattr(field, "null", False),
                "unique": getattr(field, "unique", False),
                "primary_key": getattr(field, "primary_key", False),
                "default": getattr(field, "default", None)
            }
            result[model_name].append(field_info)
    return result

def print_models_table(models_info):
    """Print models info in tabular format"""
    table = PrettyTable()
    table.field_names = ["Table", "Field", "Type", "Nullable", "Unique", "Primary Key", "Default"]
    for table_name, fields in models_info.items():
        for field in fields:
            table.add_row([
                table_name,
                field["field_name"],
                field["field_type"],
                field["nullable"],
                field["unique"],
                field["primary_key"],
                field["default"]
            ])
    print(table)

if __name__ == "__main__":
    models_info = get_models_info()

    # Optional: Print JSON
    import json
    print(json.dumps(models_info, indent=4))

    # Print pretty table
    print_models_table(models_info)
