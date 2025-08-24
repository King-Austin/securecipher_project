# extract_model_info.py
import django
import os

# Setup Django environment (adjust settings module if different)
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "middleware.settings")
django.setup()

from django.apps import apps
from prettytable import PrettyTable

def get_models_info():
    """Iterate all installed apps and extract models, fields, and types"""
    all_models = apps.get_models()
    result = {}

    for model in all_models:
        if model._meta.proxy:
            continue
        model_name = model._meta.db_table
        result[model_name] = []
        for field in model._meta.get_fields():
            # Skip reverse relations
            if field.auto_created and not field.concrete:
                continue
            field_info = {
                "field_name": field.name,
                "field_type": field.get_internal_type(),
                "unique": getattr(field, "unique", False),
                "primary_key": getattr(field, "primary_key", False),
            }
            result[model_name].append(field_info)
    return result

def print_models_table(models_info):
    """Print models info in tabular format"""
    table = PrettyTable()
    table.field_names = ["Table", "Field", "Type", "Unique", "Primary Key"]
    for table_name, fields in models_info.items():
        for field in fields:
            table.add_row([
                table_name,
                field["field_name"],
                field["field_type"],
                field["unique"],
                field["primary_key"],
            ])
    print(table)

if __name__ == "__main__":
    models_info = get_models_info()

    
    # Print pretty table
    print_models_table(models_info)
