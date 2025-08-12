pip install -r requirements.txt gunicorn && \
python manage.py migrate && \
python manage.py collectstatic --noinput && \
python manage.py shell -c "from django.contrib.auth import get_user_model; \
User = get_user_model(); \
User.objects.filter(username='admin').exists() or \
User.objects.create_superuser('admin', 'admin@admin.com', 'securecipher')" && \
# Start backend with gunicorn
gunicorn bankingapi.wsgi:application --bind 0.0.0.0:8001
