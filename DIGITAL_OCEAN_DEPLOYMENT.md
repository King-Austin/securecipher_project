# Digital Ocean App Platform Deployment Guide

## Prerequisites
- Digital Ocean account
- GitHub repository connected to Digital Ocean

## Step 1: Prepare Your Repository
Ensure your `setup.sh` scripts are executable:
```bash
chmod +x middleware/setup.sh
chmod +x server/setup.sh
git add .
git commit -m "Make setup scripts executable"
git push origin master
```

## Step 2: Create Digital Ocean App

1. Go to [Digital Ocean App Platform](https://cloud.digitalocean.com/apps)
2. Click "Create App"
3. Select your GitHub repository
4. Choose the branch (master)

## Step 3: Configure Services

### Middleware Service
- **Service Name**: middleware
- **Source Directory**: middleware
- **Environment**: Python
- **Build Command**: `chmod +x setup.sh && ./setup.sh`
- **Run Command**: `gunicorn securecipher.wsgi:application --bind 0.0.0.0:$PORT`

### Banking API Service
- **Service Name**: banking-api
- **Source Directory**: server
- **Environment**: Python
- **Build Command**: `chmod +x setup.sh && ./setup.sh`
- **Run Command**: `gunicorn bankingapi.wsgi:application --bind 0.0.0.0:$PORT`

### Frontend Service
- **Service Name**: frontend
- **Source Directory**: frontend
- **Environment**: Node.js
- **Build Command**: `npm ci && npm run build`
- **Output Directory**: dist

## Step 4: Configure Environment Variables

### For Both Backend Services:
```
DEBUG=false
SECRET_KEY=<your-secret-key>
DATABASE_URL=<provided-by-digital-ocean>
DJANGO_SUPERUSER_USERNAME=admin
DJANGO_SUPERUSER_EMAIL=admin@securecipher.app
DJANGO_SUPERUSER_PASSWORD=<secure-password>
```

### For Banking API (additional):
```
FIELD_ENCRYPTION_KEY=<your-encryption-key>
```

### For Frontend:
```
VITE_API_URL=<middleware-service-url>/api
VITE_APP_NAME=SecureCipher Bank
NODE_ENV=production
```

## Step 5: Configure Database

1. Add a PostgreSQL database to your app
2. Digital Ocean will automatically provide the `DATABASE_URL`

## Step 6: Deploy

1. Review your configuration
2. Click "Create Resources"
3. Wait for deployment to complete

## Troubleshooting

### Build Failures
- Check that `setup.sh` has execute permissions
- Verify all environment variables are set
- Check build logs for specific errors

### Runtime Issues
- Ensure database migrations ran successfully
- Check that static files were collected
- Verify service URLs are correctly configured

### Environment Detection
The setup scripts automatically detect Digital Ocean by checking for:
- `DIGITALOCEAN_APP_SPEC` environment variable
- `DIGITALOCEAN_APP_ID` environment variable

If neither is present, it assumes local development and creates a virtual environment.