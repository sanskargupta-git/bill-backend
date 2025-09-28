# Instructions for Google Vision OCR Integration

1. Go to https://console.cloud.google.com/ and create a project (if you don't have one).
2. Enable the Vision API for your project.
3. Create a service account and download the JSON key file.
4. Place the key file in your backend directory (e.g., backend/vision-key.json).
5. Set the environment variable before running your backend:
   export GOOGLE_APPLICATION_CREDENTIALS="/home/sanskargpta/projects/bill/backend/vision-key.json"
6. Install the Google Cloud Vision client library:
   pip install google-cloud-vision
7. The backend will be updated to use Vision API for OCR.
