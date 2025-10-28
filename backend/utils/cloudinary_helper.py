import cloudinary
import cloudinary.uploader
import os

# Load Cloudinary configuration from environment variables
cloudinary.config(
    cloud_name=os.getenv("CLOUDINARY_CLOUD_NAME"),
    api_key=os.getenv("CLOUDINARY_API_KEY"),
    api_secret=os.getenv("CLOUDINARY_API_SECRET"),
    secure=True
)

def upload_file_to_cloudinary(file_obj, folder="sirverse/notes"):
    """
    Uploads a file object to Cloudinary and returns the upload result.
    file_obj = Flask FileStorage object
    """
    try:
        result = cloudinary.uploader.upload(file_obj, folder=folder, resource_type="auto")
        return result
    except Exception as e:
        print("❌ Cloudinary upload failed:", e)
        raise

def delete_file_by_url(url):
    """
    (Optional) Delete a file from Cloudinary by its URL.
    Implement later if you want cleanup.
    """
    pass
