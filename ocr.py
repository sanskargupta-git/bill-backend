import sys
import os
from PIL import Image, ImageOps, ImageFilter


def use_google_vision(file_path: str):
    try:
        from google.cloud import vision
        client = vision.ImageAnnotatorClient()
        with open(file_path, 'rb') as image_file:
            content = image_file.read()
        image = vision.Image(content=content)
        # Prefer document text detection for invoices/receipts
        response = client.document_text_detection(
            image=image,
            image_context={'language_hints': ['en']}
        )
        if response.error.message:
            raise RuntimeError(response.error.message)
        annotation = response.full_text_annotation
        if annotation and annotation.text:
            print(annotation.text)
        else:
            texts = response.text_annotations
            if texts:
                print(texts[0].description)
            else:
                print('')
    except Exception as e:
        print(f'Google Vision Error: {e}')
        sys.exit(1)


def use_tesseract(file_path: str):
    import pytesseract
    try:
        img = Image.open(file_path)
        img = ImageOps.exif_transpose(img)  # auto-rotate based on EXIF
        img = img.convert('L')  # grayscale
        img = img.point(lambda x: 0 if x < 160 else 255, '1')
        img = img.filter(ImageFilter.MedianFilter(size=3))
        img = img.filter(ImageFilter.SHARPEN)
        text = pytesseract.image_to_string(img, lang='eng')
        print(text)
    except Exception as e:
        print(f'Tesseract Error: {e}')
        sys.exit(1)


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print('No file provided')
        sys.exit(1)

    file_path = sys.argv[1]
    if os.environ.get('GOOGLE_APPLICATION_CREDENTIALS'):
        use_google_vision(file_path)
    else:
        use_tesseract(file_path)
