# stegorknot
REST API to check a JPG for indications of PixelKnot, a common mobile steganography app for Android


Responses Back from API will be either an "error" message or an indicator of yes/no regarding PixelKnot.

If an image contains embedding by PixelKnot, you'll receive a response of:  {'PixelKnot' : 'YES'}
If the image does NOT contain any indicators of PixelKnot, you'll receive a response of:  {'PixelKnot' : 'NO'}


ERRORS / JSON RESPONSE:
 - tried to upload a non-supported filetype.
    {'error' : 'Allowed file types are jpg or jpeg'}
    
 - image didn't send properly
    {'error' : 'No file part in the request'}
    
 - no image selected
    {'error' : 'No file selected for uploading'}
    
 
