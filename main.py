import os
from app import app
from flask import request, jsonify
from werkzeug.utils import secure_filename

# limit to JPG images because thats all PIXELKNOT handles iirc
ALLOWED_EXTENSIONS = set(['jpg', 'jpeg'])

def allowed_file(filename):
	return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/')
def index():
	# build HTML response for anyone not using the API
	html = "<html><body valign='middle'><center>"
	html = html + "<div width='40%'></div>"
	html = html + "<div style='align:center;width:20%;padding:25px;margin:50px;border-radius:20px;background:#e8e8e8;'>"
	html = html + "<center><h1>StegOrKnot</h1>"
	html = html + "<h4>This is not the endpoint you're looking for...</h4><br>"
	html = html + "<br><b><em>Resource Endpoint</em>:</b>  /api/scan<br><br></center>"
	html = html + "</div><div width='40%'></div></center></body</html>"
	return html

# route to API, accepts POST request with multi part form data
@app.route('/api/scan', methods=['POST'])
def upload_file():
	# check if the post request has the file part
	if 'file' not in request.files:
		resp = jsonify({'error' : 'No file part in the request'})
		resp.status_code = 400
		return resp
	file = request.files['file']
	if file.filename == '':
		resp = jsonify({'error' : 'No file selected for uploading'})
		resp.status_code = 400
		return resp
	if file and allowed_file(file.filename):
		filename = secure_filename(file.filename)
		file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
		imgfile = app.config['UPLOAD_FOLDER'] + "/" + filename
		# open the image, read in a
		with open(imgfile, 'rb') as f:
			# read in the image
			s = f.read()
		# PIXEL KNOT byte string
		found = s.find(b'\xFF\xC0\x00\x11\x08')
		if found == -1:
			# not found -- this byte string always happens around the same series/place in the file
			resp = jsonify({'PixelKnot' : 'NO'})
		else:
			# Byte stirng was found, PixelKnot chances are high
			resp = jsonify({'PixelKnot': 'YES'})

		resp.status_code = 201
		return resp
	else:
		resp = jsonify({'error' : 'Allowed file types are jpg or jpeg'})
		resp.status_code = 400
		return resp

if __name__ == "__main__":
    app.run()
