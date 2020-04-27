import os
from flask import Flask, request, jsonify
from werkzeug.utils import secure_filename
from struct import unpack
from wand.image import Image

UPLOAD_FOLDER = os.path.abspath(os.path.dirname(__file__)) + "/img2scan"	# set a folder to upload images to
# I have a cronjob on my server to delete all the uploaded images, but it's probably smarter to delete after the scan is done..

app = Flask(__name__)
app.secret_key = "YOUR_SECRET_KEY_HERE"			# you can just make something up.
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER		# set the upload folder.
app.config['MAX_CONTENT_LENGTH'] = 8 * 1024 * 1024	# set a limit of 8mb file size.

ALLOWED_EXTENSIONS = set(['gif', 'png', 'pdf', 'jpg', 'jpeg'])	# limit filetypes to image formats


filename = ""		# define an empty variable for the file that's being scanned

def allowed_file(filename):
	return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/')
def index():
	# build HTML response for anyone not using the API properly (and trying to view as a webpage)
	html = "<html><body valign='middle'><center>"
	html += "<div width='40%'></div>"
	html += "<div style='align:center;width:20%;padding:25px;margin:50px;border-radius:20px;background:#e8e8e8;'>"
	html += "<center><h1>StegOrKnot</h1>"
	html += "<h4>This is not the endpoint you're looking for...</h4><br>"
	html += "<ul><b><em>Resource Endpoints</em>:</b>"
	html += "<li><b>/api/scan</b><br><em>*check for PixelKnot</em></li>"
	html += "<li><b>/api/embed</b><br><em>*check for appended files</em></li>"
	html += "</ul></center>"
	html += "</div><div width='40%'></div></center></body</html>"
	return html		# return the string of HTML for the browser to display

# route to PixelKnot scan, accepts POST request with multi part form data
@app.route('/api/scan', methods=['POST'])
def check_PixelKnot():
	# check if the post request has the file part
	if 'file' not in request.files:		# file didn't attach for some reason
		resp = jsonify({'error' : 'No file part in the request'})
		resp.status_code = 400
		return resp
	file = request.files['file']
	if file.filename == '':			# no file selected
		resp = jsonify({'error' : 'No file selected for uploading'})
		resp.status_code = 400
		return resp
	if file and allowed_file(file.filename):	# make sure the filetype is allowed
		filename = secure_filename(file.filename)
		file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
		imgfile = app.config['UPLOAD_FOLDER'] + "/" + filename
		# open the image to read as bytes
		with open(imgfile, 'rb') as f:
			# read in the image
			s = f.read()
		# PIXEL KNOT byte string
		found = s.find(b'\xFF\xC0\x00\x11\x08')	# byte string present in all pixelknot processed images
							# there's a possibility of false positives of course
			
		wbStego = s.find(b'\x00\xFF')		# will work on this later

		if found == -1:
			# not found -- this byte string always happens around the same series/place in the file
			resp = jsonify({'PixelKnot':'NO'})
		else:
			# Byte stirng was found, PixelKnot chances are high
			resp = jsonify({'PixelKnot':'YES'})

		resp.status_code = 201
		return resp
	else:
		resp = jsonify({'error' : 'Allowed file types are jpg or jpeg'})
		resp.status_code = 400
		return resp


# scan for appended files, accepts POST request with multi part form data
@app.route('/api/embed', methods=['POST'])
def check_Embed():
	# check if the post request has the file part
	if 'file' not in request.files:
		resp2 = jsonify({'error': 'No file part in the request'})
		resp2.status_code = 400
		return resp2
	file = request.files['file']
	if file.filename == '':
		resp2 = jsonify({'error': 'No file selected for uploading'})
		resp2.status_code = 400
		return resp
	if file and allowed_file(file.filename):
		filename = secure_filename(file.filename)
		file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
		imgfile = app.config['UPLOAD_FOLDER'] + "/" + filename
		# open the image, read in a
		f = open(imgfile, 'rb')
		# read in the image
		s = f.read()
		# wbStego byte string
		#wbStego = s.find(b'\x00\xFF')

		# byte strings / Magic File Numbers for a variety of file types
		png = s.find(b"\x89\x50\x4E\x47\x0D\x0A\x1A\x0A", 2)
		jpg = s.find(b"\xff\xd8\xff\xe0", 2)
		gif = s.find(b"\x47\x49\x46\x38\x39\x61", 2)
		zipf = s.find(b"\x50\x3b\x03\x04")
		rar = s.find(b"\x52\x61\x72\x21\x1a\x07")	# rar
		z7z = s.find(b"\x37\x7a\xbc\xaf\x27\x1c")	# 7zip
		sqlite = s.find(b"\x53\x51\x4c\x69\x74\x65\x20\x66\x6f\x72\x6d\x61\x74\x20\x33\x00")	# SQLite database
		telgd = s.find(b"\x54\x44\x46\x24")		# telegram desktop file
		telenc = s.find(b"\x54\x44\x45\x46")		# telegram encrypted file
		pdf = s.find(b"\x25\x50\x44\x46\x2d")		# pdf file
		lzip = s.find(b"\x4C\x5A\x49\x50")		# LZip archive
		pkzip = s.find(b"\x50\x4B\x03\x04")		# PKZip compressed archive
		utf8 = s.find(b"\xEF\xBB\xBF")			# UTF-8 encoded data/text
		tar = s.find(b"\x75\x73\x74\x61\x72")		# TAR archive
		xzlz = s.find(b"\xFD\x37\x7A\x58\x5A\x00\x00")		# XZ compressed archive
		doc = s.find(b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1")	# Microsoft Office file

		# define some empty variables to hold a yes/no RE: embedded file
		resp2 = ''
		resp_jpg = ''
		resp_png = ''
		resp_gif = ''
		resp_zip = ''
		resp_rar = ''
		resp_z7z = ''
		resp_sql = ''
		resp_tel = ''
		resp_ten = ''
		resp_lz = ''
		resp_pkz = ''
		resp_utf = ''
		resp_xz = ''
		resp_tar = ''
		resp_doc = ''

		if png == -1 & jpg == -1 & gif == -1 & zip == -1 & rar == -1 & z7z == -1 & sqlite == -1 & telgd == -1 & telenc == -1 & lzip == -1 & pkzip == -1 & pdf == -1 & utf8 == -1 & tar == -1 & xzlz == -1 & doc == -1:
			# nothing found
			resp2 = jsonify({'Embedded':'NO'})
			resp2.status_code = 201
			return resp2


		if zipf != -1:
			fdpng = open(app.config['UPLOAD_FOLDER'] + "/" + filename, "rb")
			fdpng.seek(zip)
			dat = fdpng.read()
			#x = dat.find(b"\x06\x05\x4b\x50")
			resp_zip = "{'ZIP':'" + str(dat.__sizeof__()) + " bytes'}"


		if pkzip != -1:
			fdpng = open(app.config['UPLOAD_FOLDER'] + "/" + filename, "rb")
			fdpng.seek(pkzip)
			dat = fdpng.read()
			#x = dat.find(b"\x06\x05\x4b\x50")
			#xend = dat.endswith(b"\x06\x05\x4b\x50")
			resp_pkz = "{'PKZip':'" + str(dat.__sizeof__()) + " bytes'}"


		if utf8 != -1:
			fdpng = open(app.config['UPLOAD_FOLDER'] + "/" + filename, "rb")
			fdpng.seek(utf8)
			dat = fdpng.read()
			resp_utf = "{'UTF-8 Text':'" + str(dat.__sizeof__()) + " bytes'}"


		if xzlz != -1:
			fdpng = open(app.config['UPLOAD_FOLDER'] + "/" + filename, "rb")
			fdpng.seek(xzlz)
			dat = fdpng.read()
			resp_xz = "{'XZ/LZMA Compressed Archive':'" + str(dat.__sizeof__()) + " bytes'}"


		if rar != -1:
			fdpng = open(app.config['UPLOAD_FOLDER'] + "/" + filename, "rb")
			fdpng.seek(rar)
			dat = fdpng.read()
			print("RAR :" + str(dat.__sizeof__()))
			num = dat.count(b"\x89\x50\x4E\x47\x0D\x0A\x1A\x0A", 1, dat.__sizeof__())
			resp_rar = "{'RAR':'" + str(dat.__sizeof__()) + " bytes'}"


		if png != -1:
			fdpng = open(app.config['UPLOAD_FOLDER'] + "/" + filename, "rb")
			pngb = fdpng.read()
			pngoffset = pngb.find(b"\x89\x50\x4E\x47\x0D\x0A\x1A\x0A", 2)  # Magic bytes
			endofpng = pngb.find(b"\x49\x45\x4E\x44\xAE\x42\x60\x82", pngoffset)
			fdpng.seek(pngoffset)
			png_length = unpack('i', fdpng.read(4))  # Read size of JPEG data
			dat = fdpng.read(png_length[0])
			x = dat.endswith(b"\x49\x45\x4E\x44\xAE\x42\x60\x82")

			if x == True:
				resp_png = "{'PNG':'" + str(dat.__sizeof__()) + " bytes'}"
			else:
				fdpng.seek(endofpng)
				ep = fdpng.read()
				print(ep.__sizeof__())
				xlen = int(dat.__sizeof__()) - int(ep.__sizeof__())
				print("PNG :" + str(xlen))

				resp_png = "{'PNG':'approx " + str(xlen) + " bytes'}"

		if z7z != -1:
			fdpng = open(app.config['UPLOAD_FOLDER'] + "/" + filename, "rb")
			fdpng.seek(z7z)
			dat = fdpng.read()
			resp_z7z = "{'7Zip Compressed Archive':'" + str(dat.__sizeof__()) + " bytes'}"


		if pdf != -1:
			fdpng = open(app.config['UPLOAD_FOLDER'] + "/" + filename, "rb")
			fdpng.seek(pdf)
			dat = fdpng.read()
			resp_pdf = "{'PDF':'" + str(dat.__sizeof__()) + " bytes'}"


		if sqlite != -1:
			fdpng = open(app.config['UPLOAD_FOLDER'] + "/" + filename, "rb")
			fdpng.seek(sqlite)
			dat = fdpng.read()
			resp_sql = "{'SQLite Database':'" + str(dat.__sizeof__()) + " bytes'}"


		if telgd != -1:
			fdpng = open(app.config['UPLOAD_FOLDER'] + "/" + filename, "rb")
			fdpng.seek(telgd)
			dat = fdpng.read()
			resp_tel = "{'Telegram Desktop File':'" + str(dat.__sizeof__()) + " bytes'}"


		if telenc != -1:
			fdpng = open(app.config['UPLOAD_FOLDER'] + "/" + filename, "rb")
			fdpng.seek(telenc)
			dat = fdpng.read()
			resp_ten = "{'Telegram Encrypted File':'" + str(dat.__sizeof__()) + " bytes'}"


		if lzip != -1:
			fdpng = open(app.config['UPLOAD_FOLDER'] + "/" + filename, "rb")
			fdpng.seek(lzip)
			dat = fdpng.read()
			resp_lz = "{'LZIP Compressed Archive':'" + str(dat.__sizeof__()) + " bytes'}"


		if jpg != -1:
			fdpng = open(app.config['UPLOAD_FOLDER'] + "/" + filename, "rb")
			fdpng.seek(jpg)
			dat = fdpng.read()
			resp_jpg = "{'JPEG/JPG Image':'" + str(dat.__sizeof__()) + " bytes'}"


		if gif != -1:
			fdpng = open(app.config['UPLOAD_FOLDER'] + "/" + filename, "rb")
			fdpng.seek(gif)
			dat = fdpng.read()
			resp_gif = "{'GIF Image':'" + str(dat.__sizeof__()) + " bytes'}"


		if tar != -1:
			fdpng = open(app.config['UPLOAD_FOLDER'] + "/" + filename, "rb")
			fdpng.seek(tar)
			dat = fdpng.read()
			resp_tar = "{'TAR Compressed Archive':'" + str(dat.__sizeof__()) + " bytes'}"


		if doc != -1:
			fdpng = open(app.config['UPLOAD_FOLDER'] + "/" + filename, "rb")
			fdpng.seek(doc)
			dat = fdpng.read()
			resp_doc = "{'MS Office File':'" + str(dat.__sizeof__()) + " bytes'}"



		resp2 = jsonify({'Embedded Files':'[' + resp_jpg + resp_png + resp_gif + resp_zip + resp_tar + resp_rar + resp_z7z + resp_sql + resp_pkz + resp_tel + resp_ten + resp_lz + resp_doc + resp_xz + resp_utf + ']'})
		resp2.status_code = 201

		return resp2

	else:
		# 
		resp2 = jsonify({'error': 'Incompatible file type--only image formats allowed.'})
		resp2.status_code = 400
		return resp2


if __name__ == "__main__":
    app.run()
