import os
from flask import Flask

UPLOAD_FOLDER = os.path.abspath(os.path.dirname(__file__)) + "/img2scan"

app = Flask(__name__)
app.secret_key = "app1key4220k3Vk3y4pphft3wo85dtkhyu"
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024