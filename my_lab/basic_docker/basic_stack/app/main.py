from flask import Flask
app = Flask(__name__)

@app.route('/')
def index():
    return "Hello from Flask app served by Nginx!"

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=8000)

