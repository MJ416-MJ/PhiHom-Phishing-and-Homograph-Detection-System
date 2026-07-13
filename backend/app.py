from flask import Flask,request
from flask import jsonify
from flask_cors import CORS
from detector import analyse_url

app = Flask(__name__)
CORS(app)
@app.route('/analyse',methods=['POST'])
def analyse():
    result = request.get_json(force=True)
    if(result) is None:
        return jsonify({"error": "No JSON sent"}), 400
    extracted_url = result["url"]
    if extracted_url is None:
        return jsonify({"error": "No URL provided"}), 400
    return jsonify(analyse_url(extracted_url))

if __name__ == "__main__":
    app.run(debug=False, use_reloader=False,)
    
