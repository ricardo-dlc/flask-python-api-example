import time
from flask import Flask
from flask import jsonify
from DbConnection import DbConnection

app = Flask(__name__)
# connection = None


@app.route('/', methods=['GET'])
def home():
    # connection = None
    # try:
    connection = DbConnection("mysql-app", "usuarios")
    res = jsonify(connection.query("SELECT id_user, usuario, nombre, apellido FROM login;"))
    res.status_code = 200
    return res
    # print(result)
    # print(len(result))
    # return '<h1>Hello Docker!</h1>'
    # except Exception as e:
        # print(e.__cause__)

if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)