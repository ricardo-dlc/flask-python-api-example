from datetime import datetime, timedelta, timezone
from flask import Flask, request, jsonify, make_response
from DbConnection2 import DbConnection
from flask.logging import create_logger
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
import logging
import jwt
import bcrypt
import cryptography
from jwcrypto import jwt, jwk, jws

def read_file(filename):
    with open(filename, "rb") as pemfile:
        return jwk.JWK.from_pem(pemfile.read())
    # fh = open(filename, "r")
    # try:
    #     return fh.read()
    # finally:
    #     fh.close()

logging.basicConfig(level=logging.DEBUG)
app = Flask(__name__)
# app.config['PRIVATE_KEY'] = 'Th1s1ss3cr3t'
app.config['PRIVATE_KEY'] = read_file('./keys/jwt-key')
app.config['PUBLIC_KEY'] = read_file('./keys/jwt-key.pub')
app.config['EXP_TIME'] = 30
logger = create_logger(app)

def query(connection, query):
    pass

def consoleLog(message, type="debug"):
    time = datetime.now().strftime("%d/%m/%Y %I:%M:%S%p")
    if type == "info":
        logger.info(time)
        logger.info(message)
    elif type == "error":
        logger.error(time)
        logger.error(message)
    elif type ==  "warning":
        logger.warning(time)
        logger.warning(message)
    else:
        logger.debug(time)
        logger.debug(message)

def response(message="", error=False, status=200, data=None, headers=None):
    date_object = datetime.now(timezone(timedelta(hours=-5)))
    date_string = ('{:%Y-%m-%d %X%Z}'.format(date_object))

    if not data:
        json = jsonify(status=status, message=message, error=error, datetime=date_string)
    else:
        json = jsonify(status=status, message=message, error=error, datetime=date_string, data=data)

    return make_response(json, status, headers)

def token_required(handler):
    @wraps(handler)
    def decorator(*args, **kwargs):
        auth_token = None
        auth_header = request.headers.get('Authorization')

        if auth_header:
            auth_type = auth_header.split(" ")[0]
            auth_token = auth_header.split(" ")[1]

        if not auth_token:
            return response('Missing token', True, 401, headers={'WWW-Authenticate': 'Bearer realm="Missing token"'})

        if auth_type != 'Bearer':
            return response('Invalid type of auth', True, 401, headers={'WWW-Authenticate': 'Bearer realm="Invalid type of auth"'})

        #########PYJWT#################

        # try:
        #     decoded = jwt.decode(auth_token.encode('UTF-8'), app.config['PUBLIC_KEY'], algorithms=['RS256'])
        #     consoleLog(decoded)
        #     if decoded['public_id'] == 1:
        #         user = 9999
        #     current_user = user
        #     kwargs ['current_user'] = current_user
        # except (jwt.DecodeError):
        #     return response('Invalid token', True, 400, headers={'WWW-Authenticate': 'Bearer realm="Invalid token"'}, result=auth_token)
        # except (jwt.ExpiredSignatureError):
        #     return response('Token expired', True, 401, headers={'WWW-Authenticate': 'Bearer realm="You need to login again"'}, result=auth_token)

        #########PYJWT#################

        try:
            payload = jwt.JWT(key=app.config['PUBLIC_KEY'], jwt=auth_token).claims
            kwargs['payload'] = payload
        except (jws.InvalidJWSSignature):
            return response('Invalid token', True, 400, headers={'WWW-Authenticate': 'Bearer realm="Invalid token"'})
        except (jwt.JWTExpired):
            consoleLog(jwt.JWTExpired)
            return response('Expired token', True, 400, headers={'WWW-Authenticate': 'Bearer realm="Expired token"'})
        return handler(*args, **kwargs)

    return decorator

@app.route('/signin', methods=['POST'])
def register():
    try:
        req = request.get_json()
    except:
        return response('Provide information for register', True, 400)

    try:
        connection = DbConnection("mysql-app", "usuarios")
        query = """
        SELECT
            1
        FROM
            login
        WHERE
            usuario = '{}'
        LIMIT 1;
        """.format(req['usuario'])
        # consoleLog(query)
        res = connection.query(query)
        message = res["errorMessage"] if res["error"] else ("" if res["result"] else "No data")
        result = res["result"]
        status = 400 if res["error"] else 200
        error = True if res["error"] else False
        connection.close()
        consoleLog("Connection closed")
    except Exception as e:
        consoleLog(str(e))
        message = str(e)
        error = True
        status = 400
        result = []

    if error:
        return response(message, error, status, result)

    if not result:
        params = {"usuario": str, "password": str}

        params_check = check_params(params, req)
        if params_check:
            return response(params_check, True, 400)

        type_check = check_type_of_params(params, req)
        if type_check:
            return response(type_check, True, 400)

        return response("Success")

    return response('User already exists', True, 400)

def check_params(params, request_elements):
    checks = {k: True if k in request_elements.keys() else False for k in params.keys()}
    consoleLog([k for k, v in checks.items() if v == False])
    if False in checks.values():
        # message = [k for k, v in checks.items() if v == False]
        return "Missing parameter(s): " \
            + (", ".join(map(lambda parameter: "'" + str(parameter) + "'", [k for k, v in checks.items() if v == False]))) \
            + "."
    return None

def check_type_of_params(params, request_elements):
    checks = {k: True if  isinstance(request_elements[k], v) else False for k, v in params.items()}
    if False in checks.values():
        # message = [k for k, v in checks.items() if v == False]
        return "Type error in parameter(s): " \
            + (", ".join(map(lambda parameter: "('" + parameter[0] + "': must be '" + parameter[1].__name__ + "')", [(k, params[k]) for k, v in checks.items() if v == False]))) \
            + "."
    return None

@app.route('/login', methods=['POST'])
def login():
    auth = request.authorization

    if not auth or not auth.username or not auth.password:
        return response('Missing credentials', True, 401, headers={'WWW-Authenticate': 'Basic realm="Credentials Required"'})

    try:
        connection = DbConnection("mysql-app", "usuarios")
        query = """
        SELECT
            usuario,
            password
        FROM
            login
        WHERE
            usuario = '{}';
        """.format(auth.username)
        res = connection.query(query)
        message = res["errorMessage"] if res["error"] else ("" if res["result"] else "No data")
        result = res["result"]
        status = 400 if res["error"] else 200
        error = True if res["error"] else False
        connection.close()
        consoleLog("Connection closed")
    except Exception as e:
        consoleLog(str(e))
        message = str(e)
        error = True
        status = 400
        result = []

    if error:
        return response(message, error, status, result)

    if not result:
        return response("User not found", True, 401, headers={'WWW-Authenticate': 'Basic realm="User not found"'})

    if bcrypt.checkpw(auth.password.encode('utf-8'), result['password'].encode('utf-8')):
        # bcrypt.hashpw(password="".encode('utf-8'), salt=bcrypt.gensalt(12))
        # bcrypt.checkpw(password.encode('utf-8'), hashpwd.encode('utf-8'))
        #########PYJWT#################

        # now = datetime.utcnow()
        # payload = {
        #     'iss': 'CADU API Server',
        #     'sub': auth.username,
        #     'iat': now,
        #     'exp' : now + timedelta(minutes=app.config['EXP_TIME']),
        #     # 'public_id': 1
        # }
        # token = jwt.encode(payload, app.config['PRIVATE_KEY'], algorithm='RS256').decode('UTF-8')

        #########PYJWT#################
        try:
            date_object = datetime.now(timezone(timedelta(hours=-5)))
            header = {"typ": "JWT", "alg": "RS256"}
            payload = {
                'iss': 'CADU API Server',
                'sub': auth.username,
                'iat': date_object.timestamp(),
                'exp' : (date_object + timedelta(minutes=app.config['EXP_TIME'])).timestamp()
            }
            Token = jwt.JWT(header=header, claims=payload)
            consoleLog(app.config['PRIVATE_KEY'])
            Token.make_signed_token(app.config['PRIVATE_KEY'])
            return response(result={'token' : Token.serialize()})
        except ValueError:
            return response('Unable to create a valid key', True, 401, headers={'WWW-Authenticate': 'Basic realm="Invalid private key"'})
        except AttributeError:
            return response('Unable to create a valid key', True, 401, headers={'WWW-Authenticate': 'Basic realm="Unable to create a valid key'})
        except Exception:
            return response('Unexpected error', True, 401, headers={'WWW-Authenticate': 'Basic realm="Unexpected"'})


    return response('Could not verify', True, 401, headers={'WWW-Authenticate': 'Basic realm="Invalid Credentials"'})

@app.route('/usuarios', methods=['GET', 'POST'])
@token_required
def usuarios(**kwargs):
    try:
        connection = DbConnection("mysql-app", "usuarios")
        query = '''
        SELECT
            id_user,
            usuario,
            nombre,
            apellido
        FROM
            login
        LIMIT 10;
        '''
        res = connection.query(query)
        message = res["errorMessage"] if res["error"] else ("" if res["result"] else "No data")
        result = res["result"]
        status = 400 if res["error"] else 200
        error = True if res["error"] else False
        connection.close()
        consoleLog("Connection closed")
    except Exception as e:
        consoleLog(str(e), "error")
        message = str(e)
        error = True
        status = 400
        result = []

    return response(message, error, status, result)

@app.route('/usuarios/<int(signed=True):id>', methods=['POST'])
@token_required
def usuarioPorId(id, **kwargs):
    consoleLog(kwargs['payload'])
    consoleLog(request.get_json())
    try:
        connection = DbConnection("mysql-app", "usuarios")
        res = connection.query(("SELECT id_user, usuario, nombre, apellido FROM login WHERE id_user = {};").format(id))
        message = res["errorMessage"] if res["error"] else ("" if res["result"] else "No data")
        result = res["result"]
        status = 400 if res["error"] else 200
        error = True if res["error"] else False
        connection.close()
        consoleLog("Connection closed")
    except Exception as e:
        consoleLog(str(e))
        message = str(e)
        error = True
        status = 400
        result = []

    return response(message, error, status, result)

if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)