def check_type_of_params(params, request_elements):
    checks = {k: True if  isinstance(request_elements[k], v) else False for k, v in params.items()}
    if False in checks.values():
        # message = [k for k, v in checks.items() if v == False]
            # lambda: expression
        return "Type error in parameter(s): " \
            + (", ".join(map(lambda parameter: "('" + parameter[0] + "': must be '" + parameter[1].__name__ + "')", [(k, params[k]) for k, v in checks.items() if v == False]))) \
            + "."

        return map(lambda parameter, parameter_type: "('" + parameter + "': must be '" + parameter_type.__name__ + "')", [])
    return None

def check_params(params, request_elements):
    checks = {k: True if k in request_elements.keys() else False for k in params.keys()}
    if False in checks.values():
        # message = [k for k, v in checks.items() if v == False]
        return "Missing parameter(s): " \
            + (", ".join(map(lambda parameter: "'" + str(parameter) + "'", [k for k, v in checks.items() if v == False]))) \
            + "."
    return None

if __name__ == "__main__":
    request_elements = {"usuario": {}, "password": "", "tipo": ""}
    params = {"usuario": str, "password": str, "tipo": bool}

    param_check = check_params(params, request_elements)
    print(param_check)

    if not param_check:
        type_check = check_type_of_params(params, request_elements)
        print(type_check)