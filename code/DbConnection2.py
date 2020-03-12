import mysql.connector
from mysql.connector import Error, ProgrammingError

class DbConnection:
    def __init__(self, host, database):
        try:
            self.connection = mysql.connector.connect(host=host,
                                                database=database,
                                                user='root',
                                                password='hola123',
                                                )
            # if self.connection.is_connected():
            #     db_Info = self.connection.get_server_info()
                # print("Connected to MySQL Server version ", db_Info)
        except ProgrammingError as e:
            self.connection = None
            print(e.msg)
            raise e
        except Error as e:
            print(e.msg)
            raise e

    def query(self, query):
        res = {
            "error": False,
            "errorMessage": "",
            "result": []
        }
        try:
            self.cursor = self.connection.cursor(dictionary=True)
            self.cursor.execute(query)
            records = []
            while True:
                row = self.cursor.fetchone()
                if row == None:
                    break
                records.append(row)
            res["result"] = records if len(records) >= 2 else records[0] if len(records) >= 1 else None
        except ProgrammingError as e:
            res["error"] = True
            res["errorMessage"] = e.msg
        return res

    def close(self):
        if (not self.connection.is_connected()):
            raise Error("No connection available.")

        self.cursor.close()
        self.connection.close()