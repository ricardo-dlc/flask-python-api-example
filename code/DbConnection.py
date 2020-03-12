import mysql.connector
from mysql.connector import Error

class DbConnection:
    def __init__(self, host, database):
        try:
            self.connection = mysql.connector.connect(host=host,
                                                database=database,
                                                user='root',
                                                password='hola123',
                                                )
            if self.connection.is_connected():
                db_Info = self.connection.get_server_info()
                print("Connected to MySQL Server version ", db_Info)

        except Error as e:
            print(e.msg)
            raise e

    def query(self, query):
        self.cursor = self.connection.cursor()
        self.cursor.execute(query)
        records = []
        while True:
            row = self.cursor.fetchone()
            if row == None:
                break
            records.append(row)
        return records

    def close(self):
        if (not self.connection.is_connected()):
            raise Error("No connection available.")

        self.cursor.close()
        self.connection.close()
        print("MySQL connection is closed")