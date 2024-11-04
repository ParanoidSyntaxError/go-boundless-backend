# import mysql.connector
# import os

# HOST = os.getenv('host')
# USER = os.getenv('user')
# PASSWORD = os.getenv('password')
# DATABASE = "noderunner"


# def getDB():
#     dbConnection = mysql.connector.connect(host=HOST,user=USER, password=PASSWORD, database=DATABASE)
#     return dbConnection

# def commitQuery(query):
#     db = getDB()
#     cursor = db.cursor(prepared=True, dictionary=True)
#     cursor.execute(query)
#     db.commit()
#     cursor.close()
#     db.close()

# def grabQuery(query):
#     db = getDB()
#     cursor = db.cursor(prepared=True, dictionary=True)
#     cursor.execute(query)
#     data = cursor.fetchall()
#     cursor.close()
#     db.close()
#     return data