import sqlite3

connection = sqlite3.connect('database.db')


########################################################################################################################
#Iniciando las bases de datos
########################################################################################################################
'''with open('sqlchema.sql') as f:
    connection.executescript(f.read())

cur = connection.cursor()
# add roles

cur.execute("INSERT INTO roles (roles_name) VALUES (?)",
            (['admin'])
            )
cur.execute("INSERT INTO roles (roles_name) VALUES (?)",
            (['user'])
            )
cur.execute("INSERT INTO roles (roles_name) VALUES (?)",
            (['contributor'])
            )
cur.execute("INSERT INTO roles (roles_name) VALUES (?)",
            (['visitante'])
            )

# add users

cur.execute("INSERT INTO users (first_name,last_name ,email,password ,role ) VALUES (?,?,?,?,?)",
            (['Mike', 'Colbert', 'mike@mike.com', 'abc123', 'admin'])
            )

connection.commit()
connection.close()
'''
########################################################################################################################
#Revisar los usuarios
########################################################################################################################
import sqlite3
conn = sqlite3.connect('database.db')
cur = conn.cursor()
delete_user = cur.execute("SELECT * FROM users").fetchall()
conn.close()
delete_user


########################################################################################################################
#Agregar Roles
########################################################################################################################
import sqlite3
conn = sqlite3.connect('database.db')
cur = conn.cursor()
cur.execute("INSERT INTO roles (roles_name) VALUES (?)",
            (['CUMPLIMIENTO'])
            )
conn.commit()
conn.close()

import sqlite3
conn = sqlite3.connect('database.db')
cur = conn.cursor()
cur.execute("INSERT INTO roles (roles_name) VALUES (?)",
            (['BANCA DIGITAL'])
            )
conn.commit()
conn.close()


import sqlite3
conn = sqlite3.connect('database.db')
cur = conn.cursor()
cur.execute("INSERT INTO roles (roles_name) VALUES (?)",
            (['AUDITORIA INTERNA'])
            )
conn.commit()
conn.close()

import sqlite3
conn = sqlite3.connect('database.db')
cur = conn.cursor()
cur.execute("INSERT INTO roles (roles_name) VALUES (?)",
            (['INCLUSION FINANCIERA'])
            )
conn.commit()
conn.close()

import sqlite3
conn = sqlite3.connect('database.db')
cur = conn.cursor()
cur.execute("INSERT INTO roles (roles_name) VALUES (?)",
            (['FRAUDES'])
            )
conn.commit()
conn.close()

import sqlite3
conn = sqlite3.connect('database.db')
cur = conn.cursor()
cur.execute("INSERT INTO roles (roles_name) VALUES (?)",
            (['RIESGOS'])
            )
conn.commit()
conn.close()


from google.cloud import bigquery
from google.oauth2 import service_account
credentials = service_account.Credentials.from_service_account_file(
'portal-hatun-data-c484ca25008f.json')


def create_table():
    project_id = 'portal-hatun-data'
    client = bigquery.Client(credentials=credentials, project=project_id)
    table_id ="portal-hatun-data.Portal_data.roles"
    schema = [
        bigquery.SchemaField("id", "INTEGER", mode="REQUIRED"),
        bigquery.SchemaField("roles", "STRING", mode="REQUIRED")

    ]
    table = bigquery.Table(table_id, schema=schema)
    table = client.create_table(table)
    print(
        "Created table {}.{}.{}".format(table.project, table.dataset_id, table.table_id)
    )

create_table()

import pandas_gbq
import pandas as pd
project = 'portal-hatun-data'
schema  = 'Portal_data'
pandas_gbq.context.credentials = credentials
client = bigquery.Client(credentials=credentials, project=credentials.project_id,)


#Adding first row
df = pd.DataFrame.from_dict({
    'id': [1,2,3],
    'roles': ["ADMIN","USUARIO","ESTADO"],

})
df.to_gbq(schema + '.' + "roles",project_id=project,if_exists='append') ##
df=df.drop(index=df.index[0], axis=0)



import pandas_gbq
import pandas as pd
project = 'portal-hatun-data'
schema  = 'Portal_data'
pandas_gbq.context.credentials = credentials
client = bigquery.Client(credentials=credentials, project=credentials.project_id,)


#Adding first row
df = pd.DataFrame.from_dict({
    'id': [1,2,3],
    'roles': ["ADMIN","USUARIO","ESTADO"],

})
df.to_gbq(schema + '.' + "roles",project_id=project,if_exists='append') ##
df=df.drop(index=df.index[0], axis=0)



#Adding first row
df = pd.DataFrame.from_dict({
    'id': [1,2,3],
    'roles': ["ADMIN","USUARIO","ESTADO"],

})
df.to_gbq(schema + '.' + "roles",project_id=project,if_exists='append') ##
df=df.drop(index=df.index[0], axis=0)

import datetime
df = pd.DataFrame.from_dict({
    'id': [1],
    'first_name': ["LUIGGI"],
'last_name': ["SILVA"],
'email': ["luiggi@bn.com.pe"],
'password': ["qwe123"],
'role': ["admin"],
'date_added': [datetime.datetime.now(),],
'date_modified': [datetime.datetime.now()],
})


df.to_gbq(schema + '.' + "users",project_id=project,if_exists='replace') ##

from google.cloud import bigquery
from google.oauth2 import service_account
import pandas_gbq
import pandas as pd
project = 'portal-hatun-data'
schema  = 'Portal_data'
credentials = service_account.Credentials.from_service_account_file(
'portal-hatun-data-c484ca25008f.json')
pandas_gbq.context.credentials = credentials
client = bigquery.Client(credentials=credentials, project=credentials.project_id,)

query_job = client.query("""
   SELECT *
   FROM Portal_data.users
   LIMIT 1000 """)

results = query_job.result().to_dataframe(
        # Optionally, explicitly request to use the BigQuery Storage API. As of
        # google-cloud-bigquery version 1.26.0 and above, the BigQuery Storage
        # API is used by default.
        create_bqstorage_client=True,
    )


query_users = client.query("""SELECT * FROM Portal_data.users where email =""" + '"' + "luiggi"+ '"')
users = query_users.result().to_dataframe(create_bqstorage_client=True, )
user = users.iloc[0, :]



query_users = client.query("""SELECT * FROM Portal_data.users where email =""" + '"' + ''.join(["luiggi6"])+ '"')
users = query_users.result().to_dataframe(create_bqstorage_client=True, )
user = users.iloc[0, :]
users.shape[0]
user[3].lower()
user[5]
user[0]
user[1]

query_users = client.query("""
              SELECT *
              FROM Portal_data.users
              """)
users = query_users.result().to_dataframe(create_bqstorage_client=True, )

for row in users.values:
    print(row[1])

import pyrebase

config = {
    "apiKey": "apiKey",
    "authDomain": "projectId.firebaseapp.com",
    "databaseURL": "https://databaseName.firebaseio.com",
    "storageBucket": "projectId.appspot.com"
}

firebase = pyrebase.initialize_app(config)