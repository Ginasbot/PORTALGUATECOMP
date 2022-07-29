########################################################################################################################
#                                         CONSTRUCCION PORTAL ANALITICA
#  Autor : Luiggi Silva  / luiggi11.16@gmail.com /996261574
#
########################################################################################################################


import os
from dotenv import load_dotenv
import datetime
# from bson.objectid import ObjectId
from flask import Flask, request, render_template, redirect, url_for, session, flash
from flask_login import LoginManager, UserMixin, current_user, login_user, logout_user, login_required
# import bcrypt
from functools import wraps
from flask import Flask, render_template, url_for, request
import pandas as pd
import pickle
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.naive_bayes import MultinomialNB

# import sqlite3
app = Flask(__name__)
app.secret_key = os.urandom(24)
login_manager = LoginManager()
login_manager.init_app(app)


# import logging
# from logging.handlers import RotatingFileHandler
# from firebase_admin import credentials, firestore, initialize_app


########################################################################################################################
#                                                      MANEJO DE LOGS
#
########################################################################################################################
# handler = RotatingFileHandler(os.path.join(app.root_path, 'logs', 'oboeqa_web.log'), maxBytes=102400, backupCount=10)
# logging_format = logging.Formatter(
#   '%(asctime)s - %(levelname)s - %(filename)s - %(funcName)s - %(lineno)s - %(message)s')

# handler.setFormatter(logging_format)
# app.logger.addHandler(handler)

@app.errorhandler(404)
def page_not_found(error):
    app.logger.error(error)

    return 'This page does not exist', 404


@app.errorhandler(500)
def special_exception_handler(error):
    app.logger.error(error)
    return '500 error', 500


def page_not_found(error):
    return 'This page does not exist', 404


app.error_handler_spec[None][404] = page_not_found
## necessary for python-dotenv ##
APP_ROOT = os.path.join(os.path.dirname(__file__), '..')  # refers to application_top
dotenv_path = os.path.join(APP_ROOT, '.env')
load_dotenv(dotenv_path)

########################################################################################################################
#                  CARGA DE ROLES Y USUARIOS
#
########################################################################################################################

from google.cloud import bigquery
from google.oauth2 import service_account
import pandas_gbq
import pandas as pd

project = 'portal-hatun-data'
schema = 'Portal_data'
credentials = service_account.Credentials.from_service_account_file('portal-hatun-data-c484ca25008f.json')
pandas_gbq.context.credentials = credentials
client = bigquery.Client(credentials=credentials, project=credentials.project_id, )

query_users = client.query("""
   SELECT *
   FROM Portal_data.users
   """)
users = query_users.result().to_dataframe(create_bqstorage_client=True, )

query_roles = client.query("""
   SELECT roles
   FROM  Portal_data.roles
   """)
roles = query_roles.result().to_dataframe(create_bqstorage_client=True, )
# conn = sqlite3.connect('database.db')
'''roles = conn.execute('SELECT roles_name FROM roles').fetchall()
users = conn.execute('SELECT * FROM users').fetchall()
conn.close()'''

login = LoginManager()
login.init_app(app)
login.login_view = 'login'


########################################################################################################################
#                  CONTROL DE LOGIN
#
########################################################################################################################
@login.user_loader
def load_user(username):
    query_users = client.query("""SELECT * FROM Portal_data.users where email =""" + '"' + username.lower() + '"')
    users = query_users.result().to_dataframe(create_bqstorage_client=True, )
    lu = users.iloc[0, :]

    if lu is None:
        return None
    else:
        return User(username=lu[3].lower(), role=lu[5], id=lu[0], name=lu[1])


def insertUser(first_name, last_name, email, password, role):
    date = datetime.datetime.now()
    # con = sqlite3.connect("database.db")
    ##cur = con.cursor()
    # c#ur.execute("INSERT INTO users (first_name,last_name,email,password,role,date_added,date_modified) VALUES (?,?,?,?,?,?,?)", (first_name,last_name,email.lower(),password,role,date,date))
    # c#on.commit()
    # con.close()
    query_users = client.query("""
                     SELECT max(id) id FROM Portal_data.users """)
    users = query_users.result().to_dataframe(create_bqstorage_client=True, )

    df = pd.DataFrame.from_dict({
        'id': users['id'][0] + 1

        ,
        'first_name': [first_name],
        'last_name': [last_name],
        'email': [email],
        'password': [password],
        'role': [role],
        'date_added': [date],
        'date_modified': [date],
    })
    df.to_gbq(schema + '.' + "users", project_id=project, if_exists='append')


class User:
    def __init__(self, id, username, role, name):
        self._id = id
        self.username = username
        self.role = role
        self.name = name

    @staticmethod
    def is_authenticated():
        return True

    @staticmethod
    def is_active():
        return True

    @staticmethod
    def is_anonymous():
        return False

    def get_id(self):
        return self.username


### custom wrap to determine role access  ###
def roles_required(*role_names):
    def decorator(original_route):
        @wraps(original_route)
        def decorated_route(*args, **kwargs):
            if not current_user.is_authenticated:
                print('The user is not authenticated.')
                return redirect(url_for('login'))

            print(current_user.role)
            print(role_names)
            if not current_user.role in role_names:
                print('The user does not have this role.')
                return redirect(url_for('login'))
            else:
                print('The user is in this role.')
                return original_route(*args, **kwargs)

        return decorated_route

    return decorator


########################################################################################################################
#                   CARGA DE PAGINAS REGISTRO
#
########################################################################################################################

# PAGINA PRINCIPAL
@app.route('/', methods=['GET', 'POST'])
def index():
    return render_template('Pagina-inicio.html')


########################################################################################################################

# PAGINA DE REGISTRO
@app.route('/register')
def register():
    return render_template('Menu_login/register_visitor.html')


@app.route('/MODELOS')
@login_required
def modelos():
    return render_template('reportes/MODELOS_PREDICCION.html')


########################################################################################################################

# PAGINA DE PRUEBAS
@app.route('/test_01')
def test_01():
    return render_template('CRISP-DM.html')


########################################################################################################################

# PAGINA DE LOGEO
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.method == 'POST':
        '''conn = sqlite3.connect('database.db')
        curs = conn.cursor()
        curs.execute("SELECT * FROM users where email = (?)", [request.form['username'].lower()])
        user = curs.fetchone()
        conn.close()'''
        print([request.form['username']])
        query_users = client.query(
            """SELECT * FROM Portal_data.users where email =""" + '"' + ''.join([request.form['username']]) + '"')
        users = query_users.result().to_dataframe(create_bqstorage_client=True, )
        user = users.iloc[0, :]

        if users.shape[0] == 0:
            flash("Ingrese correctamente su  usuario o contraseña!", category='error')
            return render_template('Menu_login/login Chasky.html')
        if users.shape[0] == 1 and user[4] == request.form['password']:
            user_obj = User(username=user[3].lower(), role=user[5], id=user[0], name=user[1])
            login_user(user_obj)
            next_page = request.args.get('next')

            if not next_page or url_parse(next_page).netloc != '':
                next_page = url_for('index')
                return redirect(next_page)
            flash("Ingreso Exitosamente!", category='success')
            return redirect(request.args.get("next") or url_for("index"))

        flash("Ingrese correctamente su  usuario o contraseña!", category='error')
    return render_template('Menu_login/login Chasky.html')


########################################################################################################################

# PAGINA DE DESLOGEO
@app.route('/logout', methods=['GET', 'POST'])
def logout():
    logout_user()
    flash('You have successfully logged out.', 'success')
    return redirect(url_for('login'))


########################################################################################################################
# PAGINA DE USUARIO
@app.route('/my-account/<user_id>', methods=['GET', 'POST'])
@login_required
# @roles_required('user', 'contributor', 'admin','visitor')
def my_account(user_id):
    '''conn = sqlite3.connect('database.db')
    curs = conn.cursor()
    curs.execute("SELECT * FROM users where user_id = (?)", [user_id])
    edit_account = curs.fetchone()
    conn.close()'''
    query_users = client.query("""SELECT * FROM Portal_data.users where id =""" + str(user_id))
    users = query_users.result().to_dataframe(create_bqstorage_client=True, )
    edit_account = users.iloc[0, :]
    print(users)
    # edit_account = users.find_one({'_id': ObjectId(user_id)})
    if users.shape[0] >= 1:
        return render_template('Menu_login/my-account2.html', user=edit_account)
    flash('User not found.', 'warning')
    return redirect(url_for('index'))


########################################################################################################################

# PAGINA DE ACTUALIZACION DE USUARIO
@app.route('/update-myaccount/<user_id>', methods=['GET', 'POST'])
@login_required
def update_myaccount(user_id):
    if request.method == 'POST':
        # conn = sqlite3.connect('database.db')
        # cur = conn.cursor()
        form = request.form
        password = request.form['password']
        first_name = form['first_name']
        last_name = form['last_name']
        email = form['email']
        role = form['role']
        date_added = form['date_added']
        date_modified = datetime.datetime.now()
        if form['password'] != form['confirm_password']:
            flash('La contraseña de validación es distinta a la contraseña', 'warning')
            return redirect(url_for('my_account', user_id=user_id))
        dml_statement = (
                '''UPDATE Portal_data.users SET 
                first_name =''' + '"' + first_name + '"' +
                ''',last_name =''' + '"' + last_name + '"' +
                ''',email =''' + '"' + email.lower() + '"' +
                ''',password =''' + '"' + password + '"' +
                ''',role =''' + '"' + role + '"' +
                ''',date_added =''' + '"' + str(date_added) + '"' +
                ''',date_modified =''' + '"' + str(date_modified) + '"' +
                '''where  id = ''' + str(user_id))
        query_job = client.query(dml_statement)
        query_job.result()
        # cur.execute("UPDATE users SET first_name = ?, last_name = ?, email = ?, password = ?, role = ? , date_added = ? , date_modified = ? where  user_id = (?)",
        #            (first_name, last_name, email.lower() , password,role,date_added,date_modified, user_id))
        # conn.commit()

        # update_account = cur.execute("SELECT * FROM users WHERE user_id = (?)", (user_id)).fetchone()

        query_users = client.query("""
                      SELECT * FROM Portal_data.users where id =""" + str(user_id))
        users = query_users.result().to_dataframe(create_bqstorage_client=True, )
        update_account = users.iloc[0, :]

        # conn.close()
        flash(update_account[3] + ' Su cuenta ha sido actualizada', 'success')
        return redirect(url_for('index'))
    return redirect(url_for('index'))


########################################################################################################################

# PAGINA DE ACTUALIZACION DE USUARIO
@app.route('/add-user', methods=['GET', 'POST'])
def visitor_add_user():
    if request.method == 'POST':
        form = request.form
        password = request.form['password']
        # conn = sqlite3.connect('database.db')
        # curs = conn.cursor()
        # curs.execute("SELECT * FROM users where email = (?)", [request.form['email'].lower()])
        # email = curs.fetchone()
        # conn.close()

        query_users = client.query("""
                   SELECT * FROM Portal_data.users where email =""" + '"' + request.form['email'].lower() + '"')
        users = query_users.result().to_dataframe(create_bqstorage_client=True, )
        try:
            email = users.iloc[0, :]
            existe = email.shape[0] >= 1
        except:
            existe = 0
        if existe >= 1:
            flash('This email is already registered.', 'warning')
            return redirect(url_for('visitor_users'))
        if request.form['password'] != request.form['confirm_password']:
            flash('La contraseña de validación es distinta a la contraseña', 'warning')
            return redirect(url_for('visitor_users'))
        if "@" not in request.form['email'].lower():
            flash('Ingrese un correo valido', 'warning')
            return redirect(url_for('visitor_users'))
        insertUser(form['first_name'], form['last_name'], form['email'].lower(), password, form['role'])

        flash(form['email'].lower() + ' El usuario ha sido agregado', 'success')
        return redirect(url_for('login'))
        # return redirect(url_for('visitor_users'))
    # conn = sqlite3.connect('database.db')
    query_roles = client.query("""
          SELECT roles
          FROM  Portal_data.roles
          """)
    roles = query_roles.result().to_dataframe(create_bqstorage_client=True, )
    # users = conn.execute('SELECT email FROM users').fetchall()

    query_users = client.query("""
              SELECT email
              FROM Portal_data.users
              """)
    users = query_users.result().to_dataframe(create_bqstorage_client=True, )
    # conn.close()

    return render_template('Menu_login/register_visitor.html', all_roles=roles, all_users=users)


########################################################################################################################

# PAGINA DE ACTUALIZACION DE USUARIO

@app.route('/users', methods=['GET', 'POST'])
def visitor_users():
    # conn = sqlite3.connect('database.db')
    query_roles = client.query("""
          SELECT roles
          FROM  Portal_data.roles
          """)
    roles = query_roles.result().to_dataframe(create_bqstorage_client=True, )
    query_users = client.query("""
                 SELECT email FROM Portal_data.users """)
    users = query_users.result().to_dataframe(create_bqstorage_client=True, )
    # conn.close()
    return render_template('Menu_login/register_visitor.html', all_roles=roles, all_users=users)


########################################################################################################################

# PAGINA DE EDICION USUARIO

@app.route('/edit-user-visitor/<user_id>', methods=['GET', 'POST'])
def visitor_edit_user(user_id):
    # conn = sqlite3.connect('database.db')
    # cur = conn.cursor()
    # edit_user =  cur.execute("select *  FROM  users WHERE user_id = (?)", (user_id)).fetchone()
    # conn.close()

    query_users = client.query("""
               SELECT * FROM Portal_data.users where id  =""" + '"' + user_id + '"')
    users = query_users.result().to_dataframe(create_bqstorage_client=True, )
    edit_user = users.iloc[0, :]

    # edit_user = users.find_one({'_id': ObjectId(user_id)})
    query_roles = client.query("""
          SELECT roles
          FROM  Portal_data.roles
          """)
    roles = query_roles.result().to_dataframe(create_bqstorage_client=True, )
    if edit_user:
        return render_template('Menu_login/edit-user 2.html', user=edit_user, all_roles=roles.find())
    flash('Usuario no encontrado!', 'warning')
    return redirect(url_for('visitor_users'))


########################################################################################################################

# FUNCIONES DE ADMINISTRACION

##########  Admin functionality -- Administracion de usuarios ##########################################################

@app.route('/admin/users', methods=['GET', 'POST'])
@login_required
@roles_required('admin')
def admin_users():
    # return render_template('users.html', all_roles=roles.find(), all_users=users.find())
    # conn = sqlite3.connect('database.db')
    query_roles = client.query("""
          SELECT roles
          FROM  Portal_data.roles
          """)
    roles = query_roles.result().to_dataframe(create_bqstorage_client=True, )
    query_users = client.query("""
              SELECT *
              FROM Portal_data.users
              """)
    users = query_users.result().to_dataframe(create_bqstorage_client=True, )
    # users = conn.execute('SELECT * FROM users').fetchall()
    # conn.close()
    return render_template('Menu_login/users_admi2.html', all_roles=roles, all_users=users)


##########  Admin functionality -- Agregar Usuarios ####################################################################

@app.route('/admin/add-user', methods=['GET', 'POST'])
@login_required
@roles_required('admin')
def admin_add_user():
    if request.method == 'POST':
        form = request.form
        password = request.form['password']

        # conn = sqlite3.connect('database.db')
        # curs = conn.cursor()
        # curs.execute("SELECT * FROM users where email = (?)", [request.form['email']])
        # email = curs.fetchone()
        # conn.close()
        query_users = client.query("""
                   SELECT * FROM Portal_data.users where email =""" + '"' + request.form['email'].lower() + '"')
        users = query_users.result().to_dataframe(create_bqstorage_client=True, )
        email = users.iloc[0, :]

        if email:
            flash('This email is already registered.', 'warning')
            return 'This email has already been registered.'
        insertUser(form['first_name'], form['last_name'], form['email'], password, form['role'])
        flash(form['email'] + ' user has been added.', 'success')
        return redirect(url_for('admin_users'))

    # conn = sqlite3.connect('database.db')
    query_roles = client.query("""
          SELECT roles
          FROM  Portal_data.roles
          """)
    roles = query_roles.result().to_dataframe(create_bqstorage_client=True, )
    query_users = client.query("""
                  SELECT *
                  FROM Portal_data.users
                  """)
    users = query_users.result().to_dataframe(create_bqstorage_client=True, )
    return render_template('Menu_login/users_admi2.html', all_roles=roles, all_users=users)


###########  Admin functionality -- borrar Usuarios ####################################################################

@app.route('/admin/delete-user/<user_id>', methods=['GET', 'POST'])
@login_required
@roles_required('admin')
def admin_delete_user(user_id):
    # conn = sqlite3.connect('database.db')
    # cur = conn.cursor()
    # delete_user = cur.execute("SELECT * FROM users WHERE user_id = (?)", (user_id,)).fetchone()
    # conn.close()

    query_users = client.query("""
               SELECT * FROM Portal_data.users where id  =""" + '"' + user_id + '"')
    users = query_users.result().to_dataframe(create_bqstorage_client=True, )
    delete_user = users.iloc[0, :]
    try:
        existe = delete_user.shape[0] >= 1
    except:
        existe = 0

    if existe:
        # conn = sqlite3.connect('database.db')
        # cur = conn.cursor()
        # cur.execute("DELETE FROM  users WHERE user_id = (?)", (user_id,))
        # conn.commit()
        # conn.close()

        dml_statement = (
                """DELETE FROM Portal_data.users where id  =""" + '"' + user_id + '"')
        query_job = client.query(dml_statement)

        flash(delete_user[3] + ' has been deleted.', 'warning')
        return redirect(url_for('admin_users'))
    flash('User not found.', 'warning')
    return redirect(url_for('admin_users'))


###########  Admin functionality -- Editar Usuarios ####################################################################

@app.route('/admin/edit-user/<user_id>', methods=['GET', 'POST'])
@login_required
@roles_required('admin')
def admin_edit_user(user_id):
    # conn = sqlite3.connect('database.db')
    # cur = conn.cursor()
    # edit_user =  cur.execute("select *  FROM  users WHERE user_id = (?)", (user_id,)).fetchone()
    # conn.close()

    query_users = client.query("""
                          SELECT * FROM Portal_data.users where id =""" + user_id)
    users = query_users.result().to_dataframe(create_bqstorage_client=True, )
    edit_user = users.iloc[0, :]

    query_roles = client.query("""
          SELECT roles
          FROM  Portal_data.roles
          """)
    roles = query_roles.result().to_dataframe(create_bqstorage_client=True, )
    try:
        existe = edit_user.shape[0] >= 1
    except:
        existe = 0

    if existe:
        return render_template('Menu_login/edit-user 2.html', user=edit_user, all_roles=roles)
    flash('User not found.', 'warning')
    return redirect(url_for('admin_users'))


###########  Admin functionality -- Editar Usuarios ####################################################################

@app.route('/admin/update-user/<user_id>', methods=['GET', 'POST'])
@login_required
@roles_required('admin')
def admin_update_user(user_id):
    if request.method == 'POST':
        # conn = sqlite3.connect('database.db')
        # cur = conn.cursor()
        form = request.form
        password = request.form['password']
        first_name = form['first_name']
        last_name = form['last_name']
        email = form['email']
        role = form['role']
        date_added = form['date_added']
        date_modified = datetime.datetime.now()
        dml_statement = (
                '''UPDATE users SET 
                first_name =''' + '"' + first_name + '"' +
                ''',last_name =''' + '"' + last_name + '"' +
                ''',email =''' + '"' + email.lower() + '"' +
                ''',password =''' + '"' + password + '"' +
                ''',role =''' + '"' + role + '"' +
                ''',date_added =''' + '"' + str(date_added) + '"' +
                ''',date_modified =''' + '"' + str(date_modified) + '"' +
                '''where  id = ''' + user_id)
        query_job = client.query(dml_statement)

        # cur.execute("UPDATE users SET first_name = ?, last_name = ?, email = ?, password = ?, role = ? , date_added = ? , date_modified = ? where  user_id = (?)",
        #            (first_name, last_name, email , password,role,date_added,date_modified, user_id))
        # conn.commit()
        query_users = client.query("""
                                  SELECT * FROM Portal_data.users where id =""" + user_id)
        users = query_users.result().to_dataframe(create_bqstorage_client=True, )
        update_account = users.iloc[0, :]

        # update_account = cur.execute("SELECT * FROM users WHERE user_id = (?)", (user_id,)).fetchone()
        # conn.close()
        flash(update_account[3] + ' has been modified.', 'success')
        return redirect(url_for('admin_users'))

    query_users = client.query("""
          SELECT *
          FROM Portal_data.users
          """)
    users = query_users.result().to_dataframe(create_bqstorage_client=True, )

    query_roles = client.query("""
          SELECT roles
          FROM  Portal_data.roles
          """)
    roles = query_roles.result().to_dataframe(create_bqstorage_client=True, )

    return render_template('Menu_login/users_admi2.html', all_roles=roles, all_users=users)


########################             Pagina Principal               ####################################################

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('Pagina-Principal.html')


@app.route('/Proyectos Analitica')
@login_required
def Proyectos_Analitica():
    return render_template('Menu_pages/Proyectos Analitica2.html')


@app.route('/formulario_Analitica')
@login_required
def formulario_Analitica():
    return render_template('Menu_pages/Formulario Proyectos2.html')


#####REPORTE PARA TODOS


@app.route('/SBS_MORA', methods=['GET', 'POST'])
@login_required
def reporte_SBS_MORA():
    query_usersmail = client.query("""
          SELECT email
          FROM Portal_data.users
          """)
    users = query_usersmail.result().to_dataframe(create_bqstorage_client=True, )

    query_roles = client.query("""
          SELECT roles
          FROM  Portal_data.roles
          """)
    roles = query_roles.result().to_dataframe(create_bqstorage_client=True, )
    return render_template('reportes/SBS_MORA.html', all_roles=roles, all_users=users)


@app.route('/SBS_FINANCIERO', methods=['GET', 'POST'])
@login_required
def reporte_SBS_FINANCIERO():
    query_usersmail = client.query("""
          SELECT email
          FROM Portal_data.users
          """)
    users = query_usersmail.result().to_dataframe(create_bqstorage_client=True, )

    query_roles = client.query("""
          SELECT roles
          FROM  Portal_data.roles
          """)
    roles = query_roles.result().to_dataframe(create_bqstorage_client=True, )
    return render_template('reportes/SBS_MORA.html', all_roles=roles, all_users=users)


########################################################################################################################
# PAGINAS ---------- MODIFICAR A PARTIR DE AQUI -------------------------------
########################################################################################################################

############################# CUMPLIMIENTO ################
@app.route('/CUMPLIMIENTO', methods=['GET', 'POST'])
@login_required
@roles_required('CUMPLIMIENTO', 'admin')
def Pagina_Cumplimiento():
    query_usersmail = client.query("""
          SELECT email
          FROM Portal_data.users
          """)
    users = query_usersmail.result().to_dataframe(create_bqstorage_client=True, )

    query_roles = client.query("""
          SELECT roles
          FROM  Portal_data.roles
          """)
    roles = query_roles.result().to_dataframe(create_bqstorage_client=True, )
    return render_template('Menu_pages/Menu Principal/Cumplimiento2.html', all_roles=roles, all_users=users)


@app.route('/CUMPLIMIENTO/REPORTE_8UIT', methods=['GET', 'POST'])
@login_required
@roles_required('CUMPLIMIENTO', 'admin')
def reporte_cumplimiento_8uit():
    query_usersmail = client.query("""
          SELECT email
          FROM Portal_data.users
          """)
    users = query_usersmail.result().to_dataframe(create_bqstorage_client=True, )

    query_roles = client.query("""
          SELECT roles
          FROM  Portal_data.roles
          """)
    roles = query_roles.result().to_dataframe(create_bqstorage_client=True, )
    return render_template('reportes/Cumplimiento/Reporte_8UIT.html', all_roles=roles, all_users=users)


@app.route('/CUMPLIMIENTO/REPORTE_TC', methods=['GET', 'POST'])
@login_required
@roles_required('CUMPLIMIENTO', 'admin')
def reporte_cumplimiento_TC():
    query_usersmail = client.query("""
          SELECT email
          FROM Portal_data.users
          """)
    users = query_usersmail.result().to_dataframe(create_bqstorage_client=True, )

    query_roles = client.query("""
          SELECT roles
          FROM  Portal_data.roles
          """)
    roles = query_roles.result().to_dataframe(create_bqstorage_client=True, )
    return render_template('reportes/Cumplimiento/Programacion_TC.html', all_roles=roles, all_users=users)


############################# BANCA DIGITAL################

@app.route('/BANCA_DIGITAL', methods=['GET', 'POST'])
@login_required
@roles_required('BANCA DIGITAL', 'admin')
def Pagina_Bancadigital():
    query_usersmail = client.query("""
          SELECT email
          FROM Portal_data.users
          """)
    users = query_usersmail.result().to_dataframe(create_bqstorage_client=True, )

    query_roles = client.query("""
          SELECT roles
          FROM  Portal_data.roles
          """)
    roles = query_roles.result().to_dataframe(create_bqstorage_client=True, )
    return render_template('Menu_pages/Menu Principal/Banca Digital2.html', all_roles=roles, all_users=users)


@app.route('/BANCA_DIGITAL/PAGALO', methods=['GET', 'POST'])
@login_required
@roles_required('BANCA DIGITAL', 'admin')
def reporte_bancadigital_pagalo():
    query_usersmail = client.query("""
          SELECT email
          FROM Portal_data.users
          """)
    users = query_usersmail.result().to_dataframe(create_bqstorage_client=True, )

    query_roles = client.query("""
          SELECT roles
          FROM  Portal_data.roles
          """)
    roles = query_roles.result().to_dataframe(create_bqstorage_client=True, )
    return render_template('reportes/Banca Digital/PAGALO.html', all_roles=roles, all_users=users)


############################# AUDITORIA INTERNA################

@app.route('/AUDITORIA_INTERNA', methods=['GET', 'POST'])
@login_required
@roles_required('AUDITORIA INTERNA', 'admin')
def Pagina_Auditoriainterna():
    query_usersmail = client.query("""
          SELECT email
          FROM Portal_data.users
          """)
    users = query_usersmail.result().to_dataframe(create_bqstorage_client=True, )

    query_roles = client.query("""
          SELECT roles
          FROM  Portal_data.roles
          """)
    roles = query_roles.result().to_dataframe(create_bqstorage_client=True, )
    return render_template('Menu_pages/Menu Principal/Auditoria interna2.html', all_roles=roles, all_users=users)


@app.route('/AUDITORIA_INTERNA/REPORTE_OPERACIONES', methods=['GET', 'POST'])
@login_required
@roles_required('AUDITORIA INTERNA', 'admin')
def reporte_auditoriainterna_roperaciones():
    query_usersmail = client.query("""
          SELECT email
          FROM Portal_data.users
          """)
    users = query_usersmail.result().to_dataframe(create_bqstorage_client=True, )

    query_roles = client.query("""
          SELECT roles
          FROM  Portal_data.roles
          """)
    roles = query_roles.result().to_dataframe(create_bqstorage_client=True, )
    return render_template('reportes/Auditoria interna/Reporte operaciones.html', all_roles=roles, all_users=users)


############################# INCLUSION FINANCIERA################

@app.route('/INCLUSION_FINANCIERA', methods=['GET', 'POST'])
@login_required
@roles_required('INCLUSION FINANCIERA', 'admin')
def Pagina_Inclusionfinanciera():
    query_usersmail = client.query("""
          SELECT email
          FROM Portal_data.users
          """)
    users = query_usersmail.result().to_dataframe(create_bqstorage_client=True, )

    query_roles = client.query("""
          SELECT roles
          FROM  Portal_data.roles
          """)
    roles = query_roles.result().to_dataframe(create_bqstorage_client=True, )
    return render_template('Menu_pages/Menu Principal/Inclusion financiera2.html', all_roles=roles, all_users=users)


'''
@app.route('/INCLUSION_FINANCIERA', methods=['GET', 'POST'])
@login_required
@roles_required('INCLUSION FINANCIERA','admin')
def inclusion_financiera():
    conn = sqlite3.connect('database.db')
    roles = conn.execute('SELECT roles_name FROM roles').fetchall()
    users = conn.execute('SELECT email FROM users').fetchall()
    conn.close()
    return render_template('pages_new/Menu Principal/Inclusion financiera.html', all_roles=roles, all_users=users)

'''


@app.route('/INCLUSION_FINANCIERA/IMPACTO BCP', methods=['GET', 'POST'])
@login_required
@roles_required('INCLUSION FINANCIERA', 'admin')
def reporte_inclusionfinanciera_impactobcp():
    query_usersmail = client.query("""
          SELECT email
          FROM Portal_data.users
          """)
    users = query_usersmail.result().to_dataframe(create_bqstorage_client=True, )

    query_roles = client.query("""
          SELECT roles
          FROM  Portal_data.roles
          """)
    roles = query_roles.result().to_dataframe(create_bqstorage_client=True, )
    return render_template('reportes/Inclusion Financiera/Impacto BCP.html', all_roles=roles, all_users=users)


############################# AUDITORIA INTERNA################

@app.route('/FRAUDES', methods=['GET', 'POST'])
@login_required
@roles_required('FRAUDES', 'RIESGOS', 'admin')
def Pagina_Fraudes():
    query_usersmail = client.query("""
          SELECT email
          FROM Portal_data.users
          """)
    users = query_usersmail.result().to_dataframe(create_bqstorage_client=True, )

    query_roles = client.query("""
          SELECT roles
          FROM  Portal_data.roles
          """)
    roles = query_roles.result().to_dataframe(create_bqstorage_client=True, )
    return render_template('Menu_pages/Menu Principal/Fraudes2.html', all_roles=roles, all_users=users)


@app.route('/FRAUDES/REPORTE_FRAUDES', methods=['GET', 'POST'])
@login_required
@roles_required('FRAUDES', 'RIESGOS', 'admin')
def reporte_fraudes_operaciones():
    query_usersmail = client.query("""
          SELECT email
          FROM Portal_data.users
          """)
    users = query_usersmail.result().to_dataframe(create_bqstorage_client=True, )

    query_roles = client.query("""
          SELECT roles
          FROM  Portal_data.roles
          """)
    roles = query_roles.result().to_dataframe(create_bqstorage_client=True, )
    return render_template('reportes/Fraudes/Reporte_Fraudes.html', all_roles=roles, all_users=users)


############################# RIESGOS  ################

@app.route('/RIESGOS', methods=['GET', 'POST'])
@login_required
@roles_required('RIESGOS', 'FRAUDES', 'admin')
def Pagina_riesgos():
    query_usersmail = client.query("""
       SELECT email
       FROM Portal_data.users
       """)
    users = query_usersmail.result().to_dataframe(create_bqstorage_client=True, )

    query_roles = client.query("""
       SELECT roles
       FROM  Portal_data.roles
       """)
    roles = query_roles.result().to_dataframe(create_bqstorage_client=True, )
    return render_template('Menu_pages/Menu Principal/Riesgos2.html', all_roles=roles, all_users=users)


@app.route('/RIESGOS/REPORTE_FRAUDES', methods=['GET', 'POST'])
@login_required
@roles_required('RIESGOS', 'FRAUDES', 'admin')
def reporte_riesgos_scoring():
    query_usersmail = client.query("""
       SELECT email
       FROM Portal_data.users
       """)
    users = query_usersmail.result().to_dataframe(create_bqstorage_client=True, )

    query_roles = client.query("""
       SELECT roles
       FROM  Portal_data.roles
       """)
    roles = query_roles.result().to_dataframe(create_bqstorage_client=True, )
    return render_template('reportes/Riesgos/Reporte_Scoring.html', all_roles=roles, all_users=users)


@app.route('/MODELOS/predict', methods=['POST'])
@login_required
def predict():
    # Alternative Usage of Saved Model
    # joblib.dump(clf, 'NB_spam_model.pkl')
    # NB_spam_model = open('NB_spam_model.pkl','rb')
    # clf = joblib.load(NB_spam_model)

    # 01. Import libraries

    # Básicos
    from operator import contains
    import pandas as pd
    import numpy as np
    import re
    import string
    import pickle
    import joblib
    from datetime import datetime
    from unidecode import unidecode
    from pathlib import Path
    import warnings

    # Formato
    from num2words import num2words

    # Scikit-learn
    from sklearn import metrics
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.feature_selection import chi2

    # NLTK
    import nltk
    from nltk.stem import WordNetLemmatizer
    from nltk.tokenize import word_tokenize
    from nltk.corpus import stopwords

    # Spacy
    import spacy
    from spacy_spanish_lemmatizer import SpacyCustomLemmatizer
    import es_core_news_sm
    # import es_core_news_lg

    # Scikit-learn
    from sklearn.neighbors import KNeighborsClassifier
    from sklearn.linear_model import LogisticRegression
    from sklearn.model_selection import train_test_split
    from sklearn.model_selection import cross_val_score
    from sklearn.model_selection import GridSearchCV
    from sklearn.calibration import CalibratedClassifierCV
    from sklearn.utils.class_weight import compute_sample_weight
    from sklearn.metrics import accuracy_score
    from sklearn import preprocessing
    from sklearn.feature_extraction.text import CountVectorizer
    from sklearn.metrics import cohen_kappa_score, make_scorer, log_loss
    from sklearn.metrics import classification_report
    from sklearn.metrics import confusion_matrix

    # limpieza de  texto
    def formato_texto(texto):
        texto = texto.upper()
        texto = texto.translate(str.maketrans("ÁÉÍÓÚ", "AEIOU"))
        texto = texto.translate(str.maketrans("ÀÈÌÒÙ", "AEIOU"))
        texto = texto.translate(str.maketrans("ÂÊÎÔÛ", "AEIOU"))
        texto = ' '.join(texto.split())

        return texto

    def remover_numeros_puntuacion(texto):
        texto = texto.translate(str.maketrans('', '', string.digits))
        texto = texto.translate(str.maketrans('', '', string.punctuation + '¡¿°º-–•“”‘’´ª¨'))
        texto = ' '.join(texto.split())

        return texto

    def remover_stopwords(texto):
        # Retirar stopwords
        stopwords_spanish = pd.read_csv('static/recursos/stopwords_spanish.csv')
        stopwords_spanish = stopwords_spanish['WORD'].tolist()

        stopwords_esp = [formato_texto(i) for i in stopwords_spanish]

        preposiciones = ['A', 'ANTE', 'BAJO', 'CABE', 'CON', 'CONTRA', 'DE', 'DESDE', 'DURANTE', 'EN', 'ENTRE', 'HACIA',
                         'HASTA', 'MEDIANTE', 'PARA', 'POR', 'SEGUN', 'SIN', 'SOBRE', 'TRAS', 'VERSUS', 'VIA',
                         'RESPECTO']

        stopwords_esp = list(set(preposiciones + stopwords_esp))
        texto = ' '.join([i for i in texto.split() if i not in stopwords_esp])

        return texto

    def limpieza_texto(texto):
        # Limpieza de tildes
        texto_limp = formato_texto(texto)

        # Remoción de números y puntuación
        texto_limp = remover_numeros_puntuacion(texto_limp)

        # Remoción de stopwords
        texto_limp = remover_stopwords(texto_limp)

        return texto_limp

    def process(text):
        data = {'TEXTO': [text]}
        df_train_test = pd.DataFrame(data)

        df_train_test['TEXTO_LIMP'] = df_train_test['TEXTO'].astype(str).apply(lambda x: limpieza_texto(x))

        # %% TD IDF
        # Carga de vocabulario
        tf_idf = joblib.load('static/version/tf_idf_unigram.pkl')

        df_train_test['FEATURES'] = list(tf_idf.transform(df_train_test['TEXTO_LIMP']).toarray())

        #################################
        # %% LOGISTIC REGRESSION

        log_model = joblib.load('static/version/log_model.pkl')
        x_pred = pd.DataFrame(df_train_test['FEATURES'].to_list())
        y_pred = log_model.predict(x_pred)
        y_prob = log_model.predict_proba(x_pred)[::, 1]
        y_prob = str(round(y_prob[0] * 100, 2)) + "%"
        return y_prob

    if request.method == 'POST':
        message = request.form['message']
        data = [message]
        # vect = cv.transform(data).toarray()
        my_prediction = process(data)
        Valor = int(my_prediction[0:2])
        texto=data
    return render_template('reportes/MODELOS_PREDICCIONRESPUESTA.html', prediction=my_prediction, Valor=Valor,texto=data)


if __name__ == "__main__":
    app.secret_key = os.urandom(24)
    app.run(debug=True, host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))
# app.run(debug=True)host='0.0.0.0', port=5000,v
