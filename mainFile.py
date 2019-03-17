from flask import (Flask, request, jsonify, render_template, redirect, url_for)
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm.exc import NoResultFound
from mainDb import Input, Motors, Specifications, User
from flask import session as login_session
import random
import string
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import requests
from flask import make_response
import base64
import json
import httplib2
from flask import flash
app = Flask(__name__)

engine = create_engine('sqlite:///motorItem.db')
Input.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()

CLIENT_ID = json.loads(open('client_secrets.json', 'r').read())[
    'web']['client_id']

# This function/route is navgitage user to landing page


@app.route('/')
@app.route('/mainPage', methods=['POST', 'GET'])
def main():
    session = DBSession()
    item = session.query(Motors).all()
    session.close()
    return render_template("main.html", item=item, login=login_session)

# This function/route is to render the login template
# and save the state for validating



@app.route('/login')
def login():
    if 'user_id' in login_session:
        return redirect(url_for('main'))
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in range(32))
    login_session['state'] = state
    # return "The current session state is %s" % login_session['state']
    return render_template('login.html', STATE=state)

# This route gets the access token from the frontend
# and validate with the facebook auth api and stores
# in users table if user not exits already


@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print("Token's client ID does not match app's.")
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(
                    json.dumps('Current user is already connected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()
    # After getting information from user it will
    # store data in login session
    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']

    # check for user in database if user exists
    # Stores the user id in login session else
    # Create user with details and the stores the user_id
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    print( "done!")
    return output

# This is to logout the user


@app.route('/logout')
def logout():
    access_token = login_session.get('access_token')
    if access_token is None:
        print ('Access Token is None')
        response = make_response(json.dumps(
            'Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    print ('In gdisconnect access token is %s', access_token)
    print('User name is: ')
    print( login_session['username'])
    print(login_session['access_token'])
    url = 'https://accounts.google.com/o/oauth2/revoke?token='
    url += login_session['access_token']
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    print ('result is ')
    print( result)
    if result['status'] == '200':
        del login_session['access_token']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        del login_session['user_id']
        return redirect('/')
    else:
        response = make_response(json.dumps(
            'Failed to revoke token delete cookies and re login.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response



# User Helper Functions stores
# the user data in database


def createUser(login_session):
    print("creating user")
    session = DBSession()
    try:
        user = session.query(User).filter_by(
            email=login_session['email']).one()
        return user.id
    except NoResultFound:
        print("error")
    newUser = User(name=login_session['username'], email=login_session[
        'email'], picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user1 = session.query(User).filter_by(email=login_session['email']).one()
    session.close()
    return user1.id

# Return user from user id


def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user

# Return user id if user exists in database


def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None

# This route or function is to add new motor company in database


@app.route('/addItem', methods=['POST', 'GET'])
def addItem():
    if 'user_id' in login_session:
        if request.method == "POST":
            print(login_session['user_id'])
            if request.form['san'] != "":
                item = Motors(uid=login_session['user_id'],
                              item=request.form['san'])
                session.add(item)
                session.commit()
                session.close()
                flash("New item added successfully")
                return redirect('/mainPage')
            else:
                session.close()
                return redirect('/addItem')
        else:
            print(login_session['username'])
            session.close()
            return render_template("addItem.html")
    else:
        flash("login to add new item")
        return redirect(url_for('login'))

# This route and function is used delete the motor
# company and its modals in database


@app.route('/mainPage/<int:item_id>/deleteItem', methods=['POST', 'GET'])
def deleteItem(item_id):
    session = DBSession()
    item = session.query(Motors).filter_by(id=item_id).one()
    if 'user_id' in login_session:
        if login_session['user_id'] == item.uid:
            if request.method == 'GET':
                session = DBSession()
                session.close()
                item = session.query(Motors).filter_by(id=item_id).one()
                return render_template('delete.html', item_id=item_id,
                                       item=item,
                                       login=login_session)
            else:
                print('deleting')
                session = DBSession()
                deelete = session.query(Motors).filter_by(id=item_id).one()
                del_spec = session.query(Specifications).filter_by(
                    motors_id=deelete.id).all()
                for one_del_spec in del_spec:
                    session.delete(one_del_spec)
                session.delete(deelete)
                session.commit()
                session.close()
                flash("deleted successfully")
                item = session.query(Motors).all()
                return redirect(url_for('main'))
        else:
            flash("you cannot delete the item")
            return redirect(url_for('main'))
    else:
        flash("login to delete item")
        return redirect(url_for('login'))

# This function and route is to edit the company name


@app.route('/mainPage/<int:item_id>/editItem', methods=['POST', 'GET'])
def editItem(item_id):
    session = DBSession()
    item = session.query(Motors).filter_by(id=item_id).one()
    if 'user_id' in login_session:
        if login_session['user_id'] == item.uid:
            item = session.query(Motors).filter_by(id=item_id).one()
            if request.method == 'POST':
                if request.form['san'] != "":
                    item.item = request.form['san']
                    session.add(item)
                    session.commit()
                    session.close()
                    flash("edited successfully")
                    return redirect('/mainPage')
                else:
                    session.close()
                    return redirect(url_for('editItem', item_id=item.id))
            else:
                session.close()
                return render_template("editItem.html", item_id=item_id,
                                       item=item,
                                       login=login_session)
        else:
            flash("you cannot edit this item")
            return redirect(url_for('main'))
    else:
        flash("login to edit item")
        return redirect(url_for('login'))

# This route is to view the modals in the company


@app.route('/mainPage/<int:item_id>/prototype', methods=['POST', 'GET'])
def prodouct_type(item_id):
    session = DBSession()
    spec_item = session.query(Specifications).filter_by(
        motors_id=item_id).all()
    session.close()
    item = session.query(Motors).filter_by(id=item_id).one()
    return render_template("main2.html", spec_item=spec_item,
                           item_id=item_id,
                           item=item,
                           login=login_session)

# This route is to add the modal in the company


@app.route('/mainPage/<int:item_id>/spec_additem', methods=['POST', 'GET'])
def spec_addItem(item_id):
    session = DBSession()
    item = session.query(Motors).filter_by(id=item_id).one()
    if 'user_id' in login_session:
        if login_session['user_id'] == item.uid:
            if request.method == "POST":
                if(request.form['desc'] != "" and
                   request.form['price'] != "" and
                   request.form['pumping'] != "" and
                   request.form['pressure'] != "" and
                   request.form['image'] != ""):
                    spec_it = Specifications(pressure=request.form['pressure'],
                                             desc=request.form['desc'],
                                             pumping=request.form['pumping'],
                                             price=request.form['price'],
                                             img=request.form['image'],
                                             motors_id=item_id)
                    session.add(spec_it)
                    session.commit()
                    session.close()
                    flash("New modal added")
                    return redirect(url_for('prodouct_type', item_id=item_id))
                else:
                    session.close()
                    return redirect(url_for('spec_addItem', item_id=item_id))
            else:
                session.close()
                return render_template("spec.html",
                                       item_id=item_id,
                                       login=login_session)
        else:
            flash("you cannot add new modal for this item")
            return redirect(url_for('prodouct_type', item_id=item_id))
    else:
        flash("login to edit item")
        return redirect(url_for('login'))

# This route is to delete the modal of the company


@app.route(
    '/mainPage/<int:item_id>/spec_delItem/<int:spec_item_id>/delete_spec',
    methods=['POST', 'GET'])
def spec_delItem(spec_item_id, item_id):
    session = DBSession()
    item = session.query(Motors).filter_by(id=item_id).one()
    if 'user_id' in login_session:
        if login_session['user_id'] == item.uid:
            spec_item = session.query(Specifications).filter_by(
                id=spec_item_id).one()
            if request.method == "POST":
                session.delete(spec_item)
                session.commit()
                session.close()
                flash("Modal deleted successfully")
                return redirect(url_for('prodouct_type', item_id=item_id))
            else:
                session.close()
                return render_template("delete_spec.html",
                                       item_id=item_id,
                                       spec_item_id=spec_item_id,
                                       spec_item=spec_item,
                                       login=login_session)
        else:
            flash("you cannot delete modal for this item")
            return redirect(url_for('prodouct_type', item_id=item_id))
    else:
        flash("login to delete modal item")
        return redirect(url_for('login'))

# This route is to edit the modal details


@app.route('/mainPage/<int:item_id>/spec_delItem/<int:spec_item_id>/edit_spec',
           methods=['POST', 'GET'])
def spec_editItem(spec_item_id, item_id):
    session = DBSession()
    item = session.query(Motors).filter_by(id=item_id).one()
    if 'user_id' in login_session:
        if login_session['user_id'] == item.uid:
            spec_item = session.query(Specifications).filter_by(
                id=spec_item_id).one()
            if request.method == "POST":
                spec_item.pressure = request.form['pressure']
                spec_item.desc = request.form['desc']
                spec_item.pumping = request.form['pumping']
                spec_item.price = request.form['price']
                spec_item.img = request.form['image']
                session.add(spec_item)
                session.commit()
                session.close()
                flash("Modal editted")
                return redirect(url_for('prodouct_type', item_id=item_id))
            else:
                session.close()
                return render_template("edit_spec.html",
                                       item_id=item_id,
                                       spec_item_id=spec_item_id,
                                       spec_item=spec_item,
                                       item=item,
                                       login=login_session)
        else:
            flash("you cannot edit modal")
            return redirect(url_for('prodouct_type', item_id=item_id))
    else:
        flash("login to delete modal item")
        return redirect(url_for('login'))

# This route return the json data of
# all data about motor companies


@app.route('/data/json')
def full_data():
    session = DBSession()
    motors_array = []
    motors = session.query(Motors).all()
    for motor in motors:
        motor_models = []
        mdls = session.query(Specifications).filter_by(
            motors_id=motor.id).all()
        for m in mdls:
            motor_models.append(m.serialize)
        m_w_m = {
            'id': motor.id,
            'name': motor.item,
            'models': motor_models
        }
        motors_array.append(m_w_m)
        session.close()
    return jsonify(motors=motors_array)

# This route is return specifications of
# modals in the company in json format


@app.route('/motor/<int:item_id>/jsondata')
def motor_models(item_id):
    session = DBSession()
    mdls = session.query(Specifications).filter_by(motors_id=item_id).all()
    session.close()
    return jsonify(MotorModels=[m.serialize for m in mdls])

# This route returns the specifications of modals in company


@app.route('/motor/<int:item_id>/modal/<int:mid>/jsondata')
def modal_details(item_id, mid):
    session = DBSession()
    mdl = session.query(Specifications).filter_by(id=mid).one()
    session.close()
    return jsonify(Modaldetails=mdl.serialize)


if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run( host='0.0.0.0', port=8000)
