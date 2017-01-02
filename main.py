import os
import re

import webapp2
import jinja2

import hashlib
import hmac

import string
import random

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)

SECRET = 'du.uyX9fE~Tb6.pp&U3D-OsmYO,Gqi$^jS34tzu9'

# Regular expression to validate username
RE_USER = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")


def valid_username(user_name):
    '''
        valid_username : function match the user name with the regular
        expression. If matches return true else return false
    '''
    return user_name and RE_USER.match(user_name)


# Regular expression to validate password
RE_PASS = re.compile(r"^.{3,20}$")


def valid_password(password):
    '''
        valid_password : function match the password with the regular
        expression. If matches return true else return false
    '''
    return password and RE_PASS.match(password)

# Regular expression to validate email address
RE_EMAIL = re.compile(r'^[\S]+@[\S]+\.[\S]+$')


def valid_email(emailaddress):
    '''
        valid_email : function math the email with the regular expression.
        If matches return true else return false
    '''
    return not email and RE_EMAIL.match(emailaddress)


def make_secure_val(val):
    '''
        make_secure_val : function return hashed value of val
    '''
    return '%s|%s' % (val, hmac.new(SECRET, val).hexdigest())


def check_secure_val(secure_val):
    '''
        check_secure_val : function check if the cookie is secure or not,
        if cookie is secured it return the val
    '''
    val = secure_val.split('|')[0]
    if make_secure_val(val) == secure_val:
        return val


def make_salt(len=5):
    '''
        make_salt : function make salt for password hash
    '''
    return ''.join(random.choice(string.ascii_letters) for x in xrange(len))


def make_pwd_hash(username, password, salt=None):
    '''
        make_pwd_hash : function return hashed value for password
    '''
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(username + password + salt).hexdigest()
    return '%s|%s' % (h, salt)


def valid_pwd(username, password, h):
    '''
        valid_pwd : function verifies hashed value of password
    '''
    salt = h.split('|')[1]
    return h == make_pwd_hash(username, password, salt)


class MainHandler(webapp2.RequestHandler):
    '''
        This handler class contains generic functions that are inherited by
        other child handler classes
    '''
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header('Set-Cookie', '%s=%s; Path=/' %
                                         (name, cookie_val))

    def get_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)


class User(db.Model):
    '''
        User : This is Google Datastore kind that stores information
        about registered users.

        Properties :
            username : this property store the unique username of the user
            password : this property store the encryted password of user
            email : thsi property store unique email of the user
    '''
    username = db.StringProperty(required=True)
    password = db.StringProperty(required=True)
    email = db.StringProperty(required=True)

    @classmethod
    def get_user_by_id(cls, user_id):
        return User.get_by_id(user_id)

    @classmethod
    def get_user_by_name(cls, username):
        return db.GqlQuery("SELECT * FROM User WHERE username= :username", username=username).get()     # NOQA

    @classmethod
    def user_register(cls, username, password, email):
        password_hash = make_pwd_hash(password)
        return User(username=username, password=password_hash, email=email)

    @classmethod
    def user_login(cls, username, password):
        user = cls.get_user_by_name(username)
        hashed_password = user.password
        return valid_pwd(username, password, hashed_password) 


class MainPage(webapp2.RequestHandler):
    def get(self):
        self.response.headers['Content-Type'] = 'text/plain'
        self.response.write('Hello world')


app = webapp2.WSGIApplication([
      ('/', MainPage),
      ('/login', HandlerLogin),
      ('/logout', HandlerLogout),
      ('/signup', HandlerSignUp)
      ], debug=True)
