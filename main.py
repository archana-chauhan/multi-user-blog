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


# User model
class User(db.Model):
    '''
        User : This is Google Datastore kind that stores information
        about registered users.

        Properties :
            name : this property store the name of the user
            username : this property store the unique username of the user
            password : this property store the encryted password of user
            email : thsi property store unique email of the user
    '''
    name = db.StringProperty(required=True)
    username = db.StringProperty(required=True)
    password = db.StringProperty(required=True)
    email = db.StringProperty(required=True)

    @classmethod
    def get_user_by_id(cls, user_id):
        '''
            get_user_by_id : function return user instance by id
        '''
        return User.get_by_id(user_id)

    @classmethod
    def get_user_by_username(cls, username):
        '''
            get_user_by_name : function return user instance by username
        '''
        return db.GqlQuery("SELECT * FROM User WHERE username= :username", username=username).get()     # NOQA

    @classmethod
    def user_register(cls, name, username, password, email):
        '''
            user_register : function creates hash of password then create data
            entity of User(model) class
        '''
        password_hash = make_pwd_hash(password)
        return User(name=name, username=username, password=password_hash,
                    email=email)

    @classmethod
    def user_login(cls, username, password):
        '''
            user_login : function retrieve user instance by username,
            then retrieve hashed password then match the hashed password by
            the new hash created via username and password entered during
            login. If it matches it returns true else return false
        '''
        user = cls.get_user_by_username(username)
        hashed_password = user.password
        return valid_pwd(username, password, hashed_password)


# Post model
class Post(db.model):
    '''
        Post : This is Google Datastore kind that stores information
        about posts posted by user.

        Properties :
            subject : this property store the subject of the post
            content : this property store the content of the post
            created_date_time : this property store the date and time
                when the post was created
            last_modified : this property store the data and time when
                the post was last modified
            created_by_user : this property store the data about the user
                who created it
            total_likes : this property store the total likes for the post
            liked_by_users : this property stores the list of the users who
                liked the post

    '''
    subject = db.StringProperty(required=True)
    content = db.StringProperty(required=True)
    created_date_time = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)
    created_by_user = db.StringProperty(required=False)
    total_likes = db.IntegerProperty(required=False)
    liked_by_users = db.ListProperty(str)

    @classmethod
    def get_post_by_username(cls, username):
        posts = db.GqlQuery("SELECT * FROM Post WHERE created_by_user = :username ORDER BY created_date_time DESC", username=username)  # NOQA
        return posts


# Comment model
class Comment(db.Model):
    '''
        Comment : This is Google Datastore kind that stores information
        about comments posted by user in posts.

        Properties :
            comment : this property stores the comment content on the post
            comment_by_user : this property store the user data who commented
                on post
            post_id : this property store the post id on which comment was made
            created_date_time : this property store the date time when comment
                was made
            last_modified : this property store the date time when the comment
                was last modified
    '''
    comment = db.TextProperty(required=True)
    comment_by_user = db.StringProperty(required=True)
    post_id = db.IntegerProperty(required=True)
    created_date_time = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)

    @classmethod
    def get_comments(cls, post_id):
        comments = db.GqlQuery("SELECT * FROM Comment WHERE post_id= :post_id", post_id=int(post_id))   # NOQA
        return comments


class MainPage(MainHandler):
    '''
        This handler handles the main page of the blog post
    '''
    def render_homepage(self, username):
        self.display_posts = db.GqlQuery("SELECT * FROM Post ORDER BY created_date_time DESC")  # NOQA
        self.render("mainpage.html", display_posts=self.display_posts,
                    username=username)

    def get(self):
        self.render_homepage(user=self.user)


class NewPostHandler(MainHandler):
    def render_page(self, user, subject="", content="", error=""):
        self.render("newpost.html", user=user, subject=subject,
                    content=content, error=error)

    def get(self):
        # Check first is user is logged in or not
        if self.user:
            self.render_page(user=self.user)
        else:
            self.redirect('/')

    def post(self):
        self.subject = self.request.get("subject")
        self.content = self.request.get("content")
        self.username = self.user.username
        if self.subject and self.content:
            post = Post(subject=self.subject, content=self.content,
                        created_by_user=self.username)
            post.put()
            self.redirect('/%s' % str(b.key().id()))
        else:
            self.error = "All fields are required !!"
            self.render_page(user=self.user, subject=self.subject,
                             content=self.content, error=self.error)





app = webapp2.WSGIApplication([
      ('/', MainPage),
      ('/login', HandlerLogin),
      ('/logout', HandlerLogout),
      ('/signup', HandlerSignUp)
      ], debug=True)
