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

    def set_cookie(self, user, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header('Set-Cookie', '%s=%s; Path=/' %
                                         (user, cookie_val))

    def get_cookie(self, user):
        cookie_val = self.request.cookies.get(user)
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
        password_hash = make_pwd_hash(username, password)
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
            # Redirect to the newly created post page
            self.redirect('/%s' % str(b.key().id()))
        else:
            self.error = "All fields are required !!"
            self.render_page(user=self.user, subject=self.subject,
                             content=self.content, error=self.error)


class PostPageHandler(MainHandler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id))
        self.post = db.get(key)
        if not self.post:
            self.error(404)
            return
        self.render("permalink.html", post=self.post, user=self.user)


class SignUpPageHandler(MainHandler):
    def render_sign_up_page(self, name="", username="", password="", verify="",
                            email="", error=""):
        self.render("signup.html", name=name, username=username,
                    password=password, verify=verify, email=email, error=error)

    def get(self):
        self.render_sign_up_page()

    def post(self):
        self.name = self.request.get('name')
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')
        # Checks for name first
        if not self.name:
            self.error = "Please enter name !!"
            self.render_sign_up_page(name=self.name,
                                     username=self.username,
                                     email=self.email, error=self.error)

        if self.username and self.password and self.verify and self.email:
            if not valid_username(self.username):
                self.error = "Not a valid username, please enter a valid"
                " username !!"
                self.render_sign_up_page(name=self.name,
                                         username=self.username,
                                         email=self.email, error=self.error)
            elif not valid_password(self.password):
                self.error = "Not a valid password, please enter a valid "
                "password !!"
                self.render_sign_up_page(name=self.name,
                                         username=self.username,
                                         email=self.email, error=self.error)
            elif self.password != self.verify:
                self.error = "Passwords do not match !!"
                self.render_sign_up_page(aame=self.name,
                                         username=self.username,
                                         email=self.email, error=self.error)
            elif not valid_email(self.email):
                self.error = "Email not valid !!"
                self.render_sign_up_page(name=self.name,
                                         username=self.username,
                                         email=self.email, error=self.error)
            else:
                # Checking if username already exists or not
                user = User.get_user_by_name(self.username)
                if user:
                    self.error = "Username already exists !! Please try "
                    "another"
                    self.render_sign_up_page(name=self.name,
                                             username=self.username,
                                             email=self.email,
                                             error=self.error)
                # If user doesn't exists already we put it in datastore
                else:
                    self.password_hash = make_pwd_hash(self.username,
                                                       self.password)
                    user = User.user_register(self.name, self.password_hash,
                                              self.password, self.email)
                    user.put()
                    self.set_cookie('user_id', str(user.key().id()))
                    self.redirect('/home')
        # If all fields are not filled this block will execute
        else:
            self.error = "All fields are required !!"
            self.render_sign_up_page(name=self.name, username=self.username,
                                     email=self.email, error=self.error)


class LoginPageHandler(MainHandler):
    def render_login_page(self, username="", password="", error=""):
        self.render("login.html", username=username, password=password,
                    error=error)

    def get(self):
        self.render_login_page()

    def post(self):
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        if self.username and self.password:
            self.user_exists = User.get_user_by_name(self.username, self.password)
            # If user don't exists this block will execute
            if not self.user_exists:
                self.error = "User does not exist !!"
                self.render_login_page(username=self.username,
                                       error=self.error)
            else:
                self.valid_pwd = User.login(username=self.username,
                                            password=self.password)
                if self.valid_pwd:
                    self.set_cookie('user_id', str(self.user_exists.key().id()))
                    self.redirect('/home')
                else:
                    self.error = "Invalid password !!"
                    self.render_login_page(username=self.username,
                                           error=self.error)
        else:
            self.error = "All fields are required !!"
            self.render_login_page(username=self.username, error=self.error)


app = webapp2.WSGIApplication([
      ('/', MainPage),
      ('/login', HandlerLogin),
      ('/logout', HandlerLogout),
      ('/signup', HandlerSignUp)
      ], debug=True)
