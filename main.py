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

SECRET = 'du.uyX9fE~Tb6.pp&Uub-OsmYO,Gqi$^jS34tz75'

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
    return emailaddress and RE_EMAIL.match(emailaddress)


def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)


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
    hashed_password = hashlib.sha256(username + password + salt).hexdigest()
    return '%s|%s' % (salt, hashed_password)


def valid_pwd(username, password, hashed_password):
    '''
        valid_pwd : function verifies hashed value of password
    '''
    salt = hashed_password.split('|')[0]
    return hashed_password == make_pwd_hash(username, password, salt)


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
    password = db.TextProperty(required=True)
    email = db.StringProperty(required=True)

    @classmethod
    def get_user_by_id(cls, user_id):
        '''
            get_user_by_id : function return user instance by id
        '''
        return User.get_by_id(user_id)

    @classmethod
    def get_user_by_username(cls, user_name):
        '''
            get_user_by_name : function return user instance by username
        '''
        return db.GqlQuery("SELECT * FROM User WHERE username= :username", username=user_name).get()     # NOQA

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
        password_hashed = user.password
        return valid_pwd(username, password, password_hashed)


# Post model
class Post(db.Model):
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
    subject = db.TextProperty(required=True)
    content = db.TextProperty(required=True)
    created_date_time = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)
    created_by_user = db.StringProperty(required=False)
    total_likes = db.IntegerProperty(required=False)
    liked_by_users = db.ListProperty(str)

    @classmethod
    def get_post_by_username(cls, user_name):
        posts = db.GqlQuery("SELECT * FROM Post WHERE created_by_user = :username ORDER BY created_date_time DESC", username=user_name)  # NOQA
        return posts

    @classmethod
    def get_all_posts(cls):
        posts = db.GqlQuery("SELECT * FROM Post ORDER BY created_date_time DESC")  # NOQA
        return posts

    @classmethod
    def total_post_by_users(cls, user_name):
        total_post = db.GqlQuery("SELECT * FROM Post WHERE created_by_user= :username", username=user_name).count()  # NOQA
        return total_post

    @classmethod
    def total_posts(cls):
        total_post = db.GqlQuery("SELECT * FROM Post").count()
        return total_post


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
        comments = db.GqlQuery("SELECT * FROM Comment WHERE post_id= :post_id ORDER BY created_date_time", post_id=int(post_id))   # NOQA
        return comments


class Handler(webapp2.RequestHandler):
    '''
        This handler class contains generic functions that are inherited by
        other child handler classes
    '''
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_cookie(self, user, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header('Set-Cookie', '%s=%s; Path=/' %
                                         (user, cookie_val))

    def get_cookie(self, user):
        cookie_val = self.request.cookies.get(user)
        return cookie_val and check_secure_val(cookie_val)

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        user_id = self.get_cookie('user_id')
        self.user = user_id and User.get_user_by_id(int(user_id))


class MainPageHandler(Handler):
    '''
        This handler handles the main page of the blog post
    '''
    def render_main_page(self, user=None, posts=None):
        post_count = Post.total_posts()  # NOQA
        error = ""
        if post_count == 0 or post_count == -1:
            error = "No post found !!!"
            self.render("mainpage.html", posts=posts, user=user,
                        error=error)
        else:
            all_posts = Post.get_all_posts()
            self.render("mainpage.html", posts=all_posts, user=user)

    def get(self):
        if self.user:
            self.render_main_page(user=self.user)
        else:
            self.render_main_page()


class NewPostHandler(Handler):
    '''
        NewPostHandler: Handler handles new post that are posted
    '''
    def render_page(self, subject="", content="", error="", user=None):
        self.render("newpost.html", subject=subject, content=content,
                    error=error, user=user)

    def get(self):
        # Check first is user is logged in or not
        if self.user:
            self.render_page(user=self.user)
        else:
            self.redirect('/login')

    def post(self):
        '''
            It first checks for user and then stores post in the database
        '''
        if self.user:
            self.subject = self.request.get("subject")
            self.content = self.request.get("content")
            self.username = self.user.username
            if self.subject and self.content:
                post = Post(subject=self.subject, content=self.content,
                            created_by_user=self.username)
                post.put()
                # Redirect to the newly created post page
                self.redirect('/post/%s' % str(post.key().id()))
            else:
                self.error = "All fields are required !!"
                self.render_page(subject=self.subject, content=self.content,
                                 error=self.error)
        else:
            self.redirect('/login')


class PostPageHandler(Handler):
    '''
        PostPageHandler: This handler is renders a particular post
    '''
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id))
        self.post = db.get(key)
        if not self.post:
            self.redirect('/')
            return
        self.comments = Comment.get_comments(post_id)
        self.render("post.html", post=self.post, user=self.user,
                    comments=self.comments)


class EditPostHandler(Handler):
    '''
        EditPostHandler : This handler handles post editing.
    '''
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id))
        self.post = db.get(key)
        if self.user:
            if self.post:
                if self.post.created_by_user == self.user.username:
                    self.render("editpost.html", post_id=post_id,
                                post=self.post, subject=self.post.subject,
                                content=self.post.content)
                else:
                    self.redirect('/home')
            else:
                self.redirect('/')
        else:
            self.redirect('/login')

    def post(self, post_id):
        '''
        It first checks if the user is logged in then checks if the post
        exists, if not redirect to home.
        '''
        if self.user:
            postKey = db.Key.from_path('Post', int(post_id))
            self.post = db.get(postKey)
            if self.post:
                if self.post.created_by_user == self.user.username:
                    sub = self.request.get("subject")
                    cont = self.request.get("content")
                    if sub and cont:
                        self.post.subject = sub
                        self.post.content = cont
                        self.post.put()
                        self.redirect('/post/%s' % int(post_id))
                    else:
                        self.error = "All fields are required!!"
                        self.render("editpost.html", error=self.error,
                                    subject=sub, content=cont, post=self.post)
                else:
                    self.redirect('/home')
            else:
                self.redirect('/home')
        else:
            self.redirect('/login')


class DeletePostHandler(Handler):
    '''
        DeletePostHandler: This handler handles post deletion
    '''
    def get(self, post_id):
        if self.user:
            key = db.Key.from_path('Post', int(post_id))
            self.post = db.get(key)
            if self.post:
                if self.post.created_by_user == self.user.username:
                    if self.post.created_by_user == self.user.username:
                        self.render("deletepost.html", post_id=post_id)
                    else:
                        self.redirect("/home")
                else:
                    self.redirect('/home')
            else:
                self.redirect("/home")
        else:
            self.redirect("/login")

    def post(self, post_id):
        '''
        This block first if user is logged in or not, if logged in
        then checks the request made for deletion of post is in database,
        if found it deletes that post.
        '''
        if self.user:
            key = db.Key.from_path('Post', int(post_id))
            self.post = db.get(key)
            if self.post:
                comments = Comment.get_comments(post_id)
                if self.post.created_by_user == self.user.username:
                    db.delete(key)
                    for comment in comments:
                        db.delete(comment)
                    self.redirect("/home")
                else:
                    self.redirect("/home")
            else:
                self.redirect("/home")
        else:
            self.redirect("/login")


class LikePostHandler(Handler):
    '''
        LikePostHandler : this handler handles the post likes
    '''
    def get(self, post_id):
        if self.user:
            key = db.Key.from_path('Post', int(post_id))
            self.post = db.get(key)
            if self.post:
                if self.post.created_by_user == self.user.username:
                    self.redirect('/home')
                else:
                    if self.post.total_likes is None:
                        self.post.total_likes = 0
                    if self.user.username not in self.post.liked_by_users:
                        self.post.total_likes += 1
                        self.post.liked_by_users.append(self.user.username)
                        self.post.put()
                        self.redirect('/post/%s' % int(post_id))
                    else:
                        self.post.total_likes -= 1
                        self.post.liked_by_users.remove(self.user.username)
                        self.post.put()
                        self.redirect('/post/%s' % int(post_id))
            else:
                self.redirect('/home')
        else:
            self.redirect('/login')


class CommentPostHandler(Handler):
    '''
        CommentPostHandler : This handler handles the post comments
    '''
    def post(self, post_id):
        key = db.Key.from_path('Post', int(post_id))
        self.post = db.get(key)
        if self.user:
            self.comment = self.request.get('comment')
            if self.comment:
                c = Comment(comment=self.comment,
                            comment_by_user=self.user.username,
                            post_id=int(post_id))
                c.put()
                self.comments = Comment.get_comments(int(post_id))
                self.redirect('/post/%s' % post_id)
            else:
                self.error = "Comment cannot be blank !!"
                self.redirect('/post/%s' % post_id)
        else:
            self.redirect('/login')


class CommentEditHandler(Handler):
    '''
        CommentEditHandler : This handler handles comment edits
    '''
    def get(self, comment_id):
        if self.user:
            commentKey = db.Key.from_path('Comment', int(comment_id))
            self.comment = db.get(commentKey)
            if self.comment:
                if self.comment.comment_by_user == self.user.username:
                    self.render("editcomment.html", comment=self.comment,
                                user=self.user)
                else:
                    self.redirect('/post/%s' % self.comment.post_id)
            else:
                self.redirect('/home')
        else:
            self.redirect('/login')

    def post(self, comment_id):
        '''
        This block first checks if user is logged in or not, if logged in
        it checks for the comment and if it exists it edit comment.
        '''
        if self.user:
            commentKey = db.Key.from_path('Comment', int(comment_id))
            self.comment = db.get(commentKey)
            if self.comment:
                if self.comment.comment_by_user == self.user.username:
                    editedComment = self.request.get("comment")
                    if editedComment:
                        self.comment.comment = editedComment
                        self.comment.put()
                        self.redirect('/post/%s' % int(self.comment.post_id))
                    else:
                        self.error = "Comment cannot be blank!!"
                        self.render("editcomment.html", comment=self.comment,
                                    user=self.user, error=self.error)
                else:
                    self.redirect('/home')
            else:
                self.redirect('/home')
        else:
            self.redirect('/login')


class CommentDeleteHandler(Handler):
    '''
        CommentDeleteHandler : This handler handles comment deletion
    '''
    def get(self, comment_id):
        if self.user:
            commentKey = db.Key.from_path('Comment', int(comment_id))
            self.comment = db.get(commentKey)
            if self.comment:
                if self.comment.comment_by_user == self.user.username:
                    db.delete(commentKey)
                    self.redirect('/post/%s' % self.comment.post_id)
                else:
                    self.redirect('/home')
            else:
                self.redirect('/home')
        else:
            self.redirect('/login')


class SignUpPageHandler(Handler):
    '''
        SignUpPageHandler : This handler handles sign up
    '''
    def render_sign_up_page(self, name="", username="", password="", verify="",
                            email="", error=""):
        self.render("signup.html", name=name, username=username,
                    password=password, verify=verify, email=email, error=error)

    def get(self):
        if self.user:
            self.redirect('/home')
        else:
            self.render_sign_up_page()

    def post(self):
        # Retrieve data from sign up page
        self.name = self.request.get('name')
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')
        # Checks for name first if it is empty it display error
        if not self.name:
            self.error = "Please enter name !!"
            self.render_sign_up_page(name=self.name,
                                     username=self.username,
                                     email=self.email, error=self.error)
            return
        '''
        This block checks for other entries of details other than name and
        and if each entry is correct it signed up the user and redirect it
        to home page.
        '''
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
                self.render_sign_up_page(name=self.name,
                                         username=self.username,
                                         email=self.email, error=self.error)
            elif not valid_email(self.email):
                self.error = "Email not valid !!"
                self.render_sign_up_page(name=self.name,
                                         username=self.username,
                                         email=self.email, error=self.error)
            else:
                # Checking if username already exists or not
                user = User.get_user_by_username(self.username)
                if user:
                    self.error = "Username already exists !! Please try "
                    "another"
                    self.render_sign_up_page(name=self.name,
                                             username=self.username,
                                             email=self.email,
                                             error=self.error)
                # If user doesn't exists already we put it in datastore
                else:
                    user = User.user_register(name=self.name,
                                              username=self.username,
                                              password=self.password,
                                              email=self.email)
                    user.put()
                    self.set_cookie('user_id', str(user.key().id()))
                    self.redirect('/home')
        # If all fields are not filled this block will execute
        else:
            self.error = "All fields are required !!"
            self.render_sign_up_page(name=self.name, username=self.username,
                                     email=self.email, error=self.error)


class LoginPageHandler(Handler):
    '''
        LoginPageHandler : This handler handles user login
    '''
    def render_login_page(self, username="", password="", error=""):
        self.render("login.html", username=username, error=error)

    def get(self):
        if self.user:
            self.redirect('/home')
        else:
            self.render_login_page()

    def post(self):
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        if self.username and self.password:
            self.user_exists = User.get_user_by_username(self.username)
            # If user don't exists this block will execute
            if not self.user_exists:
                self.error = "User does not exist !!"
                self.render_login_page(username=self.username,
                                       error=self.error)
            else:
                valid_pwds = User.user_login(username=self.username,
                                             password=self.password)
                if valid_pwds:
                    self.set_cookie('user_id',
                                    str(self.user_exists.key().id()))
                    self.redirect('/home')
                else:
                    self.error = "Invalid password !!"
                    self.render_login_page(username=self.username,
                                           error=self.error)
        else:
            self.error = "All fields are required !!"
            self.render_login_page(username=self.username, error=self.error)


class HomePageHandler(Handler):
    '''
        HomePageHandler : This handler handles user home page
    '''
    def render_main_page(self, user=None, posts=None):
        post_count = Post.total_post_by_users(user.username)  # NOQA
        error = ""
        if post_count == 0 or post_count == -1:
            error = "No post found !!!"
            self.render("home.html", posts=posts, user=user,
                        error=error)
        else:
            all_posts = Post.get_post_by_username(user.username)
            self.render("home.html", posts=all_posts, user=user)

    def get(self):
        if self.user:
            self.render_main_page(user=self.user)
        else:
            self.redirect('/')


class LogoutHandler(Handler):
    '''
        LogoutHandler : This handler hanles user logout
    '''
    def get(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')
        self.redirect('/')


app = webapp2.WSGIApplication([
      ('/', MainPageHandler),
      ('/signup', SignUpPageHandler),
      ('/login', LoginPageHandler),
      ('/logout', LogoutHandler),
      ('/home', HomePageHandler),
      ('/newpost', NewPostHandler),
      ('/post/([0-9]+)', PostPageHandler),
      ('/editpost/([0-9]+)', EditPostHandler),
      ('/deletepost/([0-9]+)', DeletePostHandler),
      ('/like/([0-9]+)', LikePostHandler),
      ('/comment/([0-9]+)', CommentPostHandler),
      ('/editcomment/([0-9]+)', CommentEditHandler),
      ('/deletecomment/([0-9]+)', CommentDeleteHandler)
      ], debug=True)
