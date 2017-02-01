# My working file 2/28/17
import os
import re
import random
import hashlib
import hmac
from string import letters

import webapp2
import jinja2

from google.appengine.ext import db

# This is template loading code
template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)
# This secret string is used as the hash secret for cookies
secret = 'PNEUMONOULTRAMICROSCOPICSILICOVOLCANOCONIOSIS'


def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

# This function is used to make a secure val and then hmac of that val


def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())

# This function checks to make sure the secure val is valid


def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val

##########################
###### Parent Class ######
##########################

# This is the parent class for all handlers


class BlogHandler(webapp2.RequestHandler):

    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    # This function checks to see if user is logged in or not #
    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))


def render_post(response, post):
    response.out.write('<b>' + post.subject + '</b><br>')
    response.out.write(post.content)

##########################
######### END OF #########
###### PARENT CLASS ######
##########################

# Add post and likes db code here

# Working to fix error 
class MainPage(BlogHandler):

    def get(self):
        if self.user:
            self.render('front.html')
                        #posts=posts,
                        #loggedIn=self.user)
        else:
            self.redirect('/signup')

#######################################
##### USER SECURITY & VALIDATIONS #####
#######################################

# This fuction makes a string of 5 letters, which makes the salt #


def make_salt(length=5):
    return ''.join(random.choice(letters) for x in xrange(length))

# This function makes our password hash #


def make_pw_hash(name, pw, salt=None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)

# This function is used to verfiy the password #

# It does so by taking a name, password, and  the value in the database
# and it makes sure the hash from the database matches the new hash
# that was created based on what the user entered in


def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)

# This creates the ancesteor elements in the datatbase to store all of our
# users

#########################################
################# END OF ################
###### USER SECURITY & VALIDATIONS ######
#########################################


def users_key(group='default'):
    return db.Key.from_path('users', group)

#########################
###### USER OBJECT ######
#########################

# This is the user object to store in the database


class User(db.Model):
    # These three parameters name, pw_hash, and email are required
    name = db.StringProperty(required=True)
    pw_hash = db.StringProperty(required=True)
    email = db.StringProperty()

    # This is a decorator, which is used to call the method on this object
    # In other words it calls methods on this class user
    # So in this case it takes user.byid, gives it an ID, and then calls
    # getbyid function to load the user onto the database
    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent=users_key())

    # This decorator, which uses the function by_name, which looks up a user
    # by its name

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u

    # This decorator, uses the method register, which takes a name, password,
    # and email to creat a new user object. It creates a password hash for
    # that username and password and creates a user object
    @classmethod
    def register(cls, name, pw, email=None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent=users_key(),
                    name=name,
                    pw_hash=pw_hash,
                    email=email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u


# blog stuff

def blog_key(name='default'):
    return db.Key.from_path('blogs', name)


class Post(db.Model):
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)
# Add likes here

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p=self)


class BlogFront(BlogHandler):

    def get(self):
        posts = greetings = Post.all().order('-created')
        self.render('front.html', posts=posts)


class PostPage(BlogHandler):

    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if not post:
            self.error(404)
            return

        self.render("permalink.html", post=post)


class NewPost(BlogHandler):

    def get(self):
        if self.user:
            self.render("newpost.html")
        else:
            self.redirect("/login")

    def post(self):
        if not self.user:
            self.redirect('/blog')

        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
            p = Post(parent=blog_key(), subject=subject, content=content)
            p.put()
            self.redirect('/blog/%s' % str(p.key().id()))
        else:
            error = "subject and content, please!"
            self.render(
                "newpost.html", subject=subject, content=content, error=error)


# Unit 2 HW's
# class Rot13(BlogHandler):
#    def get(self):
#        self.render('rot13-form.html')
#
#    def post(self):
#        rot13 = ''
#        text = self.request.get('text')
#        if text:
#            rot13 = text.encode('rot13')
#
#        self.render('rot13-form.html', text = rot13)

#########################################
###### USER INFORMATION VALIDATION ######
#########################################

# This expression checks if username is a-z, 0-9, between 3-20 characters
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")

# This function checks if there is a username and if it matches this
# regular expression, return true


def valid_username(username):
    return username and USER_RE.match(username)

# This expression checks if the password is between 3-20 characters
PASS_RE = re.compile(r"^.{3,20}$")

# This function checks if there is a password and if it matches this
# regular expression, return true


def valid_password(password):
    return password and PASS_RE.match(password)

# This expression checks if the email has characters, then an "@", then
# characters, then a ".", then a more characters

EMAIL_RE = re.compile(r'^[\S]+@[\S]+\.[\S]+$')

# This function checks if there is a email and if it matches this regular
# expression, return true


def valid_email(email):
    return not email or EMAIL_RE.match(email)

#########################################
############## END OF ###################
###### USER INFORMATION VALIDATION ######
#########################################


class Signup(BlogHandler):

    def get(self):
        self.render("signup-form.html")

    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username=self.username,
                      email=self.email)

        # u = User.by_name(self.username)
        # if u:
        # params['error_username1'] = "Username Already Exists"
        # errors = True

        if not valid_username(self.username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not valid_password(self.password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif self.password != self.verify:
            params['error_verify'] = "Your passwords did not match."
            have_error = True

        if not valid_email(self.email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        if have_error:
            self.render('signup-form.html', **params)
        else:
            self.done()

    def done(self, *a, **kw):
        raise NotImplementedError

# Remove thi sign up ?Q
# class Unit2Signup(Signup):

    # def done(self):
        # self.redirect('/unit2/welcome?username=' + self.username)

# This handler inherits from the class Signup


class Register(Signup):

    def done(self):
        # make sure the user doesn't already exist
        u = User.by_name(self.username)
        if u:
            msg = 'That user already exists.'
            self.render('signup-form.html', error_username=msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()

            self.login(u)
            self.redirect('/blog')


class Login(BlogHandler):

    def get(self):
        self.render('login-form.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect('/blog')
        else:
            msg = 'Invalid login'
            self.render('login-form.html', error=msg)


class Logout(BlogHandler):

    def get(self):
        self.logout()
        self.redirect('/signup')


class Unit3Welcome(BlogHandler):

    def get(self):
        if self.user:
            self.render('welcome.html', username=self.user.name)
        else:
            self.redirect('/signup')

# Remove this one ?
# class Welcome(BlogHandler):

#    def get(self):
#        username = self.request.get('username')
#        if valid_username(username):
#            self.render('welcome.html', username=username)
#        else:
#            self.redirect('/unit2/signup')

##########################
###### APP HANDLERS ######
##########################

app = webapp2.WSGIApplication([('/', MainPage),
                               #('/unit2/rot13', Rot13),
                               #'/unit2/signup', Unit2Signup),
                               #('/unit2/welcome', Welcome),
                               ('/blog/?', BlogFront),
                               ('/blog/([0-9]+)', PostPage),
                               ('/blog/newpost', NewPost),
                               ('/signup', Register),
                               ('/login', Login),
                               ('/logout', Logout),
                               ('/unit3/welcome', Unit3Welcome),
                               ],
                              debug=True)
