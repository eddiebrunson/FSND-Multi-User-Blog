# My working file 2/17/17
# Focus on Front end improvements
# Add favicon image
import os
import re
import random
import hashlib
import hmac
import string
import logging
import webapp2
import jinja2
from secret import secret


from google.appengine.ext import db

# This is template loading code
template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)



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
#      Parent Class      #
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


##########################
#         END OF         #
#        PARENT CLASS    #
##########################

# Add post and likes db code here

class MainPage(BlogHandler):

    def get(self):
        posts = db.GqlQuery("SELECT * FROM Post ORDER BY Likes DESC LIMIT 10")
        if self.user:
            self.render('front.html',
                        posts=posts,
                        loggedIn=self.user)
        else:
            self.redirect('/signup')

#######################################
#     USER SECURITY & VALIDATIONS     #
#######################################

# This fuction makes a string of 5 letters, which makes the salt #


def make_salt(length=5):
    return ''.join(random.choice(string.letters) for x in xrange(length))

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
#               END OF                  #
#      USER SECURITY & VALIDATIONS      #
#########################################


def users_key(group='default'):
    return db.Key.from_path('users', group)

#########################
#      USER OBJECT      #
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


#################################
#       BLOG FUNCTIONALITY      #
#################################

def blog_key(name='default'):
    return db.Key.from_path('blogs', name)

# Add user or authorname


class Post(db.Model):
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)
    likes = db.IntegerProperty(default=0)
    liked = db.StringProperty()
    author = db.StringProperty()

    def render(self, loggedIn):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str('post.html', p=self, loggedIn=loggedIn)


class Comment(db.Model):
    comment = db.TextProperty(required=True)
    author = db.StringProperty()
    created = db.DateTimeProperty(auto_now=True)
    post_id = db.StringProperty(required=True)

# Displays post and comments


class BlogFront(BlogHandler):

    def get(self):
        posts = db.GqlQuery("SELECT * FROM Post ORDER BY likes DESC LIMIT 10")
        comments = Comment.all().order('created')
        if self.user:
            self.render('front.html',
                        posts=posts,
                        comments=comments,
                        loggedIn=self.user)
        else:
            self.redirect('/signup')

# Creates new post


class NewPost(BlogHandler):

    def get(self):
        if self.user:
            self.render('newpost.html', loggedIn=self.user)
        else:
            self.redirect('/blog')

    def post(self):
        if not self.user:
            self.redirect('/login')
        else:
            author = self.user.name
            subject = self.request.get('subject')
            content = self.request.get('content')

            if subject and content:
                p = Post(parent=blog_key(), subject=subject, content=content,
                         author=author)
                p.put()
                post_id = str(p.key().id())
                self.key = post_id
                self.redirect('/blog')
            else:
                error = "Please add subject and content!"
                self.render('newpost.html', subject=subject,
                            content=content, error=error, author=author,
                            loggedIn=self.user)
# New comment


class NewComment(BlogHandler):

    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get((key))
        if not self.user:
            self.redirect('/login')
        else:
            comments = db.GqlQuery('SELECT * FROM Comment ' +
                                   'WHERE post_id = :1 ' +
                                   'ORDER BY created DESC',
                                   post_id)
            self.render('newcomment.html',
                        post=post,
                        comments=comments,
                        loggedIn=self.user)

    def post(self, post_id):
        if not self.user:
            self.redirect('/login')
        else:
            posts = db.GqlQuery(
                'SELECT * FROM Post ORDER BY likes DESC LIMIT 10')
            comment = self.request.get('comment')
            author = self.user.name

            if comment:
                c = Comment(post_id=post_id,
                            author=author,
                            comment=comment)
                c.put()
                self.render('front.html', posts=posts, loggedIn=self.user)


# Edit post


class EditPost(BlogHandler):

    def get(self):
        if not self.user:
            self.redirect('/login')
        else:
            post_id = self.request.get('id')
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)

            if self.user.name == post.author:
                self.render('editpost.html', p=post, loggedIn=self.user)
            else:
                msg = "Sorry, you are not allowed to edit this post."
                self.render('message.html', msg=msg)

    def post(self):
        post_id = self.request.get('id')
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        p = db.get(key)

        if self.user.name != p.author:
            self.redirect('/login')
        else:
            new_post = self.request.get('editpost')
            if new_post:
                p.content = new_post
                p.put()
                self.redirect('/blog')
            else:
                error = "Please, fill in content."
                self.render('editpost.html', p=p, error=error)

# Delete post


class Delete(BlogHandler):

    def get(self):
        if not self.user:
            self.redirect('/login')
        else:
            post_id = self.request.get('id')
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)

            if self.user.name == post.author:
                db.delete(key)
                self.redirect('/blog')
            else:
                self.redirect('/blog')


# Edit comment

class EditComment(BlogHandler):

    def get(self):
        if not self.user:
            self.redirect('/login')
        else:
            comment_id = self.request.get('id')
            key = db.Key.from_path('Comment', int(comment_id))
            comment = db.get(key)

            self.render('editcomment.html',
                        comment=comment,
                        loggedIn=self.user)

    def post(self):
        comment_id = self.request.get('id')
        edit_comment = self.request.get('editcomment')
        key = db.Key.from_path('Comment', int(comment_id))
        comment = db.get(key)
        if self.user.name != comment.author:
            self.redirect('/login')
        else:
            if edit_comment:
                comment.comment = edit_comment
                comment.put()
                self.redirect('/blog')
            else:
                self.redirect('/editcomment?id='+comment_id)

# Delete comment


class DeleteComment(BlogHandler):

    def get(self):
        comment_id = self.request.get('id')
        key = db.Key.from_path('Comment', int(comment_id))
        comment = db.get(key)
        if not self.user:
            self.redirect('/login')
        else:
            if self.user.name != comment.author:
                self.redirect('/login')
            else:
                db.delete(key)
                self.redirect('/blog')


# Like a post

class Like(BlogHandler):

    def get(self):
        if self.user:
            logging.info(self.user.name + ',')
            post_id = self.request.get('id')
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            if post.liked:
                likers = post.liked.split(',')
                if self.user.name not in likers:
                    post.likes += 1
                    post.liked += (self.user.name + ',')
                    post.put()
                    self.redirect('/blog')
                else:
                    self.redirect('/blog')
            else:
                post.likes += 1
                post.liked = (self.user.name + ',')
                post.put()
                self.redirect('/blog')
        else:
            self.redirect('/login')


###########################
#        END OF BLOG      #
#       FUNCTIONALITY     #
###########################


#########################################
#       USER INFORMATION VALIDATION     #
#########################################

# This regular expression checks if username is a-z, 0-9, between 3-20
# characters
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")

# This function checks if there is a username and if it matches this
# regular expression, return true


def valid_username(username):
    return username and USER_RE.match(username)

# This regular expression checks if the password is between 3-20 characters
PASS_RE = re.compile(r"^.{3,20}$")

# This function checks if there is a password and if it matches this
# regular expression, return true


def valid_password(password):
    return password and PASS_RE.match(password)

# This regular expression checks if the email has characters, then an "@", then
# characters, then a ".", then a more characters

EMAIL_RE = re.compile(r'^[\S]+@[\S]+\.[\S]+$')

# This function checks if there is a email and if it matches this regular
# expression, return true


def valid_email(email):
    return not email or EMAIL_RE.match(email)

#########################################
#               END OF                  #
#     USER INFORMATION VALIDATION       #
#########################################

#########################
#       USER STATE      #
#########################


class Signup(BlogHandler):

    def get(self):
        self.render("signup-form.html")

    def post(self):
        # This post variable checks if the function returns false then it will
        # render the success page and take the new user to the blog welcome.
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username=self.username,
                      email=self.email)

        u = User.by_name(self.username)
        if u:
            params['error_username_exists'] = "That username already exists."
            have_error = True

        if not valid_username(self.username):
            params['error_username_not_vaild'] = "Sorry, username is invaild."
            have_error = True

        if not valid_password(self.password):
            params['error_password'] = "Sorry, that was not a vaild password."
            have_error = True
        elif self.password != self.verify:
            params['error_verify'] = "The passwords do not match, try again."
            have_error = True

        if not valid_email(self.email):
            params['error_email'] = "Sorry, that is not a vaild email."
            have_error = True

        if have_error:
            self.render('signup-form.html', **params)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()
            self.login(u)
            self.redirect('/blog')


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


#########################
#     END OF USER       #
#        STATE          #
#########################


##########################
#      APP HANDLERS      #
##########################

app = webapp2.WSGIApplication([('/', MainPage),
                               ('/edit', EditPost),
                               ('/comment/(\d+)', NewComment),
                               ('/editcomment', EditComment),
                               ('/deletecomment', DeleteComment),
                               ('/blog/?', BlogFront),
                               ('/delete', Delete),
                               ('/like', Like),
                               ('/blog/newpost', NewPost),
                               ('/signup', Signup),
                               ('/login', Login),
                               ('/logout', Logout)
                               ],
                              debug=True)
