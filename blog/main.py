import hashlib
import hmac
import random
import re
import os
from string import letters

import webapp2
import jinja2

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)
                               
SECRET = '89uij7se'  

#validation functions
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)
    
PASS_RE = re.compile(r"^.{1,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r"^[\S]+@[\S]+\.[\S]+$")
def valid_email(email):            
    return email and EMAIL_RE.match(email)
    
#user functions
#Note: Password hashing is self implemented for learning purposes only
def make_salt():
    return ''.join(random.choice(letters) for x in xrange(5))
    
def make_pw_hash(name, pw, salt = None):
    if not salt:
        salt = make_salt()
    hash = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, hash)

def valid_pw(name, pw, hash):
    salt = hash.split(',')[0]
    return hash == make_pw_hash(name, pw, salt)
    
def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(SECRET, val).hexdigest())
    
def check_secure_val(hash):
    val = hash.split('|')[0]
    if h == make_secure_val(val):
        return val

def user_key(group = 'default'):
    return db.Key.from_path('users', group)

def blog_key(name = 'default'):
    return db.Key.from_path('blogs', name)
        
class BlogHandler(webapp2.RequestHandler):
    #For reference, *a is arguments, *kw is dictionary
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

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

#create database for blog posts        
class Post(db.Model):
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)
    
class User(db.Model):
    name = db.StringProperty(required = True)
    pw_hash = db.StringProperty(required = True)
    email = db.StringProperty(required = True)
    
    @classmethod
    def by_id(cls, uid):
        return cls.get_by_id(uid, parent = user_key())
    
    @classmethod
    def by_name(cls, name):
        u = cls.all().filter('name =', name).get()
        return u
        
    @classmethod
    def register(cls, name, pw, email):
        pw_hash = make_pw_hash(name, pw)
        return cls(parent = user_key(),
                    name = name,
                    pw_hash = pw_hash,
                    email = email)
                    
    @classmethod
    def authenticate_user(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u
        
class MainHandler(BlogHandler):
    def get(self):
        posts = db.GqlQuery("SELECT * FROM Post ORDER BY last_modified DESC")
        self.render("front.html", posts=posts)
        
class PostHandler(BlogHandler):
    def render_front(self, subject="", content="", error=""):
        self.render("newpost.html", subject=subject, content=content, error=error)
        
    def get(self):
        self.render_front()
    def post(self):
        subject = self.request.get("subject")
        content = self.request.get("content")
        if subject and content:
            p = Post(subject=subject, content=content)
            p.put()
            self.redirect("/")
        else:
            error = "Missing subject or content"
            self.render_front(subject, content, error)

class Register(BlogHandler):
    def get(self):
        self.render("register.html")
        
    def post(self):
        #get input
        username = self.request.get("username")
        password = self.request.get("password")
        verify = self.request.get("verify")
        email = self.request.get("email")
       
        error = False
        params = dict(username = username, email = email)
       
        #verify input
        if not valid_username(username):
            params['user_error'] = "That was not a valid username"
            error = True
            
        else:
            #make sure the user does not already exist
            u = User.by_name(username)
            if u:
                params['user_error'] = "That user already exists"
                error = True
        if not valid_password(password):
            params['pass_error'] = "That was not a valid password"
            error = True
        elif password != verify:
            params['verify_error'] = "Your passwords did not match"
        if not valid_email(email):
            params['email_error'] = "That was not a valid email"
            error = True
            
        if error:
            #render registration page with error messages
            self.render("register.html", **params)
        else:
            #create user
            u = User.register(username, password, email)
            u.put()
            self.login(u)
            self.write('Welcome')
            
class Login(BlogHandler):
    def get(self):
        self.render("login.html")
        
    def post(self):
        username = self.request.get("username")
        password = self.request.get("password")
        
        #verify username and password
        u = User.authenticate_user(username, password)
        if u:
            self.login(u)
            self.write("login successful")
        else:
            msg = "Invalid Login"
            self.render("login.html", error = msg)
    
class Logout(BlogHandler):
    def get(self):
        self.render("register.html")

app = webapp2.WSGIApplication([
    ('/', MainHandler),
    ('/newpost', PostHandler),
    ('/register', Register),
    ('/login', Login),
    ('/logout', Logout)
], debug=True)
