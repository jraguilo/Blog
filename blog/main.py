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
                               
class BlogHandler(webapp2.RequestHandler):
    #For reference, *a is arguments, *kw is dictionary
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

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

def valid_pw(name, password, hash):
    salt = hash.split(',')[0]
    return hash == make_pw_hash(name, password, salt)


#create database for blog posts        
class Post(db.Model):
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)
    
class User(db.Model):
    name = db.StringProperty(required = True)
    pw_hash = db.StringProperty(required = True)
    email = db.StringProperty()
    
    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u
    @classmethod
    def register(cls, name, password, email):
        pw_hash = make_pw_hash(name, pw)
        return User(name = name,
                    pw_hash = pw_hash,
                    email = email)
        
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
            u = User.register(self.username, self.password, self.email)
            u.put()
            
class Login(BlogHandler):

class Logout(BlogHandler):


app = webapp2.WSGIApplication([
    ('/', MainHandler),
    ('/newpost', PostHandler),
    ('/register', Register),
    ('/login', Login),
    ('/logout, Logout)
], debug=True)
