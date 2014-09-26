import os

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

    @classmethod
    def register(cls, name, password, email):

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

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)
    
PASS_RE = re.compile(r"^.{1,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r"^[\S]+@[\S]+\.[\S]+$")
def valid_email(email):            
    return email and EMAIL_RE.match(email)

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
            #make sure the user does not alerady exist
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
