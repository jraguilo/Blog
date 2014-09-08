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

app = webapp2.WSGIApplication([
    ('/', MainHandler),
    ('/newpost', PostHandler)
], debug=True)
