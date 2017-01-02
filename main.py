import os
import webapp2
import jinja2

class MainPage(webapp2.RequestHandler):
    def get(self):
        self.response.headers['Content-Type'] = 'text/plain'
        self.response.write('Hello world')

app = webapp2.WSGIApplication([
      ('/',MainPage),
      ], debug = True)
