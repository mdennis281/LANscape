from flask import Flask

app = Flask(__name__)

# Import Blueprints
from blueprints.api import api_bp
from blueprints.web import web_bp

# Register Blueprints
app.register_blueprint(api_bp)
app.register_blueprint(web_bp)

    
# Custom Jinja filter
def is_substring_in_values(results: dict, substring: str) -> bool:
    return any(substring.lower() in str(v).lower() for v in results.values()) if substring else True

app.jinja_env.filters['is_substring_in_values'] = is_substring_in_values


