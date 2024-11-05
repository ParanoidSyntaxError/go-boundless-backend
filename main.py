from dotenv import load_dotenv
load_dotenv()
from API import create_flask_app
from DB import db

# from API import create_flask_app
# from db import db
# ## TO DO CHANGE BACK TO AFTER TESTING
# # app = create_flask_app(db) 
# app = create_flask_app(db)

# if __name__ == "__main__":

#     app.run(debug=True, host="0.0.0.0", use_reloader=False)

from API import create_flask_app

app = create_flask_app(db)

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", use_reloader=False)
