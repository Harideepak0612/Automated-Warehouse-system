import json
from flask_bcrypt import Bcrypt

bcrypt = Bcrypt()

# Define users with hashed passwords
users = {
    "admin": {
        "password": bcrypt.generate_password_hash("123").decode("utf-8"),
        "role": "admin"
    },
    "user1": {
        "password": bcrypt.generate_password_hash("password").decode("utf-8"),
        "role": "user"
    }
}

# Save to users.json
with open("users.json", "w") as file:
    json.dump(users, file, indent=4)

print("✅ users.json file has been reset with hashed passwords!")
