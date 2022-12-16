import hashlib
import base64
import hmac

from dao.user import UserDAO
from constants import PWD_HASH_ITERATIONS, PWD_HASH_ALGO
from constants import PWD_HASH_SALT

class UserService:
    def __init__(self, dao: UserDAO):
        self.dao = dao

    def get_one(self, bid):
        return self.dao.get_one(bid)

    def get_all(self):
        return self.dao.get_all()

    def get_by_email(self, email):
        return self.dao.get_by_useremail(email)

    def create(self, user_d):
        user_d["password"] = self.make_password_hash(user_d.get("password"))
        return self.dao.create(user_d)

    def update(self, user_d):
        self.dao.update(user_d)
        return self.dao

    def delete(self, user_d):
       self.dao.delete(user_d)

    # Шаг 2.1. Добавьте методы генерации хеша пароля пользователя
    def make_password_hash(self, password):
        # base64.b64encode() - для конвертации в ascii
        return base64.b64encode(hashlib.pbkdf2_hmac(
            PWD_HASH_ALGO,
            password.encode('utf-8'),  # Convert the password to bytes
            PWD_HASH_SALT,
            PWD_HASH_ITERATIONS
        ))

    def compare_passwords(self, password_hash, request_password):
        return hmac.compare_digest(
            base64.b64decode(password_hash),
            hashlib.pbkdf2_hmac(PWD_HASH_ALGO, request_password.encode('utf-8'), PWD_HASH_SALT, PWD_HASH_ITERATIONS)
        )