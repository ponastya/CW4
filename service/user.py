import hashlib
import base64
import hmac

from dao.user import UserDAO
from constants import PWD_HASH_ITERATIONS
from constants import JWT_ALGO, PWD_HASH_SALT

class UserService:
    def __init__(self, dao: UserDAO):
        self.dao = dao

    def get_one(self, bid):
        return self.dao.get_one(bid)

    def get_all(self):
        return self.dao.get_all()

    def get_by_username(self, username):
        return self.dao.get_by_username(username)

    def create(self, user_d):
        return self.dao.create(user_d)

    def update(self, user_d):
        self.dao.update(user_d)
        return self.dao

    def delete(self, rid):
        self.dao.delete(rid)

    # Шаг 2.1. Добавьте методы генерации хеша пароля пользователя
    def get_hash(self, password):
        # base64.b16encode() - для конвертации в ascii
        return base64.b16encode(hashlib.pbkdf2_hmac(
            JWT_ALGO,
            password.encode('utf-8'),  # Convert the password to bytes
            PWD_HASH_SALT,
            PWD_HASH_ITERATIONS
        ))

    def compare_passwords(self, password_hash, request_password):
        hmac.compare_digest(
            base64.b16encode(password_hash),
            hashlib.pbkdf2_hmac(JWT_ALGO, request_password.encode('utf-8'), PWD_HASH_SALT, PWD_HASH_ITERATIONS)
        )