import calendar
import datetime

import jwt

from constants import JWT_SECRET, JWT_ALGO
from service.user import UserService


class AuthService:
    def __init__(self, user_service: UserService):
        self.user_service = user_service

    # POST /auth — получает логин и пароль из Body запроса в виде JSON,
    # далее проверяет соответствие с данными в БД (есть ли такой пользователь, такой ли у него пароль)
    # и если всё оk — генерит пару access_token и refresh_token и отдает их в виде JSON.
    def generate_token(self, username, password, is_refresh=False):
        user = self.user_service.get_by_username(username)

        if user is None:
            raise Exception

        if not is_refresh:
            if not self.user_service.compare_passwords(user.password, password):
                raise Exception

        data = {
            "username": user.username,
            "role": user.role
        }

        # 30 min access_token TTL (time to live)
        # берем текущую дату utcnow() и прибавляем к ней 30 мин timedelta() - это будет время жизни токена
        access_token_min30 = datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
        data["exp"] = calendar.timegm(access_token_min30.timetuple())
        # кодирует информацию в токен, передаем данные, секретный код и алгоритм, по которому надо кодировать
        access_token = jwt.encode(data, JWT_SECRET, algorithm=JWT_ALGO)  # на выходе токен -- данные.данные.данные

        # 130 days refresh_token живет
        days130 = datetime.datetime.utcnow() + datetime.timedelta(days=130)
        data["exp"] = calendar.timegm(days130.timetuple())
        refresh_token = jwt.encode(data, JWT_SECRET, algorithm=JWT_ALGO)

        tokens = {"access_token": access_token, "refresh_token": refresh_token}

        return tokens

    # PUT /auth — получает refresh_token из Body запроса в виде JSON, далее проверяет refresh_token
    # и если он не истек и валиден — генерит пару access_token и refresh_token и отдает их в виде JSON.
    def check_token(self, refresh_token):
        data = jwt.decode(jwt=refresh_token, key=JWT_SECRET, algorithms=[JWT_ALGO])
        username = data.get("username")
        user = self.user_service.get_by_username(username)

        if user is None:
            raise Exception

        return self.generate_token(username, user.password, is_refresh=True)
