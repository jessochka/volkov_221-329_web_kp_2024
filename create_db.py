from app import db, User, Task, File
from flask_bcrypt import Bcrypt
from datetime import datetime

bcrypt = Bcrypt()

# Удаляем и создаем заново все таблицы
db.drop_all()
db.create_all()

# Создаем пользователей
hashed_password1 = bcrypt.generate_password_hash('qwertyQQ').decode('utf-8')
hashed_password2 = bcrypt.generate_password_hash('qwertyqq').decode('utf-8')
user1 = User(first_name='Semen', last_name='Volkov', login='volk', password=hashed_password1, avatar='avatar1.jpg')
user2 = User(first_name='Alexey', last_name='Kruzhalov', login='alex', password=hashed_password2, avatar='avatar2.jpg')
db.session.add(user1)
db.session.add(user2)
db.session.commit()
