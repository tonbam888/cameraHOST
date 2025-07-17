import bcrypt

password = input("Напиши пароль который будет использоваться:")
hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
print("Это пароль в шифровоном виде:", '\n', hashed.decode())
