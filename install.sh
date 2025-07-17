#!/bin/bash
sudo apt update
echo "Устоновка python3-opencv libatlas-base-dev ffmpeg"
sudo apt install python3-opencv libatlas-base-dev
sudo apt install -y ffmpeg
echo "Устоновка pip flask opencv-python bcrypt"
echo "Если не работает используй pip install -r requirements.txt --break-system-packages"
pip install -r requirements.txt
echo "Генерация ssl сертификата и приватного ключа"
mkdir certs
openssl req -x509 -newkey rsa:4096 -keyout certs/key.pem -out certs/cert.pem -days 365 -nodes
python3 auth_gen.py
echo "Устоновка завершена!"
sleep 1
