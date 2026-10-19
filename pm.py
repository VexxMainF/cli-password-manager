import json
import os
import getpass
from pathlib import Path
from cryptography.fernet import Fernet
import hashlib

# Файлы для хранения данных
DATA_FILE = Path("passwords.json")
KEY_FILE = Path("secret.key")

def generate_key():
    """Генерирует ключ шифрования, если его еще нет."""
    if not KEY_FILE.exists():
        key = Fernet.generate_key()
        KEY_FILE.write_bytes(key)

def load_cipher():
    """Загружает ключ и инициализирует инструмент шифрования."""
    key = KEY_FILE.read_bytes()
    return Fernet(key)

def hash_master_password(password: str) -> str:
    """Хеширует мастер-пароль для безопасной проверки при входе."""
    return hashlib.sha256(password.encode()).hexdigest()

def initialize_vault():
    """Создает первый вход, если программа запускается впервые."""
    if not DATA_FILE.exists():
        print("🔐 Добро пожаловать в Менеджер Паролей!")
        print("Создайте Мастер-Пароль. ЗАПОМНИТЕ ЕГО! Без него данные нельзя восстановить.")
        
        while True:
            master = getpass.getpass("Введите Мастер-Пароль: ")
            confirm = getpass.getpass("Повторите Мастер-Пароль: ")
            if master == confirm and master:
                break
            print("❌ Пароли не совпадают или пусты! Попробуйте еще раз.\n")
            
        generate_key()
        
        # Сохраняем хеш мастер-пароля для последующих проверок
        initial_data = {
            "master_hash": hash_master_password(master),
            "vault": {}
        }
        save_data(initial_data)
        print("✅ Хранилище успешно создано!\n")

def load_data() -> dict:
    """Загружает данные из файла."""
    if not DATA_FILE.exists():
        return {}
    with open(DATA_FILE, "r", encoding="utf-8") as f:
        return json.load(f)

def save_data(data: dict):
    """Сохраняет данные в файл."""
    with open(DATA_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4, ensure_ascii=False)

def authenticate() -> bool:
    """Проверяет мастер-пароль при запуске."""
    if not DATA_FILE.exists():
        initialize_vault()
        return True
        
    data = load_data()
    stored_hash = data.get("master_hash")
    
    print("🔒 Хранилище заблокировано.")
    attempts = 3
    while attempts > 0:
        master = getpass.getpass("Введите Мастер-Пароль для входа: ")
        if hash_master_password(master) == stored_hash:
            print("🔓 Доступ разрешен!\n")
            return True
        attempts -= 1
        print(f"❌ Неверный пароль. Осталось попыток: {attempts}\n")
        
    return False

def add_password(cipher):
    """Добавляет новый пароль в хранилище."""
    resource = input("Введите название сервиса (например, GitHub, Google): ").strip().lower()
    login = input("Введите логин/email: ").strip()
    password = getpass.getpass("Введите пароль для этого сервиса: ").strip()
    
    if not resource or not login or not password:
        print("❌ Все поля должны быть заполнены!")
        return

    # Шифруем пароль перед сохранением
    encrypted_pass = cipher.encrypt(password.encode()).decode()
    
    data = load_data()
    data["vault"][resource] = {
        "login": login,
        "password": encrypted_pass
    }
    save_data(data)
    print(f"🎉 Пароль для '{resource}' успешно зашифрован и сохранен!")

def get_password(cipher):
    """Ищет и расшифровывает пароль."""
    resource = input("Какой сервис ищем? ").strip().lower()
    data = load_data()
    vault = data.get("vault", {})
    
    if resource in vault:
        login = vault[resource]["login"]
        encrypted_pass = vault[resource]["password"]
        
        # Расшифровываем обратно в текст
        decrypted_pass = cipher.decrypt(encrypted_pass.encode()).decode()
        
        print("\n🔑 Данные аккаунта:")
        print(f"📌 Сервис: {resource.capitalize()}")
        print(f"👤 Логин:  {login}")
        print(f"👁️  Пароль: {decrypted_pass}")
    else:
        print(f"❌ Сервис '{resource}' не найден в хранилище.")

def main():
    initialize_vault()
    if not authenticate():
        print("🚨 Превышено количество попыток. Выход.")
        return
        
    cipher = load_cipher()
    
    while True:
        print("\n--- МЕНЮ ---")
        print("1. Добавить новый пароль")
        print("2. Найти и показать пароль")
        print("3. Выйти")
        
        choice = input("Выберите действие (1-3): ").strip()
        
        if choice == "1":
            add_password(cipher)
        elif choice == "2":
            get_password(cipher)
        elif choice == "3":
            print("👋 Хранилище закрыто. До встречи!")
            break
        else:
            print("❌ Неверный пункт меню.")

if __name__ == "__main__":
    main()
