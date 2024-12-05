import random
import math
from sympy import isprime, mod_inverse

def bytes_to_string(bytes_list):
    # Перетворення числових значень назад у текст
    return ''.join(chr(byte) for byte in bytes_list)

def string_to_bytes(message):
    # Перетворення рядка на список байтів
    return [ord(char) for char in message]

# -------------------------------- Функції для генерації RSA ключів --------------------------------

def is_prime(n):
    """Перевірка, чи є число простим"""
    if n < 2:
        return False

    for i in range(2, int(n**0.5) + 1):
        if n % i == 0:
            return False
    return True


def generate_prime(min_val=5000, max_val=7000):
    """Генерація випадкового простого числа в заданому діапазоні"""
    while True:
        num = random.randint(min_val, max_val)
        if isprime(num):
            return num


def generate_rsa_keys(min_val=5000, max_val=7000):
    """Створення пари публічний/приватний ключ методом RSA"""
    p = generate_prime(min_val, max_val)  # Випадкове просте число p
    q = generate_prime(min_val, max_val)  # Випадкове просте число q

    while p == q:  # Перевірка, щоб p і q були різними
        q = generate_prime()

    n = p * q  # Модуль
    phi = (p - 1) * (q - 1)  # Функція Ейлера

    # Вибір випадкового відкритого експоненту, взаємно простого з phi
    def generate_coprime_exponent(phi):
        while True:
            e = generate_prime(2, phi - 1)
            if math.gcd(e, phi) == 1:
                return e
    e = generate_coprime_exponent(phi)

    # Обчислення приватного ключа d
    d = mod_inverse(e, phi)

    # Повертаємо словник з ключами для зручності
    return {
        'private_key': {
            'exponent': d,
            'modulus': n
        },
        'public_key': {
            'exponent': e,
            'modulus': n
        }
    }


def generate_rsa_keys_test(n, min_prime, max_prime):
    """Створення пари публічний/приватний ключ методом RSA"""

    p = generate_prime(min_prime, max_prime)  # Випадкове просте число p
    q = generate_prime(min_prime, max_prime)  # Випадкове просте число q

    while p == q or p * q != n:  # Перевірка, щоб p і q були різними та добуток перевищував max_encrypt_value
        p = generate_prime(min_prime, max_prime)
        q = generate_prime(min_prime, max_prime)

    phi = (p - 1) * (q - 1)  # Функція Ейлера

    # Вибір випадкового відкритого експоненту, взаємно простого з phi
    def generate_coprime_exponent(phi):
        while True:
            e = generate_prime(2, phi - 1)
            if math.gcd(e, phi) == 1:
                return e

    e = generate_coprime_exponent(phi)

    # Обчислення приватного ключа d
    def mod_inverse(a, m):
        m0, x0, x1 = m, 0, 1
        while a > 1:
            q = a // m
            a, m = m, a % m
            x0, x1 = x1 - q * x0, x0
        return x1 + m0 if x1 < 0 else x1

    d = mod_inverse(e, phi)

    # Повертаємо словник з ключами для зручності
    return {
        'private_key': {
            'exponent': d,
            'modulus': n
        },
        'public_key': {
            'exponent': e,
            'modulus': n
        }
    }


def encrypt_message(message, public_key):
    """
    Шифрування повідомлення публічним ключем.
    Підтримує різні типи вхідних даних.

    :param message: Повідомлення для шифрування (рядок або list)
    :param public_key: Публічний ключ для шифрування
    :return: Зашифроване повідомлення (list)
    """
    # Перевірка типу вхідного повідомлення
    if isinstance(message, str):
        # Якщо рядок - перетворюємо на список ASCII кодів
        message_bytes = [ord(char) for char in message]
    elif isinstance(message, list):
        # Якщо список - використовуємо як є
        message_bytes = message
    else:
        raise ValueError("Непідтримуваний тип повідомлення")

    # Шифрування кожного елементу
    encrypted_message = [
        pow(byte, public_key['exponent'], public_key['modulus'])
        for byte in message_bytes
    ]

    return encrypted_message


def decrypt_message(encrypted_message, private_key, to_string=False):
    """
    Дешифрування повідомлення приватним ключем

    :param encrypted_message: Зашифроване повідомлення
    :param private_key: Приватний ключ для дешифрування
    :param to_string: Якщо True, перетворює результат на рядок, інакше залишає як список чисел
    :return: Розшифроване повідомлення (рядок або список чисел)
    """
    # Перевірка типу вхідного повідомлення
    if isinstance(encrypted_message, bytes):
        # Якщо bytes - декодуємо та перетворюємо на список
        encrypted_message = list(encrypted_message)
    elif not isinstance(encrypted_message, list):
        raise ValueError("Непідтримуваний тип зашифрованого повідомлення")

    # Розшифрування кожного зашифрованого блоку
    decrypted_bytes = [
        pow(byte, private_key['exponent'], private_key['modulus'])
        for byte in encrypted_message
    ]

    # Перевірка, чи потрібно перетворювати на рядок
    if to_string:
        # Перетворення числових значень назад у текст
        return ''.join(chr(byte) for byte in decrypted_bytes)
    else:
        # Повертаємо список чисел
        return decrypted_bytes


def test_rsa_encryption():
    """Розширене тестування процесу шифрування та дешифрування"""
    # Генерація ключів
    keys = generate_rsa_keys()

    # Тест 1: Шифрування та дешифрування рядка
    print("Тест 1: Шифрування рядка")
    original_message = "Привіт, це тестове повідомлення RSA!"
    encrypted_msg = encrypt_message(original_message, keys['public_key'])
    decrypted_msg = decrypt_message(encrypted_msg, keys['private_key'], True)
    print("Оригінальне повідомлення:", original_message)
    print("Розшифроване повідомлення:", decrypted_msg)
    print("Успіх:", original_message == decrypted_msg)

    # Тест 2: Шифрування та дешифрування числа
    print("\nТест 2: Шифрування числа")
    original_number = 12345
    encrypted_num = encrypt_message(original_number, keys['public_key'])
    decrypted_num = decrypt_message(encrypted_num, keys['private_key'])
    print("Оригінальне число:", original_number)
    print("Розшифроване число:", decrypted_num)
    print("Успіх:", original_number == decrypted_num[0])

    # Тест 3: Шифрування та дешифрування списку
    print("\nТест 3: Шифрування списку")
    original_list = [65, 66, 67]
    encrypted_list = encrypt_message(original_list, keys['public_key'])
    decrypted_list = decrypt_message(encrypted_list, keys['private_key'])
    print("Оригінальний список:", original_list)
    print("Розшифрований список:", decrypted_list)
    print("Успіх:", original_list == decrypted_list)


def test_forth_encryption_with_validation():
    while True:
        original_message = "Вибір 1|akf9sasc4dkf2l4"

        # Шифруємо перший раз
        first_keys = generate_rsa_keys()
        encrypted_m_1 = encrypt_message(original_message, first_keys['public_key'])


        # Шифруємо другий раз
        second_keys = generate_rsa_keys()
        encrypted_m_2 = encrypt_message(encrypted_m_1, first_keys['public_key'])


        # Шифруємо третій раз
        third_keys = generate_rsa_keys()
        encrypted_m_3 = encrypt_message(encrypted_m_2, first_keys['public_key'])

        # Шифруємо четвертий раз
        forth_keys = generate_rsa_keys()
        encrypted_m_4 = encrypt_message(encrypted_m_3, first_keys['public_key'])

        #  decryption
        decrypted_m_1 = decrypt_message(encrypted_m_4, first_keys['private_key'])
        decrypted_m_2 = decrypt_message(decrypted_m_1, first_keys['private_key'])
        decrypted_m_3 = decrypt_message(decrypted_m_2, first_keys['private_key'])
        decrypted_m_4 = decrypt_message(decrypted_m_3, first_keys['private_key'])

        # Перевірка успішності дешифрування
        decrypted_string = bytes_to_string(decrypted_m_4)

        if decrypted_string == original_message:
            return {
                'first_keys': first_keys,
                'second_keys': first_keys,
                'third_keys': first_keys,
                'forth_keys': first_keys
            }


'''# Запуск тесту
if __name__ == "__main__":
    test_rsa_encryption()
    keys = test_forth_encryption_with_validation()'''
