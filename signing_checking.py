import hashlib
import random
import math


'''def string_to_blocks(message, p):
    """Перетворення рядка на блоки числами."""
    blocks = []
    for char in message:
        # Перетворюємо символ на число
        block = ord(char)

        # Перевірка, що блок менше p
        if block >= p:
            raise ValueError(f"Символ {char} перевищує допустиме значення для p={p}")

        blocks.append(block)
    return blocks


def blocks_to_string(blocks):
    """Перетворення блоків назад у рядок."""
    return ''.join(chr(block) for block in blocks)'''


def is_prime(n):
    """Перевірка числа на простоту."""
    if n < 2:
        return False
    for i in range(2, int(math.sqrt(n)) + 1):
        if n % i == 0:
            return False
    return True


def generate_prime(max_val=10000):
    """Генерація випадкового простого числа."""
    while True:
        p = random.randint(2, max_val)
        if is_prime(p):
            return p


def generate_keys_al_gamal():
    """Генерація ключів для системи Аль-Гамаля."""
    p = generate_prime()

    while True:
        g = random.randint(2, p - 1)
        if g < p:
            break

    x = random.randint(2, p - 2)
    y = pow(g, x, p)

    return {
        'public_key': (p, g, y),
        'private_key': x
    }


def hash_message(message):
    """
    Перетворення повідомлення в число для хешування.

    :param message: Повідомлення (рядок або список цілих чисел)
    :return: Число-хеш повідомлення
    """
    if isinstance(message, str):
        # Якщо рядок - кодуємо в байти
        message_bytes = message.encode()
    elif isinstance(message, list):
        # Перетворення списку на байти з підтримкою більших чисел
        message_bytes = b''.join(num.to_bytes((num.bit_length() + 7) // 8, byteorder='big') for num in message)
    else:
        raise ValueError("Непідтримуваний тип повідомлення")

    return int(hashlib.sha1(message_bytes).hexdigest(), 16)


def sign_message(message, private_key, public_key):
    """
    Підписання повідомлення методом Ель-Гамаля з підтримкою різних типів вхідних даних.

    :param message: Повідомлення для підпису (рядок або список int)
    :param private_key: Приватний ключ
    :param public_key: Кортеж (p, g, y)
    :return: Підпис (a, b)
    """
    p, g, y = public_key
    x = private_key

    # Конвертація повідомлення в байти і хешування
    hash_value = hash_message(message)

    # Знаходження k - випадкового числа, що є взаємно простим з (p-1)
    while True:
        k = random.randint(2, p - 2)
        if math.gcd(k, p - 1) == 1:
            break

    # Обчислення a = g^k mod p
    a = pow(g, k, p)

    # Обчислення b = (H(m) - x*a) * k^-1 mod (p-1)
    def mod_inverse(a, m):
        def egcd(a, b):
            if a == 0:
                return (b, 0, 1)
            else:
                g, y, x = egcd(b % a, a)
                return (g, x - (b // a) * y, y)

        g, x, _ = egcd(a, m)
        if g != 1:
            raise Exception('Модульне обернене не існує')
        else:
            return x % m

    k_inverse = mod_inverse(k, p - 1)
    b = ((hash_value - x * a) * k_inverse) % (p - 1)

    return (a, b)


def verify_signature(message, signature, public_key):
    """
    Перевірка підпису методом Ель-Гамаля з підтримкою різних типів вхідних даних.

    :param message: Оригінальне повідомлення (рядок або список int)
    :param signature: Кортеж підпису (a, b)
    :param public_key: Кортеж публічного ключа (p, g, y)
    :return: True, якщо підпис валідний, інакше False
    """
    p, g, y = public_key
    a, b = signature

    # Перевірка меж підпису
    if not (1 <= a < p and 0 <= b < p - 1):
        return False

    # Хешування повідомлення
    hash_value = hash_message(message)

    # Перевірка умови підпису
    # y^a * a^b ≡ g^H(m) (mod p)
    left_side = (pow(y, a, p) * pow(a, b, p)) % p
    right_side = pow(g, hash_value, p)

    return left_side == right_side


def test_el_gamal_signature():
    """Тестування системи підпису Ель-Гамаля."""
    print("Генерація ключів...")
    keys = generate_keys_al_gamal()
    public_key = keys['public_key']
    private_key = keys['private_key']

    # Тестові повідомлення
    test_messages = [
        "Hello, World!",
        "Це тестове повідомлення",
        "Перевірка криптографічного підпису"
    ]

    # Тестові повідомлення у вигляді списків чисел
    test_numeric_messages = [
        [1000, 2000, 3000, 400, 6000, 3000, 1000, 4503, 6704],
        [54321, 98765, 12345, 430223, 230521, 385302, 420522],
        [9876543210, 1234567890, 1234567890, 1234567890, 1234567890],
        [ord(char) for char in 'Бюлетень тест']
    ]

    # Тестування текстових повідомлень
    print("\n--- Тестування текстових повідомлень ---")
    for message in test_messages:
        print(f"\nТестування повідомлення: {message}")

        # Підписання повідомлення
        signature = sign_message(message, private_key, public_key)
        print(f"Підпис: {signature}")

        # Перевірка підпису
        is_valid = verify_signature(message, signature, public_key)
        print(f"Підпис валідний: {is_valid}")

        # Перевірка невірного підпису
        wrong_signature = (signature[0] + 1, signature[1])
        is_valid_wrong = verify_signature(message, wrong_signature, public_key)
        print(f"Невірний підпис: {is_valid_wrong}")

    # Тестування числових повідомлень
    print("\n--- Тестування числових повідомлень ---")
    for message in test_numeric_messages:
        print(f"\nТестування числового повідомлення: {message}")

        # Підписання повідомлення
        signature = sign_message(message, private_key, public_key)
        print(f"Підпис: {signature}")

        # Перевірка підпису
        is_valid = verify_signature(message, signature, public_key)
        print(f"Підпис валідний: {is_valid}")

        # Перевірка невірного підпису
        wrong_signature = (signature[0] + 1, signature[1])
        is_valid_wrong = verify_signature(message, wrong_signature, public_key)
        print(f"Невірний підпис: {is_valid_wrong}")


'''
# Виконання тестів
if __name__ == "__main__":
    test_el_gamal_signature()
'''