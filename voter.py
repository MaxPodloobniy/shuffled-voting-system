from encryption_decryption import *
from signing_checking import *
from datetime import datetime

def generate_random_string():
    timestamp = datetime.now().isoformat().encode('utf-8')
    string = hashlib.sha1(timestamp).hexdigest()
    return string[:15]

class Voter:
    def __init__(self, name, comm_keys, choice):
        self.name = name
        self.public_comm_key = comm_keys['public_key']
        self.private_comm_key = comm_keys['private_key']
        self.sign_keys = generate_keys_al_gamal()
        self.public_sign_key = self.sign_keys['public_key']
        self.private_sign_key = self.sign_keys['private_key']
        self.choice = choice
        self.random_strings = []

    def create_ballot(self, public_key_list):
        """
        Функція для створення початково зашифрованого бюлетеня всіма ключами RSA.

        :param public_key_list: Список публічних ключів RSA.
        :return: Зашифрований бюлетень та список AES-ключів.
        """

        # Створення FcA(FcB(FcC(FcD(Ev, Rs1)))), де Rs - випадковий рядок, Ev - бюлетень, Fc - функція шифрування
        random_string = generate_random_string()
        self.random_strings.append(random_string)
        ballot = f'{self.choice}{random_string}'
        prev_ballot = string_to_bytes(ballot) # Перетворення на список байтів

        # Шифрування вибору виборця
        for key in reversed(public_key_list):
            encrypted_ballot = encrypt_message(prev_ballot, key)
            prev_ballot = encrypted_ballot

        # Додавання додаткових випадкових рядків, створення FcA(Rs5, FcB(Rs4, FcC(Rs3, FcD(Rs2, FcA(FcB(FcC(FcD(Ev, Rs1))))))))
        for key in reversed(public_key_list):
            # Створюємо рандомний рядок
            random_string = generate_random_string()
            self.random_strings.append(random_string)
            # Додавання ASCII-кодів рандомного рядка до попереднього списку через роздільник |
            random_string_bytes = string_to_bytes(random_string)
            curr_ballot = prev_ballot + random_string_bytes
            # Шифрування бюлетеня з доданим рядком
            encrypted_ballot = encrypt_message(curr_ballot, key)
            prev_ballot = encrypted_ballot

        return prev_ballot

    def first_decryption(self, decrypted_ballots):
        """Розшифровуємо набір бюлетенів, перевіряємо чи присутній наш рядок, видаляємо всі рандомні рядки"""
        current_decrypted_ballots = []
        current_decrypted_strings = []
        for ballot in decrypted_ballots:
            # Розшифрування бюлетеня приватним ключем поточного виборця
            decrypted_ballot = decrypt_message(ballot, self.private_comm_key)

            # Зберігаємо рандомний рядок
            random_string = decrypted_ballot[-15:]
            current_decrypted_strings.append(random_string)

            # Видаляємо рандомний рядок з бюлетеня
            current_decrypted_ballots.append(decrypted_ballot[:-15])

        # Перевіряємо чи присутній рандомний рядок виборця
        is_valid = self.check_string(current_decrypted_strings)
        if not is_valid:
            raise ValueError("Хтось намагається нашкодити голосуванню")

        # Оновлюємо список розшифрованих бюлетенів
        return current_decrypted_ballots

    def second_decryption(self, decrypted_ballots, signatures, prev_voter_public_key, is_last):
        """Вдруге розшифровуємо набір бюлетенів, перевіряємо по підпису їх валідність, підписуємо і повертаємо назад"""

        current_decrypted_ballots = []
        current_signatures = []

        # Якщо не перший виборець
        if signatures:
            # Перевірка всіх попередніх підписів
            for idx, signature in enumerate(signatures):
                validation_list = []
                # Перевіряємо чи хоча б під один бюлетень підходить підпис(так бо всі бюлетені поперемішані)
                for ballot in decrypted_ballots:
                    is_valid = verify_signature(
                        ballot,
                        signature,
                        prev_voter_public_key
                    )
                    validation_list.append(is_valid)
                if not any(validation_list):
                    raise ValueError("Хтось намагається нашкодити голосуванню")

        for ballot in decrypted_ballots:
            # Розшифрування бюлетеня
            decrypted_ballot = decrypt_message(ballot, self.private_comm_key)

            # Останній виборець видаляє рандомний рядок
            if is_last:
                decrypted_ballot = decrypted_ballot[:-15]

            # Формування підпису
            signature = sign_message(decrypted_ballot, self.private_sign_key, self.public_sign_key)
            current_signatures.append(signature)

            # Додавання розшифрованих бюлетенів
            current_decrypted_ballots.append(decrypted_ballot)

        return current_decrypted_ballots, current_signatures






    def check_string(self, string_list):
        """Перевірка чи генерував виборець цю строку"""
        results = []

        for string in string_list:
            # Перетворюємо на рядок
            if isinstance(string, list):
                string = bytes_to_string(string)

            # Перевірка чи присутній рядок в збережених рандомних рядках
            if string in self.random_strings:
                self.random_strings.remove(string)
                results.append(True)
            else:
                results.append(False)
        return any(results)



