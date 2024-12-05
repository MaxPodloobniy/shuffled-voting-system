from voter import Voter
from encryption_decryption import *
from signing_checking import *
import matplotlib.pyplot as plt
from collections import Counter


def main():
    # Створення пар ключів комунікації для кожного виборця
    # Апелювати до того що єдина можливість створити чотири різні пари ключів для виборців при цьому, щоб n було однаковим
    # майже неможливо, а n повинне бути однаковим про при різних n в різних виборців при шифруванні/дешифруванні втрачається
    # частина даних, в будь-якому разі хоч роби ключі дуже великими зоч дуже малими хоч якими хоч
    keys_list = test_forth_encryption_with_validation()

    # Створення об'єктів виборця
    voters = [
        Voter("A", keys_list['first_keys'], "Вибір 1"),
        Voter("B", keys_list['second_keys'], "Вибір 2"),
        Voter("C", keys_list['third_keys'], "Вибір 2"),
        Voter("D", keys_list['forth_keys'], "Вибір 2"),
    ]

    # ------------------------ Шифрування бюлетенів ------------------------
    #  FcA(Rs5, FcB(Rs4, FcC(Rs3, FcD(Rs2, FcA(FcB(FcC(FcD(Ev, Rs1))))))))
    public_keys_list = [keys['public_key'] for keys in keys_list.values()]
    encrypted_ballots = []
    for voter in voters:
        full_encrypted_ballot = voter.create_ballot(public_keys_list)
        encrypted_ballots.append(full_encrypted_ballot)

    # ------------------------ Перше розшифрування бюлетенів ------------------------
    # Тепер послідовно розшифровуємо і видаляємо рандомні рядки, отримаємо FcA(FcB(FcC(FcD(Ev, Rs1))))
    decrypted_ballots = encrypted_ballots

    # Кожен виборець по порядку розшифровує бюлетені й проводить перевірки
    for voter in voters:
        decrypted_ballots = voter.first_decryption(decrypted_ballots)
        random.shuffle(decrypted_ballots)

    # ------------------------ Друге розшифрування бюлетенів ------------------------
    # Тепер послідовно розшифруємо бюлетені й сгенеруємо підписи
    signatures = []

    for voter_idx, voter in enumerate(voters):
        # Кожен виборець розшифровує всі бюлетені, перевіряє підписи і
        current_decrypted_ballots, current_signatures = voter.second_decryption(
            decrypted_ballots,
            signatures,
            voters[voter_idx - 1].public_sign_key,
            voter == voters[-1]
        )

        # Оновлення бюлетенів і підписів
        decrypted_ballots = current_decrypted_ballots
        random.shuffle(decrypted_ballots)
        signatures = current_signatures

    # ------------------------ Підведення підсумків виборів ------------------------
    results = []
    for ballot in decrypted_ballots:
        choice = ''.join(chr(byte) for byte in ballot)
        results.append(choice)

    print(results)

    # Підрахунок голосів
    vote_counts = Counter(results)

    # Підготовка даних для графіку
    choices = list(vote_counts.keys())
    vote_numbers = list(vote_counts.values())

    # Створення графіку
    plt.figure(figsize=(10, 6))
    bars = plt.bar(choices, vote_numbers, color='skyblue', edgecolor='navy')

    # Додавання підписів на стовпчики
    for bar in bars:
        height = bar.get_height()
        plt.text(
            bar.get_x() + bar.get_width() / 2., height,
            f'{height}',
            ha='center', va='bottom')

    # Налаштування графіку
    plt.title('Результати голосування', fontsize=15)
    plt.xlabel('Варіанти', fontsize=12)
    plt.ylabel('Кількість голосів', fontsize=12)
    plt.tight_layout()

    # Показ графіку
    plt.show()


if __name__ == "__main__":
    main()
