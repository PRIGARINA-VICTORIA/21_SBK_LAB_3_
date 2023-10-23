import binascii
import os
from random import SystemRandom

W_RANGE = 10
Q_RANGE = 10
LAN_GE = 16


def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    g, y, x = egcd(b % a, a)
    return (g, x - (b // a) * y, y)


def mod_inverse(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('Приватный ключь не имеет обратного модуля')
    return x % m


def gen_keypair(pt_len):
    w = []
    s = 2
    for _ in range(0, pt_len):
        value = SystemRandom().randrange(s, s + W_RANGE)
        w.append(value)
        s += value

    q = SystemRandom().randrange(s, s + Q_RANGE)

    while True:
        r = SystemRandom().randrange(2, q)
        if egcd(r, q)[0] == 1:
            break
    private_key = (w, q, r)

    public_key = [(n * r) % q for n in w]
    return (public_key, private_key)


def encrypt(pt, public_key):
    return str(
        sum([(int(bin(int(binascii.hexlify(pt.encode()), 16))[2:].rjust(len(pt) * LAN_GE, "0")[i]) * public_key[i]) for
             i in
             range(0, len(public_key))]))


def decrypt(ct, private_key):
    s = (ct * mod_inverse(private_key[2], private_key[1])) % private_key[1]
    pt = ""
    for i in range(len(private_key[0]) - 1, -1, -1):  # перебираем w с конца
        if private_key[0][i] <= s:
            s -= private_key[0][i]
            pt += "1"
        else:
            pt += "0"
    return binascii.unhexlify(
        hex((int(pt[::-1], 2)))[2:].encode()).decode()


def main():
    pt = os.getenv("tmp_value")
    print(f'Текст для щифрации > {pt}\n')
    key = gen_keypair(len(pt) * LAN_GE)

    with open("publickey.txt", "w") as pub:
        for n in key[0]:
            pub.write(str(n) + "\n")
    with open("privatekey.txt", "w") as prv:
        prv.write("w:\n")
        for n in key[1][0]:
            prv.write(str(n) + "\n")
        prv.write("q:\n")
        prv.write(str(key[1][1]) + "\n")
        prv.write("r:\n")
        prv.write(str(key[1][2]) + "\n")
    public_key = key[0]

    ct = encrypt(pt, public_key)
    print("\nЗашифрованный текст > " + ct + "\n")

    values = []
    with open("privatekey.txt", "r") as prv:
        for line in prv:
            if "w:" in line or "q:" in line or "r:" in line:
                continue
            if int(line[:-1]) <= 0:
                raise Exception()
            values.append(int(line[:-1]))
    w = values[:-2]
    q = values[-2:-1][0]
    r = values[-1:][0]
    private_key = (w, q, r)
    pt = decrypt(int(ct), private_key)

    print("\nДекодированный текст > " + pt + "\n")


if __name__ == '__main__':
    main()
