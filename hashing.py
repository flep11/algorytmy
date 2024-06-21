import bcrypt
import hashlib

def hash_with_bcrypt(password):
    # Hashowanie hasła przy użyciu B-Crypt
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    return hashed

def verify_with_bcrypt(password, hashed):
    # Weryfikacja hasła przy użyciu B-Crypt
    return bcrypt.checkpw(password.encode(), hashed)

def hash_with_sha256(password):
    # Hashowanie hasła przy użyciu SHA-256
    hashed = hashlib.sha256(password.encode()).hexdigest()
    return hashed

def verify_with_sha256(password, hashed):
    # Weryfikacja hasła przy użyciu SHA-256
    return hash_with_sha256(password) == hashed

def main():
    # Wprowadzenie hasła przez użytkownika
    password = input("Wprowadź hasło, które zostanie zapamiętane: ")

    # Hashowanie przy użyciu B-Crypt
    bcrypt_hashed = hash_with_bcrypt(password)
    print(f"Hasło zostało zapamiętane (B-Crypt): {bcrypt_hashed}")

    # Hashowanie przy użyciu SHA-256
    sha256_hashed = hash_with_sha256(password)
    print(f"Hasło zostało zapamiętane (SHA-256): {sha256_hashed}")

    # Czyszczenie zmiennej password
    password = ""

    # Sprawdzanie hasła
    password_check = input("Wprowadź hasło ponownie do sprawdzenia: ")

    # Weryfikacja hasła przy użyciu B-Crypt
    is_verified_bcrypt = verify_with_bcrypt(password_check, bcrypt_hashed)
    if is_verified_bcrypt:
        print("Hasło poprawne (B-Crypt)")
    else:
        print("Hasło błędne (B-Crypt)")

    # Weryfikacja hasła przy użyciu SHA-256
    is_verified_sha256 = verify_with_sha256(password_check, sha256_hashed)
    if is_verified_sha256:
        print("Hasło poprawne (SHA-256)")
    else:
        print("Hasło błędne (SHA-256)")

    # Czyszczenie zmiennej password_check
    password_check = ""

if __name__ == "__main__":
    main()
