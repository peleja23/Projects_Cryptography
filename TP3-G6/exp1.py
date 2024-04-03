import random
import hashlib
import time

# List of the most used passwords
common_passwords = [
    "123456", "admin", "password", "123456789", "qwerty", "12345",
    "1234", "123", "Aa123456", "1234567890", "UNKNOWN", "1234567",
    "123123", "111111", "Password", "12345678910", "000000", "admin123",
    "********", "user", "1111", "P@ssw0rd", "root", "654321", "qwerty",
    "Pass@123", "******", "112233", "102030", "ubnt", "abc123", "Aa@123456",
    "abcd1234", "1q2w3e4r", "123321", "err", "qwertyuiop", "87654321",
    "987654321", "Eliska81", "123123123", "11223344", "987654321", "demo",
    "12341234", "qwerty123", "Admin@123", "1q2w3e4r5t", "11111111", "pass",
    "Demo@123", "**********", "azerty", "admintelecom", "Admin", "123meklozed",
    "666666", "123456789", "121212", "1234qwer", "admin@123", "*************",
    "123456789a", "Aa112233", "asdfghjkl", "Password1", "888888", "admin1",
    "test", "Aa123456@", "asd123", "qwer1234", "123qwe", "202020", "asdf1234",
    "Abcd@1234", "banned", "12344321", "aa123456", "1122334455", "Abcd1234",
    "guest", "88888888", "Admin123", "secret", "1122", "admin1234",
    "administrator", "Password@123", "q1w2e3r4", "10203040", "a123456",
    "12345678a", "555555", "zxcvbnm", "welcome", "Abcd@123", "Welcome@123",
    "minecraft", "101010", "Pass@1234", "123654", "123456a", "India@123",
    "Ar123455", "159357", "qwe123", "54321", "password1", "1029384756",
    "1234567891", "vodafone", "jimjim30", "Cindylee1", "1111111111", "azertyuiop",
    "999999", "adminHW", "10203", "gvt12345", "12121212", "12345678901", "222222",
    "7777777", "12345678900", "Kumar@123", "147258", "qwerty12345", "asdasd",
    "abc12345", "bismillah", "Heslo1234", "1111111", "a123456789", "iloveyou",
    "Passw0rd", "aaaaaa", "Flores123", "12qwaszx", "Welcome1", "password123",
    "123mudar", "123456aA@", "123qweasd", "868689849", "1234554321", "motorola",
    "q1w2e3r4t5", "1234512345", "undefined", "1q2w3e", "a1b2c3d4", "admin123456",
    "2402301978", "Qwerty123", "1qazxsw2", "test123", "Adam2312", "Password123",
    "1234567899", "Aa195043", "Test@123", "111111111", "admin12345", "zaq12wsx",
    "adminadmin", "ADMIN", "1234abcd", "Menara", "qwerty1234", "123abc",
    "theworldinyourhand", "123456a@", "Aa102030", "987654", "Mm123456",
    "p@ssw0rd", "Abc@1234", "131313", "1a2b3c4d", "123654789", "changeme",
    "12345679", "student", "senha123", "1234567a", "user1234", "abc123456",
    "master", "12345qwert", "1234561", "adminisp", "azerty123", "pakistan",
    "aaaaaaaa", "a1234567", "P@55w0rd", "P@$$w0rd", "qwerty123456"
]
# Calculate hash 
def hash_data(data):
    sha256 = hashlib.sha256()
    sha256.update(data.encode("utf-8"))
    return sha256.hexdigest()

# Get one random password from the list
def generate_common_password():
    return random.choice(common_passwords)

def main():
    # Start time function
    start_time = time.time()
    hash_og = '96cae35ce8a9b0244178bf28e4966c2ce1b8385723a96a6b838858cdd6ca0a1e'
    while True:
        generated_password = generate_common_password()
        pass_hash = hash_data(generated_password)
        # Compare the calculate hash from the random password with the original hash
        if(pass_hash == hash_og):
            print('Password found:',generated_password)
            # End time function
            end_time = time.time()
            # Calculate the total time
            elapsed_time = end_time - start_time
            print ('It took about',elapsed_time, 'seconds')
            break

if __name__ == "__main__":
    main()