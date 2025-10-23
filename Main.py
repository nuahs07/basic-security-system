import time

def login_system():
    username = "user"
    password = "pass"
    attempts = 0

    while attempts < 5:
        user = input("Enter Username: ")
        pwd = input("Enter Password: ")

        if user == username and pwd == password:
            print("Access Granted!")
            return
        else:
            attempts += 1
            print(f"Incorrect credentials. Attempts left: {5 - attempts}")

    print("Too many failed attempts. System locked for 10 seconds.")
    time.sleep(10)
    print("You may try again later.")

login_system()