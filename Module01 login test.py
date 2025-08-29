"""
Module01 login test.py
by Paul Renaud
8/29/2025
for SDEV 245 Secure Coding

This program uses a simple login with hard-coded name and password to send an admin or a user
to two different places, based on their roles. You may also enter q to quit at the username prompt.

One login/password is admin/admin.
The other is user/password.

I know, I know. Very poor password choices. But this is just an example.

This code demonstrates one part of the CIA Triad - Confidentiality. It first does some authentication, and then
limits what each person can do based on their roles, which is what each is authorized to do.

The user account can only see options to read something, change their username, or change their password.
The admin account can list all the writings (to add/modify/delete) or list all the users (to add/modify/delete).
As this program is just an exercise, most of the options do not actually do anything.

Curiously, the user account actually has a bit more they can do, because they can read something, while the
admin can only see a list of usernames.
"""

import getpass   # for masking password entry

# init user array, which will be a list of dictionary entries, one per user.
all_users = []

# add some sample users. id is hidden. id and username should be unique.
all_users.append({"id": 0, "username": "admin", "password": "admin",    "role": "admin"})
all_users.append({"id": 1, "username": "user",  "password": "password", "role": "user"})

# define what roles are allowed to do. Just a list separated by commas.
# For this assignment this is too fine-grained a control. Just two endpoints is all that's needed.
allow = {}
allow["user"] = "read, change_my_username, change_my_password"
allow["admin"] = allow["user"] + ", write, list_users, add_user, delete_user, change_other_username, change_other_password"
# note the admin role inherits user permissions and adds to it. But this is customizable, clunky, and prone to typos.

# login loop. Should probably put this into a function.
found = False
while not found:
    entered_user = input("Enter username (Q to quit):")
    if entered_user.upper() == "Q": exit()
    entered_password = getpass.getpass()   # hides password entry. Prompt is "Password:" by default.

    # check for valid name/password
    for user in all_users:
        if entered_user == user["username"] and entered_password == user["password"]:
            found = True
            id = user["id"]
            username = user["username"]
            role = user["role"]
    if found:
        print("Logged in.")
    else:
        print("Name or password incorrect.")

print()
print("Welcome " + username + ".")
print("Your role is:", role)
print("Here is what you can do:")

def allowed_options():
# checks role to see if each option should be allowed. Unused in this simple program.
    if True:                                   print("0 - Quit")
    if "read" in allow[role]:                  print("1 - Read things")
    if "change_my_username" in allow[role]:    print("2 - Change my username")
    if "change_my_password" in allow[role]:    print("3 - Change my password")
    if "write" in allow[role]:                 print("4 - Write something")
    if "list_users" in allow[role]:            print("5 - List users")
    if "add_user" in allow[role]:              print("6 - Add user")
    if "delete_user" in allow[role]:           print("7 - Delete user")
    if "change_other_username" in allow[role]: print("8 - Change other username")
    if "change_other_password" in allow[role]: print("9 - Change other password")


def show_limerick():
# user-only function.
    print("* Read something *")
    print()
    print("There once was a man from Peru")
    print("Who dreamed he was eating his shoe")
    print("   He awoke in a fright")
    print("   In the middle of the night")
    print("And found it was perfectly true")
    print()
    wait = input("(Press Enter to return to menu)")
    return

def change_my_username():
# user-only function. Incomplete.
    print("* Change my username (unfinished)*")
    print()
    return

def change_my_password():
# user-only function. Incomplete.
    print("* Change my password (unfinished)*")
    print()
    return

def user_options():
# user-only menu, calls the above functions
    while True:
        print("0 - Quit")
        print("1 - Read something")
        print("2 - Change my username")
        print("3 - Change my password")
        choice = input("Pick an option:")
        if choice == "0":
            print("Quit")
            break
        if choice == "1": show_limerick()
        if choice == "2": change_my_username()
        if choice == "3": change_my_password()
    return

def list_writings():
# admin-only function. Incomplete.
    print("* List writings (unfinished)*")
    print("(all posts will be listed here)")
    print("0 - Return to main menu")
    print("1 - Add post")
    print("2 - Edit post")
    print("3 - Delete a post")
    wait = input("(Press Enter to return to menu)")
    return
    
def list_users():
# admin-only function. Incomplete.
    print("* List users (unfinished)*")
    print()
    print("username", "*", "role")
    for user in all_users:
        print(user["username"], "*", user["role"])
    print("0 - Return to main menu")
    print("1 - Add user")
    print("2 - Edit user")
    print("3 - Delete user")
    wait = input("(Press Enter to return to menu)")
    return

def admin_options():
# admin-only main menu. Calls above functions.
    while True:
        print("0 - Quit")
        print("1 - List all writings and modify")
        print("2 - List all users and modify")
        choice = input("Pick an option:")
        if choice == "0":
            print("Quit")
            break
        if choice == "1": list_writings()
        if choice == "2": list_users()
    return
    

# check current role, and send to appropriate menu selections.
# if roles doesn't match either (somehow) the program just quits.
if role == "user":
    user_options()
elif role == "admin":
    admin_options()
