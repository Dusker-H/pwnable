import os

def filtering(user_input):
    blacklist = [';', '|', '&', 'cat', 'f', 'l', 'a', 'g', ' ', '`', '?', '*', 'sh', 'bash', 'zsh', 'tcsh']
    for word in blacklist:
        if word in user_input:
            print("Invalid input detected!")
            exit(0)

def main():
    print("Welcome to the command challenge!")
    cmd = input("Enter the ping: ")
    filtering(cmd)

    os.system(f"ping -c 1 {cmd}")

if __name__ == "__main__":
    main()