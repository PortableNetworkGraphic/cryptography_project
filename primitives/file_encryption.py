from hashing import SHA2

def encrypt_file(file_path: str) -> None:
    initial_file = open(file_path, 'rb')
    encrypted_file = open(file_path+"_enc", 'wb')

    while chunk := initial_file.read(16):
        print(chunk)

encrypt_file("test.txt")
