from Crypto.Cipher import DES, DES3, AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from PIL import Image
import os

def encrypt_data(data, key, mode):
    cipher = AES.new(key, mode)
    return cipher.encrypt(pad(data, AES.block_size))


def decrypt_data(data, key, mode):
    cipher = AES.new(key, mode)
    return cipher.decrypt(data)


def process_image(file_path, key, mode, encrypt=True):
    with Image.open(file_path) as im:
        data = im.tobytes()
        original_mode = im.mode
        original_size = im.size

    if encrypt:
        processed_data = encrypt_data(data, key, mode)

        new_file_path = file_path.split('.')[0] + '-encriptada.' + file_path.split('.')[1]
    else:
        processed_data = decrypt_data(data, key, mode)

        new_file_path = file_path.split('.')[0] + '-desencriptada.' + file_path.split('.')[1]

    with open(new_file_path, 'wb') as f:
        f.write(processed_data)

    return new_file_path

def process_messages():

    key_des = get_random_bytes(8)  
    cipher_des = DES.new(key_des, DES.MODE_ECB)
    message = b'Hola Mundo!'
    encrypted_message_des = cipher_des.encrypt(pad(message, DES.block_size))
    decrypted_message_des = unpad(cipher_des.decrypt(encrypted_message_des), DES.block_size)
    print("Mensaje cifrado con DES:", encrypted_message_des)
    print("Mensaje descifrado con DES:", decrypted_message_des)

    key_3des = get_random_bytes(24)  
    cipher_3des = DES3.new(key_3des, DES3.MODE_ECB)
    encrypted_message_3des = cipher_3des.encrypt(pad(message, DES3.block_size))
    decrypted_message_3des = unpad(cipher_3des.decrypt(encrypted_message_3des), DES3.block_size)
    print("Mensaje cifrado con DES3:", encrypted_message_3des)
    print("Mensaje descifrado con DES3:", decrypted_message_3des)


    key_aes = get_random_bytes(32)  
    cipher_aes = AES.new(key_aes, AES.MODE_ECB)
    message_aes = b'Hola Mundo!'
    encrypted_message_aes = cipher_aes.encrypt(pad(message_aes, AES.block_size))
    decrypted_message_aes = unpad(cipher_aes.decrypt(encrypted_message_aes), AES.block_size)
    print("Mensaje cifrado con AES:", encrypted_message_aes)
    print("Mensaje descifrado con AES:", decrypted_message_aes)
    
def main():

    key = os.urandom(16)

    mode = AES.MODE_CBC  

    process_messages()
    image_paths = ['foto1.jpeg', 'Logo-UVG.webp', 'tux.ppm']
    processed_paths = []


    for path in image_paths:
        encrypted_path = process_image(path, key, mode, encrypt=True)
        processed_paths.append(encrypted_path)

    return processed_paths


processed_image_paths = main()
print(processed_image_paths)
