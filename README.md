# Steganography Tool with Encryption

## Overview

This project is a **Steganography Tool** that allows users to securely embed and extract messages in/from images using both **steganography** and **encryption**. The tool encrypts a given message with a password and embeds it into an image file, making the message invisible to the naked eye while preserving the image’s visual integrity. The recipient can extract the hidden message using the correct password and decrypt it.

## Features

- **Message Embedding**: Securely embed a message into an image by altering the least significant bits of the image pixels.
- **Password Protection**: Messages are encrypted using a password, ensuring that only the person with the correct password can decrypt the message.
- **Decryption & Extraction**: Extract hidden messages from an image and decrypt them using the correct password.
- **Cross-platform**: Built using Python, this tool can run on different platforms (Windows, Mac, Linux).

## Requirements

- Python 3.x
- Required libraries:
  - `opencv-python` (for image processing)
  - `numpy` (for array manipulations)
  - `tkinter` (for GUI)
  - `cryptography` (for message encryption/decryption)
  - `hashlib` (for password hashing)

You can install the required libraries using the following:

```bash
pip install opencv-python numpy cryptography
```

## Installation

1. Clone this repository to your local machine:

```bash
git clone https://github.com/your-username/steganography-tool.git
cd steganography-tool
```

2. Install the required libraries using the command mentioned above.

3. Run the application:

```bash
python steganography_tool.py
```

## Usage

### Encrypt Message

1. Click on the "Encrypt Message" tab.
2. Upload the image you want to embed the message into by clicking the "Browse" button.
3. Enter the message you want to hide in the image.
4. Provide a password that will be used to encrypt the message.
5. Click on "Embed Message". The encrypted message will be embedded into the image, and a new image will be saved with the embedded message.

### Decrypt Message

1. Click on the "Decrypt Message" tab.
2. Upload the image containing the hidden message.
3. Enter the password used during encryption.
4. Click on "Extract Message". The hidden message will be extracted and decrypted.

## How It Works

- **Encryption**: The message is encrypted using the password and the **Fernet encryption** method from the `cryptography` library. This ensures that the message is secure and can only be decrypted using the same password.
- **Embedding**: The encrypted message is converted into binary and embedded into the least significant bit of each pixel in the image.
- **Decryption & Extraction**: The image is read, and the binary data hidden in the least significant bits of the pixels is extracted. The binary data is then converted back to a string and decrypted using the password.

## Technologies Used

- **Python**: Programming language used to build the application.
- **OpenCV**: Used for image processing and manipulation.
- **Cryptography**: For encrypting and decrypting messages.
- **Tkinter**: For creating the graphical user interface (GUI).

## Future Enhancements

- Support for embedding multiple messages in different images.
- Add malware detection features to monitor the image files and catch potential criminals.
- Improve UI/UX for a more user-friendly experience.
- Integrate the tool with cloud storage platforms for seamless sharing of encrypted images.

## Contributing

Contributions are welcome! If you'd like to contribute, feel free to fork the repository and submit a pull request. Please ensure that any changes made adhere to the project's coding style and include appropriate tests.
