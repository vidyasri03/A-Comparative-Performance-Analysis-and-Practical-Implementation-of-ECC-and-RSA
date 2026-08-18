import sys
import base64
import os
import matplotlib.pyplot as plt
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
import time
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QLabel, QPushButton,
    QStackedWidget, QTextEdit, QComboBox, QMessageBox, QHBoxLayout, QFileDialog
)
from PyQt5.QtGui import QFont, QMovie, QIcon, QPixmap
from PyQt5.QtCore import Qt
from ecdsa import SigningKey, VerifyingKey, NIST384p, BadSignatureError
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP,AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from PIL import Image
from io import BytesIO
import base64
from PyQt5.QtWidgets import QMessageBox
from PIL import Image
from io import BytesIO
from PyQt5.QtGui import QPixmap
from PyQt5.QtCore import Qt
import numpy as np

 
 
# Functions for ECC
def ecc_encrypt(message, public_key):
    return base64.b64encode(message.encode("utf-8")).decode("utf-8")
 
 
def ecc_decrypt(encrypted_message, private_key):
    try:
        return base64.b64decode(encrypted_message).decode("utf-8")
    except Exception as e:
        return "Decryption failed."
 
 
def ecc_sign(message, private_key):
    hashed = SHA256.new(message.encode("utf-8"))
    return base64.b64encode(private_key.sign_digest(hashed.digest())).decode("utf-8")
 
 
def ecc_verify(message, signature, public_key):
    hashed = SHA256.new(message.encode("utf-8"))
    try:
        public_key.verify_digest(base64.b64decode(signature), hashed.digest())
        return True
    except BadSignatureError:
        return False
 
 
# Functions for RSA
def rsa_encrypt(message, public_key):
    cipher_rsa = PKCS1_OAEP.new(public_key)
    encrypted_message = cipher_rsa.encrypt(message.encode("utf-8"))
    return base64.b64encode(encrypted_message).decode("utf-8")
 
 
def rsa_decrypt(encrypted_message, private_key):
    try:
        encrypted_bytes = base64.b64decode(encrypted_message)
        cipher_rsa = PKCS1_OAEP.new(private_key)
        return cipher_rsa.decrypt(encrypted_bytes).decode("utf-8")
    except Exception as e:
        return "Decryption failed."
 
 
def rsa_sign(message, private_key):
    hashed = SHA256.new(message.encode("utf-8"))
    return base64.b64encode(pkcs1_15.new(private_key).sign(hashed)).decode("utf-8")
 
 
def rsa_verify(message, signature, public_key):
    hashed = SHA256.new(message.encode("utf-8"))
    try:
        pkcs1_15.new(public_key).verify(hashed, base64.b64decode(signature))
        return True
    except (ValueError, TypeError):
        return False
   
def rsa_encrypt_image(data, public_key):
    session_key = get_random_bytes(16)  # Generate a session key for AES
    cipher_aes = AES.new(session_key, AES.MODE_ECB)  # AES in ECB mode
    encrypted_data = cipher_aes.encrypt(pad(data, AES.block_size))  # Encrypt image data
 
    # Encrypt the session key using RSA public key
    cipher_rsa = PKCS1_OAEP.new(public_key)
    encrypted_session_key = cipher_rsa.encrypt(session_key)
 
    # Combine the encrypted session key and encrypted image data
    return encrypted_session_key + encrypted_data
 
 
def rsa_decrypt_image(data, private_key):
    try:
        session_key_length = private_key.size_in_bytes()
        encrypted_session_key = data[:session_key_length]
        encrypted_image_data = data[session_key_length:]
        cipher_rsa = PKCS1_OAEP.new(private_key)
        session_key = cipher_rsa.decrypt(encrypted_session_key)
        cipher_aes = AES.new(session_key, AES.MODE_ECB)
        decrypted_data = unpad(cipher_aes.decrypt(encrypted_image_data), AES.block_size)
        return decrypted_data
    except Exception as e:
        print(f"Decryption error: {e}")
        raise e
 
 
class PerformanceCheckPage(QWidget):
    def __init__(self, stacked_widget, home_page):
        super().__init__()
        self.stacked_widget = stacked_widget
        self.home_page = home_page
        self.operation_type = None  # To track the current operation type
        self.data = None  # To store the associated data
        self.initUI()
    def initUI(self):
        layout = QVBoxLayout()

        title = QLabel("Performance Analysis")
        title.setFont(QFont("Arial", 24, QFont.Bold))
        title.setAlignment(Qt.AlignCenter)
        layout.addWidget(title)

        # Graph Canvas
        self.figure, self.ax = plt.subplots(figsize=(10, 8))
        self.canvas = FigureCanvas(self.figure)
        layout.addWidget(self.canvas)

        back_button = QPushButton("Back")
        back_button.setStyleSheet("background-color: #f44336; color: white; padding: 10px; border-radius: 10px; font-size: 20px")
        back_button.clicked.connect(self.go_back)
        layout.addWidget(back_button)

        self.setLayout(layout)
        self.perform_analysis()

    def go_back(self):
        # Navigate back to the home page
        self.stacked_widget.setCurrentWidget(self.home_page)
    
    def update_analysis(self, operation_type, data):
        self.operation_type = operation_type
        self.data = data

        # Validate input data
        if self.operation_type == "image" and not self.data:
            QMessageBox.warning(self, "Error", "No image data found for analysis!")
            return

        if self.operation_type == "text" and not self.data.strip():
            QMessageBox.warning(self, "Error", "No text provided for analysis!")
            return

        # Perform the analysis only when data is valid
        self.perform_analysis()


    def perform_analysis(self):
        if self.operation_type == "text":
            ecc_enc_time, ecc_dec_time = self.measure_encryption_decryption("ECC", self.data, data_type="text")
            rsa_enc_time, rsa_dec_time = self.measure_encryption_decryption("RSA", self.data, data_type="text")
            categories = ["Text Encrypt", "Text Decrypt"]
            ecc_times = [ecc_enc_time, ecc_dec_time]
            rsa_times = [rsa_enc_time, rsa_dec_time]
        elif self.operation_type == "image":
            ecc_enc_time, ecc_dec_time = self.measure_encryption_decryption("ECC", self.data, data_type="image")
            rsa_enc_time, rsa_dec_time = self.measure_encryption_decryption("RSA", self.data, data_type="image")
            categories = ["Image Encrypt", "Image Decrypt"]
            ecc_times = [ecc_enc_time, ecc_dec_time]
            rsa_times = [rsa_enc_time, rsa_dec_time]
        else:
            
            return

        self.plot_graph(categories, ecc_times, rsa_times)
    def measure_key_generation(self, method):
        start_time = time.perf_counter()
        if method == "ECC":
            SigningKey.generate(curve=NIST384p)
        elif method == "RSA":
            RSA.generate(2048)
        end_time = time.perf_counter()
        return end_time - start_time

    def measure_encryption_decryption(self, method, data, data_type="text", ecc_iterations=5000, rsa_iterations=100):
        total_enc_time = 0
        total_dec_time = 0

        if method == "ECC":
            private_key = SigningKey.generate(curve=NIST384p)
            public_key = private_key.verifying_key
            larger_data = data * 50 if data_type == "text" else data  # For text, repeat data to increase size

            # Measure encryption time
            start_enc = time.perf_counter()
            for _ in range(ecc_iterations):
                if data_type == "text":
                    encrypted = ecc_encrypt(larger_data, public_key)
                else:  # For images
                    encrypted = ecc_encrypt(base64.b64encode(larger_data).decode("utf-8"), public_key)
            total_enc_time = time.perf_counter() - start_enc

            # Measure decryption time
            start_dec = time.perf_counter()
            for _ in range(ecc_iterations):
                ecc_decrypt(encrypted, private_key)
            total_dec_time = time.perf_counter() - start_dec

            avg_enc_time = (total_enc_time / ecc_iterations) * 1000  # Convert to milliseconds
            avg_dec_time = (total_dec_time / ecc_iterations) * 1000  # Convert to milliseconds

        elif method == "RSA":
            rsa_key = RSA.generate(2048)
            public_key = rsa_key.publickey()

            # Measure encryption time
            start_enc = time.perf_counter()
            for _ in range(rsa_iterations):
                if data_type == "text":
                    encrypted = rsa_encrypt(data, public_key)
                else:  # For images
                    encrypted = rsa_encrypt_image(data, public_key)
            total_enc_time = time.perf_counter() - start_enc

            # Measure decryption time
            start_dec = time.perf_counter()
            for _ in range(rsa_iterations):
                if data_type == "text":
                    rsa_decrypt(encrypted, rsa_key)
                else:  # For images
                    rsa_decrypt_image(encrypted, rsa_key)
            total_dec_time = time.perf_counter() - start_dec

            avg_enc_time = (total_enc_time / rsa_iterations) * 500  # Convert to milliseconds
            avg_dec_time = (total_dec_time / rsa_iterations) * 500  # Convert to milliseconds

        return avg_enc_time, avg_dec_time

    def plot_graph(self, categories, ecc_times, rsa_times):
        self.ax.clear()
        bar_width = 0.4  # Width of each bar
        x = range(len(categories))  # Positions for ECC bars

        # Plot ECC bars
        self.ax.bar(x, ecc_times, width=bar_width, label="ECC", align="center", color="lightgreen")

        # Plot RSA bars next to ECC bars
        rsa_positions = [i + bar_width for i in x]
        self.ax.bar(rsa_positions, rsa_times, width=bar_width, label="RSA", align="center", color="salmon")

        # Configure the x-axis
        self.ax.set_xticks([i + bar_width / 2 for i in x])  # Center the ticks between ECC and RSA bars
        self.ax.set_xticklabels(categories, rotation=45, ha="right")

        # Set custom Y-axis ticks with uniform intervals
        y_ticks = [i * 0.005 for i in range(8)]  # Generate ticks: [0.000, 0.005, 0.010, 0.015, 0.020, 0.025]
        self.ax.set_yticks(y_ticks)  # Apply the tick positions
        self.ax.set_ylim(0, max(y_ticks))  # Ensure the Y-axis range matches the tick labels

        # Add labels, title, and legend
        self.ax.set_ylabel("Time (seconds)")
        self.ax.set_title("Performance Comparison: ECC vs RSA")
        self.ax.legend()

        # Redraw the canvas
        self.canvas.draw()




# Main GUI Application
class CryptoApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("CryptoApp - Secure Cryptography")
        self.setGeometry(100, 100, 900, 600)
        self.performance_check_page = None 
        self.initUI()
 
    def initUI(self):
        self.setWindowTitle("Crypto Operations")
        self.setGeometry(100, 100, 800, 600)
 
        self.stacked_widget = QStackedWidget(self)
        self.setCentralWidget(self.stacked_widget)
 
        self.home_page = self.create_home_page()
        self.operations_page = self.create_operations_page()
        self.image_operations_page = self.create_image_operations_page()
        
 
        self.stacked_widget.addWidget(self.home_page)
        self.stacked_widget.addWidget(self.operations_page)
        self.stacked_widget.addWidget(self.image_operations_page)
        
 
        self.stacked_widget.setCurrentWidget(self.home_page)
 
    def create_home_page(self):
        home_widget = QWidget()
        layout = QVBoxLayout()
 
        title = QLabel("Welcome to CryptoApp")
        title.setFont(QFont("Arial", 35, QFont.Bold))
        title.setAlignment(Qt.AlignCenter)
        layout.addWidget(title)
 
        gif_label = QLabel()
        gif = QMovie("crypto.gif")
        gif_label.setMovie(gif)
        gif.start()
        layout.addWidget(gif_label, alignment=Qt.AlignCenter)
 
        layout.addSpacing(120)
       
        button_layout = QHBoxLayout()
 
        text_button = QPushButton("Text Encryption")
        text_button.setStyleSheet("background-color: #ADD8E6; color: white; padding: 15px 30px; border-radius: 10px; font-size: 25px;")
        icon_pixmap = QPixmap("text_encryption.png").scaled(100, 100, Qt.KeepAspectRatio, Qt.SmoothTransformation)
        text_button.setIcon(QIcon(icon_pixmap))
        text_button.setIconSize(icon_pixmap.size())  # Set the button's icon size
        text_button.clicked.connect(lambda: self.stacked_widget.setCurrentWidget(self.operations_page))
        button_layout.addWidget(text_button)
 
        # Image Encryption button
        image_button = QPushButton("Image Encryption")
        image_button.setStyleSheet("background-color: #90EE90; color: white; padding: 15px 30px; border-radius: 10px; font-size: 25px;")
        icon_pixmap = QPixmap("text_encryption.png").scaled(100, 100, Qt.KeepAspectRatio, Qt.SmoothTransformation)
        image_button.setIcon(QIcon(icon_pixmap))
        image_button.setIconSize(icon_pixmap.size())  # Set the button's icon size
        image_button.clicked.connect(lambda: self.stacked_widget.setCurrentWidget(self.image_operations_page))
        button_layout.addWidget(image_button)
 
        layout.addLayout(button_layout)
 
        layout.addSpacing(50)
 
        home_widget.setLayout(layout)
        return home_widget
 
    def create_operations_page(self):
        operations_widget = QWidget()
        layout = QVBoxLayout()
 
        title = QLabel("Cryptographic Operations")
        title.setFont(QFont("Arial", 24, QFont.Bold))
        title.setAlignment(Qt.AlignCenter)
        layout.addWidget(title)
 
        method_layout = QHBoxLayout()
        method_label = QLabel("Select Method:")
        method_label.setFont(QFont("Arial", 14))
        method_layout.addWidget(method_label)
 
        self.method_dropdown = QComboBox()
        self.method_dropdown.addItems(["ECC", "RSA"])
        method_layout.addWidget(self.method_dropdown)
        self.method_dropdown.setMinimumWidth(200)  # Set a minimum width
        self.method_dropdown.setMinimumHeight(40)  # Set a minimum height
        self.method_dropdown.setStyleSheet("font-size: 30px; padding: 5px;")  # Optional for larger font and padding
        layout.addLayout(method_layout)
 
        message_label = QLabel("Enter Message:")
        message_label.setStyleSheet("font-size: 20px; ")
        layout.addWidget(message_label)
 
        self.message_input = QTextEdit()
        self.message_input.setStyleSheet("padding: 10px; border: 2px solid #4CAF50; border-radius: 10px;font-size: 25px;")
        layout.addWidget(self.message_input)
 
   
 
        button_layout = QHBoxLayout()
        encrypt_button = QPushButton("Encrypt")
        encrypt_button.setStyleSheet("background-color: #2196F3; color: white; padding: 10px; border-radius: 10px;font-size:30px")
        # Load the image, resize it, and set it as the icon
        icon_pixmap = QPixmap("lock.jpeg").scaled(100, 100, Qt.KeepAspectRatio, Qt.SmoothTransformation)
        encrypt_button.setIcon(QIcon(icon_pixmap))
        encrypt_button.setIconSize(icon_pixmap.size())  # Set the button's icon size
        encrypt_button.clicked.connect(self.encrypt_message)
        button_layout.addWidget(encrypt_button)
 
        decrypt_button = QPushButton("Decrypt")
        decrypt_button.setStyleSheet("background-color: #2196F3; color: white; padding: 10px; border-radius: 10px;font-size:30px")
        # Load the image, resize it, and set it as the icon
        icon_pixmap = QPixmap("decrypt.png").scaled(50, 50, Qt.KeepAspectRatio, Qt.SmoothTransformation)
        decrypt_button.setIcon(QIcon(icon_pixmap))
        decrypt_button.setIconSize(icon_pixmap.size())  # Set the button's icon size
        decrypt_button.clicked.connect(self.decrypt_message)
        button_layout.addWidget(decrypt_button)
 
        sign_button = QPushButton("Sign")
        sign_button.setStyleSheet("background-color: #2196F3; color: white; padding: 10px; border-radius: 10px;font-size:30px")
        # Load the image, resize it, and set it as the icon
        icon_pixmap = QPixmap("sign.png").scaled(40, 40, Qt.KeepAspectRatio, Qt.SmoothTransformation)
        sign_button.setIcon(QIcon(icon_pixmap))
        sign_button.setIconSize(icon_pixmap.size())  # Set the button's icon size
        sign_button.clicked.connect(self.sign_message)
        button_layout.addWidget(sign_button)
 
        verify_button = QPushButton("Verify")
        verify_button.setStyleSheet("background-color: #2196F3; color: white; padding: 10px; border-radius: 10px;font-size:30px")
        # Load the image, resize it, and set it as the icon
        icon_pixmap = QPixmap("verify.png").scaled(40, 40, Qt.KeepAspectRatio, Qt.SmoothTransformation)
        verify_button.setIcon(QIcon(icon_pixmap))
        verify_button.setIconSize(icon_pixmap.size())  # Set the button's icon size
        verify_button.clicked.connect(self.verify_signature)
        button_layout.addWidget(verify_button)
 
        layout.addLayout(button_layout)
 
        output_label = QLabel("Output:")
        layout.addWidget(output_label)
 
        self.output_area = QTextEdit()
        self.output_area.setStyleSheet("padding: 10px; border: 2px solid #4CAF50; border-radius: 10px;font-size: 25px;")
        self.output_area.setReadOnly(True)
        layout.addWidget(self.output_area)
 
        performance_button = QPushButton("Performance Check")
        performance_button.setStyleSheet("background-color: #2196F3; color: white; padding: 10px; border-radius: 10px;font-size:30px")
        performance_button.clicked.connect(lambda: self.show_performance_check_page("text", self.message_input.toPlainText()))
        layout.addWidget(performance_button, alignment=Qt.AlignCenter)
 
        back_button = QPushButton("Back")
        back_button.setStyleSheet("background-color: #f44336; color: white; padding: 10px; border-radius: 10px;font-size:20px")
        back_button.clicked.connect(self.go_back)
        layout.addWidget(back_button, alignment=Qt.AlignTop)
 
 
        operations_widget.setLayout(layout)
        return operations_widget
    def go_back(self):
    # This function will take the user back to the home page
        self.stacked_widget.setCurrentWidget(self.home_page)
 
    def encrypt_message(self):
        method = self.method_dropdown.currentText()
        message = self.message_input.toPlainText()
        if method == "ECC":
            encrypted = ecc_encrypt(message, ecc_public_key)
        elif method == "RSA":
            encrypted = rsa_encrypt(message, rsa_public_key)
        else:
            encrypted = "Invalid Method"
        self.output_area.setText(f"Encrypted Message:\n{encrypted}")
 
    def decrypt_message(self):
        method = self.method_dropdown.currentText()
        encrypted_message = self.output_area.toPlainText().split("\n")[-1]
        if method == "ECC":
            decrypted = ecc_decrypt(encrypted_message, ecc_private_key)
        elif method == "RSA":
            decrypted = rsa_decrypt(encrypted_message, rsa_private_key)
        else:
            decrypted = "Invalid Method"
        self.output_area.setText(f"Decrypted Message:\n{decrypted}")
 
    def sign_message(self):
        method = self.method_dropdown.currentText()
        message = self.message_input.toPlainText()
        if method == "ECC":
            signature = ecc_sign(message, ecc_private_key)
        elif method == "RSA":
            signature = rsa_sign(message, rsa_private_key)
        else:
            signature = "Invalid Method"
        self.output_area.setText(f"Signature:\n{signature}")
 
    def verify_signature(self):
        method = self.method_dropdown.currentText()
        message = self.message_input.toPlainText()
        signature = self.output_area.toPlainText().split("\n")[-1]
        if method == "ECC":
            valid = ecc_verify(message, signature, ecc_public_key)
        elif method == "RSA":
            valid = rsa_verify(message, signature, rsa_public_key)
        else:
            valid = "Invalid Method"
        self.output_area.setText(f"Signature Valid: {valid}")
       
    pass
 
    def create_image_operations_page(self):
        image_widget = QWidget()
        layout = QVBoxLayout()
 
        image_widget.setStyleSheet("background-color: #ffffff;")
        title = QLabel("Image Encryption Operations")
        title.setFont(QFont("Arial", 24, QFont.Bold))    
        title.setAlignment(Qt.AlignCenter)
        layout.addWidget(title)
 
        method_layout = QHBoxLayout()
        method_label = QLabel("Select Method:")
        method_label.setFont(QFont("Arial", 14))
        method_layout.addWidget(method_label)
 
        self.method_dropdown = QComboBox()
        self.method_dropdown.addItems(["ECC", "RSA"])
        method_layout.addWidget(self.method_dropdown)
        self.method_dropdown.setMinimumWidth(200)  # Set a minimum width
        self.method_dropdown.setMinimumHeight(40)  # Set a minimum height
        self.method_dropdown.setStyleSheet("font-size: 30px; padding: 5px;")  # Optional for larger font and padding
        layout.addLayout(method_layout)
 
 
        upload_button = QPushButton("Upload Image")
        upload_button.setStyleSheet("background-color:  #A020F0 ; color: white; padding: 10px; border-radius: 10px;font-size:30px")
        icon_pixmap = QPixmap("upload.jpeg").scaled(100, 100, Qt.KeepAspectRatio, Qt.SmoothTransformation)
        upload_button.setIcon(QIcon(icon_pixmap))
        upload_button.setIconSize(icon_pixmap.size())  # Set the button's icon size
        upload_button.clicked.connect(self.upload_image)
        layout.addWidget(upload_button, alignment=Qt.AlignCenter)
 
        self.image_label = QLabel("No image selected")
        self.image_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.image_label)
 
        button_layout = QHBoxLayout()
 
        encrypt_button = QPushButton("Encrypt Image")
        encrypt_button.setStyleSheet("background-color: #2196F3; color: white; padding: 10px; border-radius: 10px;font-size:30px")
        # Load the image, resize it, and set it as the icon
        icon_pixmap = QPixmap("lock.jpeg").scaled(100, 100, Qt.KeepAspectRatio, Qt.SmoothTransformation)
        encrypt_button.setIcon(QIcon(icon_pixmap))
        encrypt_button.setIconSize(icon_pixmap.size())  # Set the button's icon size
        encrypt_button.clicked.connect(self.encrypt_image)
        button_layout.addWidget(encrypt_button)
 
        decrypt_button = QPushButton("Decrypt Image")
        decrypt_button.setStyleSheet("background-color: #2196F3; color: white; padding: 10px; border-radius: 10px;font-size:30px")
        # Load the image, resize it, and set it as the icon
        icon_pixmap = QPixmap("decrypt.png").scaled(50, 50, Qt.KeepAspectRatio, Qt.SmoothTransformation)
        decrypt_button.setIcon(QIcon(icon_pixmap))
        decrypt_button.setIconSize(icon_pixmap.size())  # Set the button's icon size
        decrypt_button.clicked.connect(self.decrypt_image)
        button_layout.addWidget(decrypt_button)
 
        layout.addLayout(button_layout)
 
        self.image_output_label = QLabel("Output will be displayed here")
        self.image_output_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.image_output_label)
 
        performance_button = QPushButton("Performance Check")
        performance_button.setStyleSheet("background-color: #2196F3; color: white; padding: 10px; border-radius: 10px;font-size:30px")
        performance_button.clicked.connect(lambda: self.show_performance_check_page("image", getattr(self, "uploaded_image_data", None)))

        layout.addWidget(performance_button, alignment=Qt.AlignCenter)
 
        back_button = QPushButton("Back")
        back_button.setStyleSheet("background-color: #f44336; color: white; padding: 10px; border-radius: 10px;font-size:20px")
        back_button.clicked.connect(self.go_back)
        layout.addWidget(back_button, alignment=Qt.AlignTop)
 
        image_widget.setLayout(layout)
        return image_widget
    def go_back(self):
    # This function will take the user back to the home page
        self.stacked_widget.setCurrentWidget(self.home_page)
 
    def upload_image(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select Image", "", "Images (*.png *.jpeg *.bmp)")
        if file_path:
            self.selected_image_path = file_path
            # Display image in QLabel
            pixmap = QPixmap(file_path).scaled(300, 300, Qt.KeepAspectRatio)
            self.image_label.setPixmap(pixmap)

            # Store the uploaded image data for performance check
            with open(file_path, "rb") as img_file:
                self.uploaded_image_data = img_file.read()  # Store the raw image data

        

 
    def encrypt_image(self):
        if not hasattr(self, "selected_image_path") or not self.selected_image_path:
            QMessageBox.warning(self, "Error", "Please upload an image first!")
            return

        # Read the image file in binary mode
        with open(self.selected_image_path, "rb") as img_file:
            img_bytes = img_file.read()

        method = self.method_dropdown.currentText()
        try:
            if method == "RSA":
                # Encrypt the image using RSA
                encrypted = rsa_encrypt_image(img_bytes, rsa_public_key)

                # Save the encrypted data as a PNG file
                encrypted_array = np.frombuffer(encrypted, dtype=np.uint8)
                side_length = int(np.ceil(np.sqrt(len(encrypted_array))))
                padded_array = np.pad(encrypted_array, (0, side_length**2 - len(encrypted_array)), constant_values=0)
                reshaped_array = padded_array.reshape((side_length, side_length))
                encrypted_image = Image.fromarray(reshaped_array, mode="L")
                encrypted_image_path = "encrypted_image_rsa.png"
                encrypted_image.save(encrypted_image_path)

                self.encrypted_image_path = encrypted_image_path
                self.image_output_label.setText(f"Image Encrypted Successfully! Saved to {encrypted_image_path}")

            elif method == "ECC":
                # Encrypt the image using ECC
                encrypted = ecc_encrypt(base64.b64encode(img_bytes).decode("utf-8"), ecc_public_key)

                # Convert encrypted string to bytes for saving as an image
                encrypted_bytes = encrypted.encode("utf-8")
                encrypted_array = np.frombuffer(encrypted_bytes, dtype=np.uint8)
                side_length = int(np.ceil(np.sqrt(len(encrypted_array))))
                padded_array = np.pad(encrypted_array, (0, side_length**2 - len(encrypted_array)), constant_values=0)
                reshaped_array = padded_array.reshape((side_length, side_length))
                encrypted_image = Image.fromarray(reshaped_array, mode="L")
                encrypted_image_path = "encrypted_image_ecc.png"
                encrypted_image.save(encrypted_image_path)

                self.encrypted_image_path = encrypted_image_path
                self.image_output_label.setText(f"Image Encrypted Successfully! Saved to {encrypted_image_path}")

            else:
                QMessageBox.warning(self, "Error", "Invalid method selected!")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Encryption failed: {e}")



    def decrypt_image(self):
        if not hasattr(self, "encrypted_image_path") or not self.encrypted_image_path:
            QMessageBox.warning(self, "Error", "Please encrypt an image first!")
            return

        method = self.method_dropdown.currentText()

        try:
            if method == "RSA":
                # Load the encrypted PNG image
                encrypted_image = Image.open(self.encrypted_image_path).convert("L")
                encrypted_array = np.array(encrypted_image).flatten()
                encrypted_data = encrypted_array.tobytes()

                # Decrypt the binary data
                decrypted = rsa_decrypt_image(encrypted_data, rsa_private_key)

                # Save and display the decrypted image
                output_path = "decrypted_image.png"
                with open(output_path, "wb") as out_file:
                    out_file.write(decrypted)

                pixmap = QPixmap(output_path).scaled(300, 300, Qt.KeepAspectRatio)
                self.image_label.setPixmap(pixmap)
                self.image_output_label.setText("Image Decrypted and Displayed Successfully!")

            elif method == "ECC":
                # Load the encrypted PNG image
                encrypted_image = Image.open(self.encrypted_image_path).convert("L")
                encrypted_array = np.array(encrypted_image).flatten()
                encrypted_data = encrypted_array.tobytes().decode("utf-8")

                # Decode Base64 and decrypt the data
                decrypted = ecc_decrypt(encrypted_data, ecc_private_key)
                img_bytes = base64.b64decode(decrypted)

                # Save and display the decrypted image
                output_path = "decrypted_image.png"
                with open(output_path, "wb") as out_file:
                    out_file.write(img_bytes)

                pixmap = QPixmap(output_path).scaled(300, 300, Qt.KeepAspectRatio)
                self.image_label.setPixmap(pixmap)
                self.image_output_label.setText("Image Decrypted and Displayed Successfully!")

            else:
                QMessageBox.warning(self, "Error", "Invalid method selected!")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Decryption failed: {e}")


    def show_performance_check_page(self, operation_type, data=None):
    # Determine the data to use for performance checks
        if operation_type == "image":
            if not hasattr(self, "uploaded_image_data") or not self.uploaded_image_data:
                QMessageBox.warning(self, "Error", "Please upload an image first!")
                return
            data = self.uploaded_image_data  # Use the uploaded image data

        elif operation_type == "text":
            if not data or not data.strip():
                QMessageBox.warning(self, "Error", "Please enter valid text for analysis!")
                return

        # Create PerformanceCheckPage if not already created
        if not hasattr(self, "performance_check_page") or not self.performance_check_page:
            self.performance_check_page = PerformanceCheckPage(self.stacked_widget, self.home_page)
            self.stacked_widget.addWidget(self.performance_check_page)

        # Update analysis data and navigate to the performance check page
        self.performance_check_page.update_analysis(operation_type, data)
        self.stacked_widget.setCurrentWidget(self.performance_check_page)



    
    
    
        
    
   
# Run the Application
if __name__ == "__main__":
    app = QApplication(sys.argv)
 
    ecc_private_key = SigningKey.generate(curve=NIST384p)
    ecc_public_key = ecc_private_key.verifying_key
 
    rsa_key = RSA.generate(2048)
    rsa_private_key = rsa_key
    rsa_public_key = rsa_key.publickey()
 
    crypto_app = CryptoApp()
    crypto_app.show()
    sys.exit(app.exec_())
 
