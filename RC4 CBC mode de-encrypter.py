from PyQt4.QtCore import *
from PyQt4.QtGui import *
import sys
import time

class RC4_CBC():
    def encRC4_CBC(self, text, bytes, key):
        text_in_bytes = self.plain_to_bytes(text)
        key_stream = self.getKSA(key, bytes)
        key_stream = self.getPRGA(key_stream, len(text), bytes)
        encrypted_text = self.text_in_bytes_XOR_keystream(text_in_bytes, key_stream)
        encrypted_text = self.bytes_to_HEX(encrypted_text)
        encrypted_text = encrypted_text.toUpper()
        return encrypted_text 
    
    def decRC4_CBC(self, text, bytes, key):
        text_in_bytes = self.HEX_to_bytes(str(text))
        key_stream = self.getKSA(key, bytes)
        key_stream = self.getPRGA(key_stream, len(text_in_bytes), bytes)
        encrypted_text = self.text_in_bytes_XOR_keystream(text_in_bytes, key_stream)
        encrypted_text = self.bytes_to_plain(encrypted_text)
        return encrypted_text
    
    def getKSA(self, key, bytes):
        j = 0
        KSA_list = [i for i in range(bytes)]
        for i in range(bytes):
            j = (j + KSA_list[i] + ord(key[i % len(str(key))])) % bytes
            swap = KSA_list[i]
            KSA_list[i] = KSA_list[j]
            KSA_list[j] = swap
        return KSA_list
    
    def getPRGA(self, key_stream, size, bytes):
        i = 0
        j = 0
        prga = []
        for i in range(size):
            i = (i + 1) % bytes
            j = (j + key_stream[i]) % bytes
            swap = key_stream[i]
            key_stream[i] = key_stream[j]
            key_stream[j] = swap
            prga.append(key_stream[(key_stream[i] + key_stream[j]) % bytes])
        return prga
    
    def text_in_bytes_XOR_keystream(self, text_in_bytes, key_stream):
        encrypted_text = []
        for i in range(len(text_in_bytes)):
            encrypted_text.append(text_in_bytes[i] ^ key_stream[i])
        return encrypted_text
        
    def bytes_to_HEX(self, bytes):
        hex_tektas = ""
        for byte in bytes:
            hex_tektas += QString("%1").arg(byte, 0, 16)
            hex_tektas += " "
        return hex_tektas
    
    def HEX_to_bytes(self, HEX_text):
        text_in_bytes = []
        HEX_text = HEX_text.strip()
        HEX_text = HEX_text.split(" ")
        for hexaD in HEX_text:
            hexaD = QString(hexaD)
            hexaD = hexaD.toInt(16)
            text_in_bytes.append(hexaD[0])
        return text_in_bytes
    
    def plain_to_bytes(self, text):
        bytes = []
        for char in text:
            bytes.append(ord(char))
        return bytes
    
    def bytes_to_plain(self, bytes):
        plain = ""
        for byte in bytes:
            plain += chr(byte)
        return plain
    
class MainWindow(QWidget):
    def __init__(self, win_parrent = None):
        super(MainWindow, self).__init__()
        self.GUI()
        self.connect(self.open_file_PushButton, SIGNAL('clicked()'), self.open_file)
        self.connect(self.encrypt_PushButton, SIGNAL('clicked()'), self.encrypt_text)
        self.connect(self.dencrypt_PushButton, SIGNAL('clicked()'), self.decrypt_text)
        self.connect(self.quit_PushButton, SIGNAL('clicked()'), self.quit)

    def open_file(self):
        file_name = QFileDialog.getOpenFileName(self, 'Open File', '.')
        self.file_name_Label.setText(file_name)
        f_open = open(file_name) 
        text = f_open.read()
        self.encrypt_text_plain_PlainTextEdit.setPlainText(text)
        f_open.close()
    
    def encrypt_text(self):
        bits = self.encrypt_bits_LineEdit.displayText()
        text = self.encrypt_text_plain_PlainTextEdit.toPlainText()
        key = self.encrypt_key_LineEdit.displayText()
        if text == "" or bits == "" or int(bits) > 256 or int(bits) < 1 or key == "":
            self.error()
        else:
            rc4 = RC4_CBC()
            start_time = time.time()
            encrypted_text = rc4.encRC4_CBC(str(text), int(bits), str(key))
            elapsed_time = time.time() - start_time
            self.encrypt_time_seconds_Label.setText("%.3f" % elapsed_time)
            self.encrypt_text_crypt_PlainTextEdit.setPlainText(str(encrypted_text))
            
            
    def decrypt_text(self):
        bits = self.dencrypt_bits_LineEdit.displayText()
        text = self.dencrypt_text_plain_PlainTextEdit.toPlainText()
        key = self.dencrypt_key_LineEdit.displayText()
        if text == "" or bits == "" or int(bits) > 256 or int(bits) < 1 or key == "":
            self.error()
        else:
            rc4 = RC4_CBC()
            start_time = time.time()
            dencrypted_text = rc4.decRC4_CBC(str(text), int(bits), str(key))
            elapsed_time = time.time() - start_time
            self.dencrypt_time_seconds_Label.setText("%.3f" % elapsed_time)
            self.dencrypt_text_crypt_PlainTextEdit.setPlainText(str(dencrypted_text))
            
    def error(self):
            QMessageBox.critical(self, "Error", "Something has gone terribly terribly wrong! :(")
    
    def quit(self):
        sys.exit()
        
    def GUI(self):
        self.open_file_PushButton = QPushButton("Open File")
        self.open_file_PushButton.setFixedWidth(120)
        self.file_name_Label = QLabel("(File Name)")
        
        self.encrypt_PushButton = QPushButton("Encrypt")
        self.encrypt_key_Label = QLabel("Key: ")
        self.encrypt_key_LineEdit = QLineEdit()
        self.encrypt_bits_Label = QLabel("Bits: ")
        self.encrypt_bits_LineEdit = QLineEdit()
        self.encrypt_time_Label = QLabel("Encryption time: ")
        self.encrypt_time_seconds_Label = QLabel("(sec)")
        self.encrypt_text_plain_PlainTextEdit = QPlainTextEdit()
        self.encrypt_text_crypt_PlainTextEdit = QPlainTextEdit()
        self.encrypt_text_crypt_PlainTextEdit.setReadOnly(True)
        
        self.dencrypt_PushButton = QPushButton("Decrypt")
        self.dencrypt_key_Label = QLabel("Key: ")
        self.dencrypt_key_LineEdit = QLineEdit()
        self.dencrypt_bits_Label = QLabel("Bits: ")
        self.dencrypt_bits_LineEdit = QLineEdit()
        self.dencrypt_time_Label = QLabel("Decryption time: ")
        self.dencrypt_time_seconds_Label = QLabel("(sec)")
        self.dencrypt_text_plain_PlainTextEdit = QPlainTextEdit()
        self.dencrypt_text_crypt_PlainTextEdit = QPlainTextEdit()
        self.dencrypt_text_crypt_PlainTextEdit.setReadOnly(True)
        
        self.quit_PushButton =  QPushButton("Quit")    
        
        open_file_grid = QGridLayout()
        open_file_grid.addWidget(self.open_file_PushButton, 1, 0)
        open_file_grid.addWidget(self.file_name_Label, 1, 1)
        
        encrypt_options_GridLayout = QGridLayout()
        encrypt_options_GridLayout.addWidget(self.encrypt_PushButton, 1, 0)
        encrypt_options_GridLayout.addWidget(self.encrypt_key_Label, 1, 1)
        encrypt_options_GridLayout.addWidget(self.encrypt_key_LineEdit, 1, 2)
        encrypt_options_GridLayout.addWidget(self.encrypt_bits_Label, 1, 3)
        encrypt_options_GridLayout.addWidget(self.encrypt_bits_LineEdit, 1, 4)
        encrypt_options_GridLayout.addWidget(self.encrypt_time_Label, 1, 5)
        encrypt_options_GridLayout.addWidget(self.encrypt_time_seconds_Label, 1, 6)

        ecrypt_text_GridLayout = QGridLayout()
        ecrypt_text_GridLayout.addWidget(self.encrypt_text_plain_PlainTextEdit, 1, 0)
        ecrypt_text_GridLayout.addWidget(self.encrypt_text_crypt_PlainTextEdit, 1, 1)
        
        decrypt_options_GridLayout = QGridLayout()
        decrypt_options_GridLayout.addWidget(self.dencrypt_PushButton, 1, 0)
        decrypt_options_GridLayout.addWidget(self.dencrypt_key_Label, 1, 1)
        decrypt_options_GridLayout.addWidget(self.dencrypt_key_LineEdit, 1, 2)
        decrypt_options_GridLayout.addWidget(self.dencrypt_bits_Label, 1, 3)
        decrypt_options_GridLayout.addWidget(self.dencrypt_bits_LineEdit, 1, 4)
        decrypt_options_GridLayout.addWidget(self.dencrypt_time_Label, 1, 5)
        decrypt_options_GridLayout.addWidget(self.dencrypt_time_seconds_Label, 1, 6)

        decrypt_text_GridLayout = QGridLayout()
        decrypt_text_GridLayout.addWidget(self.dencrypt_text_plain_PlainTextEdit, 1, 0)
        decrypt_text_GridLayout.addWidget(self.dencrypt_text_crypt_PlainTextEdit, 1, 1)
        
        self.vbox = QVBoxLayout()
        self.vbox.addLayout(open_file_grid)
        self.vbox.addLayout(encrypt_options_GridLayout)
        self.vbox.addLayout(ecrypt_text_GridLayout)
        self.vbox.addLayout(decrypt_options_GridLayout)
        self.vbox.addLayout(decrypt_text_GridLayout)
        self.vbox.addWidget(self.quit_PushButton)
        
        self.setLayout(self.vbox)
        self.setWindowTitle("RC4 CBC mode de-encrypter")
        self.setFixedSize(900, 700)    

if __name__ == "__main__":
    prog  = QApplication(sys.argv)
    main_window = MainWindow()
    main_window.show()
    sys.exit(prog.exec_())