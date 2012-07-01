from PyQt4.QtCore import *
from PyQt4.QtGui import *
import sys
import time

class RC4_CBC():
    def encRC4_CBC(self, tekstas, baitai, raktas):
        tekstas_baitais = self.plain_to_baitai(tekstas)
        key_stream = self.getKSA(raktas, baitai)
        key_stream = self.getPRGA(key_stream, len(tekstas), baitai)
        uzkuoduotas_tekstas = self.tekstas_baitais_XOR_keystream(tekstas_baitais, key_stream)
        uzkuoduotas_tekstas = self.baitai_to_hex(uzkuoduotas_tekstas)
        uzkuoduotas_tekstas = uzkuoduotas_tekstas.toUpper()
        return uzkuoduotas_tekstas
    
    def decRC4_CBC(self, tekstas, baitai, raktas):
        tekstas_baitais = self.hex_to_baitai(str(tekstas))
        key_stream = self.getKSA(raktas, baitai)
        key_stream = self.getPRGA(key_stream, len(tekstas_baitais), baitai)
        dekuoduotas_tekstas = self.tekstas_baitais_XOR_keystream(tekstas_baitais, key_stream)
        dekuoduotas_tekstas = self.baitai_to_plain(dekuoduotas_tekstas)
        return dekuoduotas_tekstas
    
    def getKSA(self, raktas, baitais):
        j = 0
        KSA_list = [i for i in range(baitais)]
        for i in range(baitais):
            j = (j + KSA_list[i] + ord(raktas[i % len(str(raktas))])) % baitais
            swap = KSA_list[i]
            KSA_list[i] = KSA_list[j]
            KSA_list[j] = swap
        return KSA_list
    
    def getPRGA(self, keyStream, size, baitai):
        i = 0
        j = 0
        prga = []
        for i in range(size):
            i = (i + 1) % baitai
            j = (j + keyStream[i]) % baitai
            swap = keyStream[i]
            keyStream[i] = keyStream[j]
            keyStream[j] = swap
            prga.append(keyStream[(keyStream[i] + keyStream[j]) % baitai])
        return prga
    
    def tekstas_baitais_XOR_keystream(self, tekstas_baitais, key_stream):
        uzkuoduotas_tekstas = []
        for i in range(len(tekstas_baitais)):
            uzkuoduotas_tekstas.append(tekstas_baitais[i] ^ key_stream[i])
        return uzkuoduotas_tekstas
        
    def baitai_to_hex(self, baitai):
        hex_tektas = ""
        for byte in baitai:
            hex_tektas += QString("%1").arg(byte, 0, 16)
            hex_tektas += " "
        return hex_tektas
    
    def hex_to_baitai(self, hex_tekstas):
        tekstas_baitai = []
        hex_tekstas = hex_tekstas.strip()
        hex_tekstas = hex_tekstas.split(" ")
        for hexaD in hex_tekstas:
            hexaD = QString(hexaD)
            hexaD = hexaD.toInt(16)
            tekstas_baitai.append(hexaD[0])
        return tekstas_baitai
    
    def plain_to_baitai(self, tekstas):
        baitai = []
        for char in tekstas:
            baitai.append(ord(char))
        return baitai
    
    def baitai_to_plain(self, baitai):
        plain = ""
        for baitas in baitai:
            plain += chr(baitas)
        return plain
    
class lab3(QWidget):
    def __init__(self, win_parrent = None):
        super(lab3, self).__init__()
        self.GUI()
        self.connect(self.atidaryti_teksta, SIGNAL('clicked()'), self.atidaryti_faila)
        self.connect(self.uzk_uzkuoduoti_PushButton, SIGNAL('clicked()'), self.uzkuoduoti_teksta)
        self.connect(self.dek_uzkuoduoti_PushButton, SIGNAL('clicked()'), self.dekuoduoti_teksta)
        self.connect(self.baigti_PushButton, SIGNAL('clicked()'), self.baigti_darba)

    def atidaryti_faila(self):
        failo_pav = QFileDialog.getOpenFileName(self, 'Open File', '.')
        self.failo_pavadinimas_Label.setText(failo_pav)
        f_atidaryti = open(failo_pav) 
        tekstas = f_atidaryti.read()
        self.uzk_text_plain_QPlainTextEdit.setPlainText(tekstas)
        f_atidaryti.close()
    
    def uzkuoduoti_teksta(self):
        baitai = self.uzk_bitai_LineEdit.displayText()
        tekstas = self.uzk_text_plain_QPlainTextEdit.toPlainText()
        raktas = self.uzk_raktas_LineEdit.displayText()
        if tekstas == "" or baitai == "" or int(baitai) > 256 or int(baitai) < 1 or raktas == "":
            self.klaida()
        else:
            rc4 = RC4_CBC()
            start_time = time.time()
            uzkuoduotas_tekstas = rc4.encRC4_CBC(str(tekstas), int(baitai), str(raktas))
            elapsed_time = time.time() - start_time
            self.uzk_laikas_tikras_Label.setText("%.3f" % elapsed_time)
            self.uzk_text_crypt_QPlainTextEdit.setPlainText(str(uzkuoduotas_tekstas))
            
            
    def dekuoduoti_teksta(self):
        baitai = self.dek_bitai_LineEdit.displayText()
        tekstas = self.dek_text_plain_QPlainTextEdit.toPlainText()
        raktas = self.dek_raktas_LineEdit.displayText()
        if tekstas == "" or baitai == "" or int(baitai) > 256 or int(baitai) < 1 or raktas == "":
            self.klaida()
        else:
            rc4 = RC4_CBC()
            start_time = time.time()
            dekuoduotas_tekstas = rc4.decRC4_CBC(str(tekstas), int(baitai), str(raktas))
            elapsed_time = time.time() - start_time
            self.dek_laikas_tikras_Label.setText("%.3f" % elapsed_time)
            self.dek_text_crypt_QPlainTextEdit.setPlainText(str(dekuoduotas_tekstas))
            
    def klaida(self):
        QMessageBox.critical(self, "Something has gone terribly terribly wrong! :(", QMessageBox.Ok)
    
    def baigti_darba(self):
        sys.exit()
        
    def GUI(self):
        self.atidaryti_teksta = QPushButton("Open File")
        self.atidaryti_teksta.setFixedWidth(120)
        self.failo_pavadinimas_Label = QLabel("(File Name)")
        
        self.uzk_uzkuoduoti_PushButton = QPushButton("Encrypt")
        self.uzk_raktas_Label = QLabel("Key: ")
        self.uzk_raktas_LineEdit = QLineEdit()
        self.uzk_bitai_Label = QLabel("Bits: ")
        self.uzk_bitai_LineEdit = QLineEdit()
        self.uzk_laikas_Label = QLabel("Encryption time: ")
        self.uzk_laikas_tikras_Label = QLabel("(sec)")
        self.uzk_text_plain_QPlainTextEdit = QPlainTextEdit()
        self.uzk_text_crypt_QPlainTextEdit = QPlainTextEdit()
        self.uzk_text_crypt_QPlainTextEdit.setReadOnly(True)
        
        self.dek_uzkuoduoti_PushButton = QPushButton("Decrypt")
        self.dek_raktas_Label = QLabel("Key: ")
        self.dek_raktas_LineEdit = QLineEdit()
        self.dek_bitai_Label = QLabel("Bits: ")
        self.dek_bitai_LineEdit = QLineEdit()
        self.dek_laikas_Label = QLabel("Decryption time: ")
        self.dek_laikas_tikras_Label = QLabel("(sec)")
        self.dek_text_plain_QPlainTextEdit = QPlainTextEdit()
        self.dek_text_crypt_QPlainTextEdit = QPlainTextEdit()
        self.dek_text_crypt_QPlainTextEdit.setReadOnly(True)
        
        self.baigti_PushButton =  QPushButton("Quit")    
        
        atidaryti_faila_Grid = QGridLayout()
        atidaryti_faila_Grid.addWidget(self.atidaryti_teksta, 1, 0)
        atidaryti_faila_Grid.addWidget(self.failo_pavadinimas_Label, 1, 1)
        
        uzk_Grid = QGridLayout()
        uzk_Grid.addWidget(self.uzk_uzkuoduoti_PushButton, 1, 0)
        uzk_Grid.addWidget(self.uzk_raktas_Label, 1, 1)
        uzk_Grid.addWidget(self.uzk_raktas_LineEdit, 1, 2)
        uzk_Grid.addWidget(self.uzk_bitai_Label, 1, 3)
        uzk_Grid.addWidget(self.uzk_bitai_LineEdit, 1, 4)
        uzk_Grid.addWidget(self.uzk_laikas_Label, 1, 5)
        uzk_Grid.addWidget(self.uzk_laikas_tikras_Label, 1, 6)
        uzk_tekstai_Grid = QGridLayout()
        uzk_tekstai_Grid.addWidget(self.uzk_text_plain_QPlainTextEdit, 1, 0)
        uzk_tekstai_Grid.addWidget(self.uzk_text_crypt_QPlainTextEdit, 1, 1)
        
        dek_Grid = QGridLayout()
        dek_Grid.addWidget(self.dek_uzkuoduoti_PushButton, 1, 0)
        dek_Grid.addWidget(self.dek_raktas_Label, 1, 1)
        dek_Grid.addWidget(self.dek_raktas_LineEdit, 1, 2)
        dek_Grid.addWidget(self.dek_bitai_Label, 1, 3)
        dek_Grid.addWidget(self.dek_bitai_LineEdit, 1, 4)
        dek_Grid.addWidget(self.dek_laikas_Label, 1, 5)
        dek_Grid.addWidget(self.dek_laikas_tikras_Label, 1, 6)
        dek_tekstai_Grid = QGridLayout()
        dek_tekstai_Grid.addWidget(self.dek_text_plain_QPlainTextEdit, 1, 0)
        dek_tekstai_Grid.addWidget(self.dek_text_crypt_QPlainTextEdit, 1, 1)
        
        self.vbox = QVBoxLayout()
        self.vbox.addLayout(atidaryti_faila_Grid)
        self.vbox.addLayout(uzk_Grid)
        self.vbox.addLayout(uzk_tekstai_Grid)
        self.vbox.addLayout(dek_Grid)
        self.vbox.addLayout(dek_tekstai_Grid)
        self.vbox.addWidget(self.baigti_PushButton)
        
        self.setLayout(self.vbox)
        self.setWindowTitle("RC4 CBC mode de-encrypter")
        self.setFixedSize(900, 700)    

if __name__ == "__main__":
    prog  = QApplication(sys.argv)
    lab = lab3()
    lab.show()
    sys.exit(prog.exec_())