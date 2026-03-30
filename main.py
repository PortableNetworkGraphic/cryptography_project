import hashlib
from os import urandom

from PyQt6.QtWidgets import *
from PyQt6.QtGui import QColor, QPalette, QAction, QIcon
import json
from primitives.aes import AES
from primitives.hashing import SHA2
from primitives.rsa import RSA
from primitives.file_encryption import encrypt_file, decrypt_file


app = QApplication([])

DARK_THEME = """
QWidget {
background-color: #31363B;
color: white;
}
QPushButton {
background-color: #2a2e32;
color: white;
}
QTabWidget::pane {
background-color: #1b1e21;
}
QTabBar::tab {
background-color: #2a2e32;
color: white;
}
QMenu {
color: #E6E6E6;
background-color: #353A40;
border: 1px solid #555;
border-radius: 2px;
}
QMenu::item {
background-color: #353A40;
color: white;
padding: 4px 20px;
}
QMenu::item:selected {          
background-color: #4C545C;
color: #ffffff;
}
"""




def read_appdata(k: bytes, n: bytes, expected_hash: bytes) -> dict:

    t = AES(k, 256, n)
    with open("appdata.bin", 'rb') as f:
        c = f.read()
        d, nb = t.encrypt_bytes(c)
        if (SHA2(d).digest() == expected_hash):
            return json.loads(d.decode("utf-8"))
        else:
            print(expected_hash, SHA2(d).digest())
            return {"error": "Invalid Password"}

def write_appdata(k: bytes, n: bytes, appdata: dict) -> None:

    t = AES(k, 256, n)
    with open("appdata.bin", 'wb') as f:

        p = json.dumps(appdata).encode()

        c, nb = t.encrypt_bytes(p)
        f.write(c)



class NewKeyDialog(QDialog):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Create New Key")
        layout = QVBoxLayout()

        form_layout = QFormLayout()

        self.name_input = QLineEdit()
        self.email_input = QLineEdit()
        self.key_size_input = QComboBox()
        self.key_size_input.addItems(["1024", "2048", "4096"])

        form_layout.addRow("Name:", self.name_input)
        form_layout.addRow("Email:", self.email_input)
        form_layout.addRow("Key Size:", self.key_size_input)

        layout.addLayout(form_layout)

        # OK / Cancel buttons
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok |
                                   QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

        self.setLayout(layout)

    def get_data(self):
        data = {
            "name": self.name_input.text(),
            "email": self.email_input.text(),
            "key_size": int(self.key_size_input.currentText()),
        }

        public, private = RSA.new_key_pair(data["key_size"])
        data["public_key"] = public
        data["private_key"] = private
        data["fingerprint"] = (SHA2(json.dumps((public, private)).encode()).digest()).hex()

        return data

class MainWindow(QMainWindow):

    def __init__(self):
        super().__init__()
        self.appdata = None
        self.k, self.n, self.p = None, None, None
        self.setWindowTitle("WIP")

        self.mainlayout = QVBoxLayout()
        self.mainlayout.setContentsMargins(0, 0, 0, 0)

        if "taskbar tabs":

            self.superior = self.menuBar()

            if "file menu":
                file_menu = self.superior.addMenu("&File")

                self.import_button = QAction(QIcon("icons\\arrow-270.png"), "Import", self)
                self.import_button.setStatusTip("Import keys from a file")
                self.import_button.triggered.connect(self.import_action)
                file_menu.addAction(self.import_button)

                self.export_button = QAction(QIcon("icons\\arrow-090.png"), "Export", self)
                self.export_button.setStatusTip("Export keys to files")
                self.export_button.triggered.connect(self.export_action)
                file_menu.addAction(self.export_button)

            if "view_menu":
                self.view_menu = self.superior.addMenu("&Menu")

                theme_toggle = QAction("Dark Mode", self)
                theme_toggle.setStatusTip("Enable dark mode")
                theme_toggle.setCheckable(True)
                theme_toggle.triggered.connect(self.toggle_theme)

                self.view_menu.addAction(theme_toggle)

            if "new_menu":
                self.new_menu = self.superior.addMenu("New")

                self.new_key_button = QAction("New Key Pair", self)
                self.new_key_button.setStatusTip("WIP")
                self.new_key_button.triggered.connect(self.gen_new_key)
                self.new_menu.addAction(self.new_key_button)

        if "inferior":
            self.inferior = QTabWidget()

            if "keys":
                self.keysMedia = QTableWidget()
                self.inferior.addTab(self.keysMedia, "&Key Pairs")

            if "encrypt":


                self.encryptWidget = QWidget()
                self.encryptLayout = QHBoxLayout(self.encryptWidget)


                self.encryptLeft = QVBoxLayout()

                self.encrypt_file_input = QLineEdit()
                self.encrypt_file_input.setPlaceholderText("File input")
                self.encrypt_file_input_browse = QPushButton("Browse")
                self.encrypt_file_input_browse.clicked.connect(self.choose_file)

                self.destination_input = QLineEdit()
                self.destination_input.setPlaceholderText("File destination ")
                self.destination_button = QPushButton("Browse...")
                self.destination_button.clicked.connect(self.choose_destination)

                self.encryptLeft.addWidget(self.encrypt_file_input)
                self.encryptLeft.addWidget(self.encrypt_file_input_browse)
                self.encryptLeft.addWidget(self.destination_input)
                self.encryptLeft.addWidget(self.destination_button)


                self.encryptRight = QFormLayout()

                self.keylenchoice = QComboBox()
                self.keylenchoice.addItems(["128", "192", "256"])

                self.authchoice = QComboBox()
                self.authchoice.addItems(["HMAC", "RSA"])

                self.encrpyt_key_select = QComboBox()

                self.encrypt_button = QPushButton("Encrypt")
                self.encrypt_button.clicked.connect(self.encrypt_from_tab)

                self.encryptRight.addRow("Key Length", self.keylenchoice)
                self.encryptRight.addRow("Authentification",self.authchoice)
                self.encryptRight.addRow("RSA Key", self.encrpyt_key_select)
                self.encryptRight.addRow(self.encrypt_button)

                self.encryptLayout.addLayout(self.encryptLeft)
                self.encryptLayout.addLayout(self.encryptRight)

                self.inferior.addTab(self.encryptWidget, "&Encrypt")

            self.inferior.setTabPosition(QTabWidget.TabPosition.North)

        self.mainlayout.addWidget(self.superior)
        self.mainlayout.addWidget(self.inferior)

        self.mainwidget = QWidget()
        self.mainwidget.setLayout(self.mainlayout)

        self.setCentralWidget(self.mainwidget)

    def encrypt_from_tab(self):
        source = self.encrypt_file_input.text()
        key_name = self.encrpyt_key_select.currentText()
        print(source, key_name)
        keys = self.appdata["keys"].values()
        for key in keys:
            if key["name"]==key_name:
                public_key, private_key = key["public_key"], key["private_key"]


        encrypt_file()

    def choose_destination(self):
        folder = QFileDialog.getExistingDirectory(None, "Select Destination Folder")
        if folder:
            self.destination_input.setText(folder)

    def choose_file(self):
        path, _ = QFileDialog.getOpenFileName(None, "Select Target File")
        if path: self.encrypt_file_input.setText(path)

    #right now the password is "test"
    def test_password(self, expected_hash: bytes, salt, nonce: bytes) -> dict:
        valid = False
        while not valid:
            text, ok = QInputDialog.getText(self, "Login", "Password:")
            if ok and text:
                key = hashlib.pbkdf2_hmac(
                    "sha256",
                    text.encode("utf-8"),
                    salt,
                    100000,
                    128//8
                )

                data = read_appdata(key, nonce, expected_hash)
                if "error" not in data.keys():
                    self.k, self.n, self.p = key, nonce, text
                    return data

    def gen_new_key(self):
        dialog = NewKeyDialog()
        if dialog.exec():
            data = dialog.get_data()
            print(data)
            self.appdata["keys"][data["fingerprint"]] = data

            count = self.keysMedia.rowCount()
            self.keysMedia.insertRow(count)

            tabledata = {}
            for k in data.keys():
                if k not in ["public_key","private_key","fingerprint"]:
                    tabledata[k] = data[k]
                elif k == "fingerprint":
                    fingerprint = data[k].upper()
                    shortened = fingerprint[:4] + "..." + fingerprint[-4:]
                    tabledata[k] = shortened
                elif k == "name":
                    self.encrpyt_key_select.addItem(data[k])

            print(tabledata)
            for i, val in enumerate(tabledata.values()):
                self.keysMedia.setItem(count, i, QTableWidgetItem(str(val)))
        self.change_password_info(self.appdata, self.p)


    def import_action(self):
        print("Placeholder import action")

    def export_action(self):
        print("Placeholder export action")

    def toggle_theme(self, dark: bool):
        if dark:
            self.setStyleSheet(DARK_THEME)
        elif not dark:
            self.setStyleSheet("")

    def load_keys(self):
        keys = self.appdata["keys"]

        print(keys)

        self.keysMedia.setColumnCount(4)
        self.keysMedia.setRowCount(len(keys))
        self.keysMedia.setHorizontalHeaderLabels([
            "Name", "Email", "Key Size", "Fingerprint"
        ])

        self.encrpyt_key_select.addItems([key["name"] for key in keys.values()])

        for row, key in enumerate(keys.values()):

            tabledata = {}
            for k in key.keys():
                if k not in ["public_key","private_key","fingerprint"]:
                    tabledata[k] = key[k]
                elif k == "fingerprint":
                    fingerprint = key[k].upper()
                    shortened = fingerprint[:4] + "..." + fingerprint[-4:]
                    tabledata[k] = shortened

            print(tabledata)
            for i, val in enumerate(tabledata.values()):
                self.keysMedia.setItem(row, i, QTableWidgetItem(str(val)))

    @staticmethod
    def change_password_info(appdata: dict, password: str):
        salt = urandom(16)
        nonce = urandom(128//8)

        key = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt,
            100000,
            128 // 8
        )

        write_appdata(key, nonce, appdata)

        with open("key.json", 'w') as f:
            json.dump(
                {
                    "login": False,
                    "key": b"-1".hex(),
                    "salt": salt.hex(),
                    "nonce": nonce.hex(),
                    "hash": SHA2(json.dumps(appdata).encode()).digest().hex()
                }, f
            )



def main():
    mainwindow = MainWindow()
    mainwindow.show()

    with open("key.json", 'r') as f:
        rl = json.load(f)

        login = rl["login"]
        keybytes = bytes.fromhex(rl["key"])
        salt = bytes.fromhex(rl["salt"])
        nonce = bytes.fromhex(rl["nonce"])
        hash = bytes.fromhex(rl["hash"])

        if login:
            appdata = read_appdata(keybytes, nonce, hash)
        else:
            appdata = mainwindow.test_password(hash, salt, nonce)
            print(appdata)

        mainwindow.appdata = appdata

    mainwindow.load_keys()

    app.exec()

if __name__ == '__main__':

    main()
