from PyQt6.QtWidgets import QApplication, QWidget, QPushButton, QMainWindow, QHBoxLayout, QVBoxLayout, QTabWidget
from PyQt6.QtGui import QColor, QPalette
from PyQt6.QtWidgets import QWidget




app = QApplication([])

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("My App")

        inferior = QTabWidget()

        keysMedia = QHBoxLayout()
        keysMediaWidget = QWidget()
        keysMediaWidget.setLayout(keysMedia)
        inferior.addTab(keysMediaWidget, "Key Pairs")

        inferior.setTabPosition(QTabWidget.TabPosition.North)

        self.setCentralWidget(inferior)

window = MainWindow()
window.show()

app.exec()