def main():

    from PyQt6.QtWidgets import QApplication, QWidget, QPushButton, QMainWindow, QHBoxLayout, QVBoxLayout, QTabWidget, \
        QComboBox, QMenu
    from PyQt6.QtGui import QColor, QPalette, QAction, QIcon

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

    class MainWindow(QMainWindow):

        def __init__(self):
            super().__init__()
            self.setWindowTitle("WIP")

            self.mainlayout = QVBoxLayout()
            self.mainlayout.setContentsMargins(0,0,0,0)

            if "taskbar tabs":

                self.superior = self.menuBar()

                if "file menu":
                    file_menu =self. superior.addMenu("&File")

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
                    theme_toggle.setChecked(True)
                    theme_toggle.triggered.connect(self.toggle_theme)
                    self.toggle_theme(theme_toggle)

                    self.view_menu.addAction(theme_toggle)

            self.inferior = QTabWidget()

            self.keysMedia = QHBoxLayout()
            self.keysMediaWidget = QWidget()
            self.keysMediaWidget.setLayout(self.keysMedia)
            self.inferior.addTab(self.keysMediaWidget, "&Key Pairs")

            self.inferior.setTabPosition(QTabWidget.TabPosition.North)

            self.mainlayout.addWidget(self.superior)
            self.mainlayout.addWidget(self.inferior)

            self.mainwidget = QWidget()
            self.mainwidget.setLayout(self.mainlayout)

            self.setCentralWidget(self.mainwidget)

        def import_action(self):
            print("Placeholder import action")

        def export_action(self):
            print("Placeholder export action")

        def toggle_theme(self, dark: bool):
            if dark:
                self.setStyleSheet(DARK_THEME)
            elif not dark:
                self.setStyleSheet("")


    window = MainWindow()
    window.show()

    app.exec()


if __name__ == '__main__':
    main()
