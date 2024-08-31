import sys
import re
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QPushButton,
    QLabel, QTextEdit, QFileDialog, QTableWidget, QTableWidgetItem,
    QMessageBox
)
from PyQt5.QtCore import Qt


class LexicalAnalyzerGUI(QMainWindow):
    def __init__(self):
        super().__init__()

        # Configuración de la ventana principal
        self.setWindowTitle('Analizador Léxico')
        self.setGeometry(100, 100, 900, 700)

        # Contenedor principal
        central_widget = QWidget(self)
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)

        # Botón para cargar el archivo
        self.load_button = QPushButton('Cargar Archivo', self)
        self.load_button.clicked.connect(self.load_file)
        layout.addWidget(self.load_button)

        # Área de texto para mostrar el contenido del archivo
        self.text_area = QTextEdit(self)
        self.text_area.setReadOnly(True)
        layout.addWidget(self.text_area)

        # Botón para iniciar el análisis léxico
        self.analyze_button = QPushButton('Analizar', self)
        self.analyze_button.clicked.connect(self.analyze_text)
        layout.addWidget(self.analyze_button)

        # Tabla para mostrar los tokens
        self.token_table = QTableWidget(self)
        self.token_table.setColumnCount(3)
        self.token_table.setHorizontalHeaderLabels(['Token', 'Tipo', 'Cantidad'])
        layout.addWidget(self.token_table)

        # Etiqueta para mostrar los errores léxicos
        self.error_label = QLabel('Errores Léxicos:', self)
        layout.addWidget(self.error_label)

        # Área de texto para mostrar los errores léxicos
        self.error_area = QTextEdit(self)
        self.error_area.setReadOnly(True)
        layout.addWidget(self.error_area)

        # Inicialización de variables
        self.file_path = None

        # Definición y compilación de expresiones regulares
        self.token_specification = [
            ('PALABRA_RESERVADA', r'\b(entero|decimal|booleano|cadena|si|sino|mientras|hacer|verdadero|falso)\b'),
            ('OPERADOR_LOGICO', r'(<=|>=|==|<>|<|>)'),
            ('OPERADOR_ARITMETICO', r'(\+|\-|\*|\/|\%)'),
            ('ASIGNACION', r'='),
            ('PUNTO_Y_COMA', r';'),
            ('COMA', r','),
            ('PARENTESIS_ABRE', r'\('),
            ('PARENTESIS_CIERRA', r'\)'),
            ('LLAVE_ABRE', r'\{'),
            ('LLAVE_CIERRA', r'\}'),
            ('CADENA', r'\".*?\"'),
            ('NUMERO_DECIMAL', r'\d+\.\d+'),
            ('NUMERO_ENTERO', r'\d+'),
            ('IDENTIFICADOR', r'\b[a-zA-Z_][a-zA-Z0-9_]*\b'),
            ('ESPACIOS', r'[ \t]+'),
            ('NUEVA_LINEA', r'\n'),
            ('DESCONOCIDO', r'.'),
        ]
        self.tok_regex = '|'.join('(?P<%s>%s)' % pair for pair in self.token_specification)
        self.get_token = re.compile(self.tok_regex).match

    def load_file(self):
        options = QFileDialog.Options()
        file_name, _ = QFileDialog.getOpenFileName(self, "Abrir Archivo", "",
                                                   "Archivos de Texto (*.txt);;Todos los Archivos (*)", options=options)
        if file_name:
            try:
                with open(file_name, 'r', encoding='utf-8') as file:
                    content = file.read()
                    self.text_area.setText(content)
                    self.file_path = file_name
            except Exception as e:
                QMessageBox.critical(self, "Error", f"No se pudo leer el archivo:\n{e}")

    def analyze_text(self):
        if not self.text_area.toPlainText():
            QMessageBox.warning(self, "Advertencia", "Por favor, cargue un archivo antes de analizar.")
            return

        content = self.text_area.toPlainText()
        line_num = 1
        line_start = 0
        tokens_found = {}
        errors = []

        pos = 0
        end = len(content)
        while pos < end:
            match = self.get_token(content, pos)
            if match:
                type_ = match.lastgroup
                value = match.group(type_)
                if type_ == 'NUEVA_LINEA':
                    line_num += 1
                    line_start = match.end()
                elif type_ == 'ESPACIOS':
                    pass  # Ignorar espacios en blanco
                elif type_ == 'DESCONOCIDO':
                    errors.append(f"Línea {line_num}: Carácter no reconocido '{value}'")
                elif type_ == 'CADENA':
                    # Verificar si la cadena no tiene comillas de cierre
                    if value.count('"') % 2 != 0:
                        errors.append(f"Línea {line_num}: Cadena no cerrada correctamente '{value}'")
                else:
                    # Procesar y almacenar tokens
                    key = (value, type_)
                    if key in tokens_found:
                        tokens_found[key] += 1
                    else:
                        tokens_found[key] = 1
                pos = match.end()
            else:
                errors.append(f"Línea {line_num}: Carácter ilegal '{content[pos]}'")
                pos += 1  # Avanzar para evitar bucle infinito

        self.update_ui(tokens_found, errors)

    def update_ui(self, tokens, errors):
        self.token_table.setRowCount(len(tokens))
        for i, ((token, type_), count) in enumerate(tokens.items()):
            self.token_table.setItem(i, 0, QTableWidgetItem(token))
            self.token_table.setItem(i, 1, QTableWidgetItem(type_))
            self.token_table.setItem(i, 2, QTableWidgetItem(str(count)))

        if errors:
            self.error_area.setText('\n'.join(errors))
        else:
            self.error_area.setText('No se encontraron errores léxicos.')


if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = LexicalAnalyzerGUI()
    window.show()
    sys.exit(app.exec_())
