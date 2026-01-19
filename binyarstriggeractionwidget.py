from PySide6.QtWidgets import (
    QWidget,
    QPushButton,
    QHBoxLayout,
    QDialog,
    QVBoxLayout,
    QTextEdit,
    QStyle,
)
from PySide6.QtCore import Qt
from PySide6.QtGui import QGuiApplication

from base64 import b64decode

from .binyarscanner import (
    ConsoleEntryGroup,
)

from binaryninja.log import Logger

logger = Logger(session_id=0, logger_name=__name__)


class TriggerActionWidget(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)

        self._name: str | None = None
        self._code: str | None = None
        self._console_groups: list[ConsoleEntryGroup] | None = None

        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setAlignment(Qt.AlignLeft)

        # Primary action button
        self.action_button = QPushButton(self._name)
        self.action_button.setToolTip("Copy generated code snippet to clipboard")
        self.action_button.clicked.connect(self.copy_action_to_clipboard)
        layout.addWidget(self.action_button)

        # Code preview button (icon-only)
        self.code_button = QPushButton()
        self.code_button.setIcon(
            self.style().standardIcon(QStyle.SP_FileDialogInfoView)
        )
        self.code_button.setToolTip("View action code")
        self.code_button.setFixedWidth(28)
        self.code_button.clicked.connect(self.show_code_popup)
        layout.addWidget(self.code_button)

        # Spacer keeps buttons left-aligned
        layout.addStretch()

    def update_action(
        self, name: str, code: str, console_groups: list[ConsoleEntryGroup]
    ):
        """Update the widget with a new action definition."""
        self._name = name
        self._code = code
        self._console_groups = console_groups

        self.action_button.setText(f"Copy: {name}")
        self.action_button.setEnabled(True)
        self.code_button.setEnabled(True)
        self.action_button.setEnabled(bool(self._code))

    def clear(self):
        """Reset the widget to an empty state."""
        self._name = None
        self._code = None
        self._console_groups = None
        self.action_button.setText("")
        self.action_button.setEnabled(False)
        self.code_button.setEnabled(False)

    def find_duplicate_children(self) -> set[str]:
        seen: set[str] = set()
        duplicates: set[str] = set()

        for group in self._console_groups:
            for entry in group.entries:
                child = entry.child.lower()
                if child in seen:
                    duplicates.add(child)
                else:
                    seen.add(child)

        return duplicates

    def construct_code(self) -> str | None:
        try:
            code = b64decode(self._code).decode("utf-8")
        except Exception as ex:
            logger.log_error(f"The value of BNTrigger must be base64 encoded: {ex}")
            return

        child_dups = self.find_duplicate_children()
        for group in self._console_groups:
            for entry in group.entries:
                if entry.child in child_dups:
                    code = f"{entry.key.replace('.', '_')} = {entry.value}\n\n{code}"
                else:
                    code = f"{entry.child} = {entry.value}\n\n{code}"
        return code

    def show_code_popup(self):
        if not (code := self.construct_code()):
            return

        dialog = QDialog(self)
        dialog.setWindowTitle(f"Snippet - {self._name}")
        dialog.setModal(True)
        dialog.resize(600, 400)

        main_layout = QVBoxLayout(dialog)

        # Text view
        text_edit = QTextEdit()
        text_edit.setPlainText(code)
        text_edit.setFontFamily("monospace")
        text_edit.setReadOnly(True)

        main_layout.addWidget(text_edit)

        # Button row
        button_layout = QHBoxLayout()

        toggle_button = QPushButton("Edit")
        copy_button = QPushButton("Copy and Close")

        button_layout.addWidget(toggle_button)
        button_layout.addWidget(copy_button)
        button_layout.addStretch()

        main_layout.addLayout(button_layout)

        # Toggle read-only mode
        def toggle_readonly():
            is_readonly = text_edit.isReadOnly()
            text_edit.setReadOnly(not is_readonly)
            toggle_button.setText("Read-only" if is_readonly else "Edit")

        toggle_button.clicked.connect(toggle_readonly)

        # Copy all text to clipboard
        def copy_all():
            QGuiApplication.clipboard().setText(text_edit.toPlainText())
            dialog.accept()

        copy_button.clicked.connect(copy_all)

        dialog.exec()

    def copy_action_to_clipboard(self):
        if not (code := self.construct_code()):
            return

        QGuiApplication.clipboard().setText(code)
        logger.log_info(f"{self._name} snippet copied to clipboard")
