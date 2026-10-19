import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import Mutekizu

Item {
    id: page

    ScrollView {
        anchors.fill: parent
        anchors.margins: 20
        clip: true
        ColumnLayout {
            width: page.width - 40
            spacing: 14

            Card {
                Layout.fillWidth: true
                title: qsTr("Диагностика окружения")
                RowLayout {
                    Layout.fillWidth: true
                    Text {
                        Layout.fillWidth: true
                        text: qsTr("Read-only проверка ядра, nftables, прав, конфликтов queue/mark, маршрутизации и конфигурации. Внешние запросы не выполняются.")
                        color: Theme.muted
                        font.family: Theme.font
                        font.pixelSize: 12
                        wrapMode: Text.WordWrap
                    }
                    Button {
                        text: backend.busy ? qsTr("Проверяется…") : qsTr("Проверить")
                        font.family: Theme.font
                        enabled: !backend.busy
                        onClicked: backend.runDoctor()
                    }
                    Button {
                        text: qsTr("Экспорт…")
                        font.family: Theme.font
                        enabled: backend.diagnosticsRaw.length > 0
                        onClicked: exportDialog.open()
                    }
                }
                Text {
                    Layout.fillWidth: true
                    text: qsTr("doctor запускается от пользователя GUI: сообщения об отсутствии CAP_* ожидаемы, служба systemd запускается со своими capabilities. Экспорт может содержать домены, IP, пути и сведения о системе — проверьте файл перед публикацией.")
                    color: Theme.warn
                    font.family: Theme.font
                    font.pixelSize: 11
                    wrapMode: Text.WordWrap
                }
            }

            Card {
                Layout.fillWidth: true
                title: qsTr("Результаты")
                Repeater {
                    model: backend.diagnostics
                    RowLayout {
                        Layout.fillWidth: true
                        StatusBadge {
                            Layout.preferredWidth: 190
                            level: modelData.level
                            text: modelData.level === "ok" ? qsTr("OK")
                                  : modelData.level === "warn" ? qsTr("Предупреждение")
                                  : modelData.level === "fail" ? qsTr("Ошибка")
                                  : qsTr("Не проверено")
                        }
                        Text {
                            Layout.fillWidth: true
                            text: modelData.text
                            color: Theme.text
                            font.family: Theme.font
                            font.pixelSize: 12
                            wrapMode: Text.WordWrap
                        }
                    }
                }
                Text {
                    Layout.fillWidth: true
                    visible: backend.diagnostics.length === 0
                    text: qsTr("Запустите проверку. Недоступные пункты будут показаны как «не проверено», а не как успех.")
                    color: Theme.muted
                    font.family: Theme.font
                    font.pixelSize: 12
                }
            }

            Card {
                Layout.fillWidth: true
                title: qsTr("Подробный вывод")
                Switch {
                    id: rawToggle
                    text: qsTr("Показать сырой вывод doctor")
                    font.family: Theme.font
                }
                ScrollView {
                    Layout.fillWidth: true
                    Layout.preferredHeight: rawToggle.checked ? 260 : 0
                    visible: rawToggle.checked
                    TextArea {
                        text: backend.diagnosticsRaw
                        readOnly: true
                        selectByMouse: true
                        wrapMode: TextArea.Wrap
                        font.family: "monospace"
                        font.pixelSize: 11
                        color: Theme.text
                        background: Rectangle { color: Theme.surface2; radius: 8 }
                    }
                }
            }
        }
    }

    Dialog {
        id: exportDialog
        title: qsTr("Экспорт диагностики")
        modal: true
        anchors.centerIn: Overlay.overlay
        width: Math.min(600, page.width - 60)
        standardButtons: Dialog.Cancel | Dialog.Ok
        onAccepted: backend.exportText(pathField.text, backend.diagnosticsRaw)
        ColumnLayout {
            width: parent.width
            TextField {
                id: pathField
                Layout.fillWidth: true
                text: "~/mutekizu-diagnostics.txt"
                font.family: Theme.font
            }
            Text {
                Layout.fillWidth: true
                text: qsTr("Файл может содержать чувствительные сведения о системе. Не публикуйте без просмотра.")
                color: Theme.warn; font.family: Theme.font; font.pixelSize: 11
                wrapMode: Text.WordWrap
            }
        }
    }
}
