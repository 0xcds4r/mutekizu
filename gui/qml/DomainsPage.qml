import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import Mutekizu

Item {
    id: page
    property string search: ""
    property string validationText: ""

    function replaceDomain(index, text) {
        var list = backend.draftDomains.slice()
        list[index] = text
        backend.setDomains(list)
    }
    function removeDomain(index) {
        var list = backend.draftDomains.slice()
        list.splice(index, 1)
        backend.setDomains(list)
    }
    function addLines(text) {
        var parts = text.split(/[\n,]+/)
        var list = backend.draftDomains.slice()
        for (var i = 0; i < parts.length; ++i) {
            var d = parts[i].trim()
            if (d.length > 0) list.push(d)
        }
        backend.setDomains(list)
    }

    ScrollView {
        anchors.fill: parent
        anchors.margins: 20
        clip: true
        ColumnLayout {
            width: page.width - 40
            spacing: 14

            Card {
                Layout.fillWidth: true
                title: qsTr("SNI-цели")
                Text {
                    Layout.fillWidth: true
                    text: qsTr("Движок сопоставляет SNI ClientHello: запись покрывает сам домен и его поддомены. Это список наблюдаемых SNI, а не исправление DNS. Без доступного SNI правило не применится.")
                    color: Theme.muted
                    font.family: Theme.font
                    font.pixelSize: 12
                    wrapMode: Text.WordWrap
                }
                RowLayout {
                    Layout.fillWidth: true
                    TextField {
                        id: addField
                        Layout.fillWidth: true
                        placeholderText: qsTr("example.com")
                        font.family: Theme.font
                        onAccepted: { page.addLines(text); clear() }
                    }
                    Button {
                        text: qsTr("Добавить")
                        font.family: Theme.font
                        enabled: addField.text.trim().length > 0
                        onClicked: { page.addLines(addField.text); addField.clear() }
                    }
                }
                RowLayout {
                    Layout.fillWidth: true
                    TextField {
                        Layout.fillWidth: true
                        placeholderText: qsTr("Поиск")
                        font.family: Theme.font
                        onTextChanged: page.search = text
                    }
                    Button {
                        text: qsTr("Вставить несколько")
                        font.family: Theme.font
                        onClicked: pasteDialog.open()
                    }
                    Button {
                        text: qsTr("Импорт")
                        font.family: Theme.font
                        onClicked: importDialog.open()
                    }
                    Button {
                        text: qsTr("Экспорт")
                        font.family: Theme.font
                        onClicked: exportDialog.open()
                    }
                }
                Text {
                    Layout.fillWidth: true
                    visible: backend.draftDomains.length === 0
                    text: qsTr("Список пуст. Для режима SNI-split нужен хотя бы один домен.")
                    color: Theme.warn
                    font.family: Theme.font
                    font.pixelSize: 12
                }

                Repeater {
                    model: backend.draftDomains
                    RowLayout {
                        Layout.fillWidth: true
                        visible: page.search.length === 0
                                 || modelData.toLowerCase().indexOf(page.search.toLowerCase()) >= 0
                        Text {
                            text: qsTr("%1.").arg(index + 1)
                            color: Theme.muted
                            font.family: Theme.font
                            font.pixelSize: 12
                            Layout.preferredWidth: 32
                        }
                        TextField {
                            Layout.fillWidth: true
                            text: modelData
                            font.family: Theme.font
                            onEditingFinished: page.replaceDomain(index, text)
                        }
                        Button {
                            text: qsTr("Удалить")
                            font.family: Theme.font
                            onClicked: page.removeDomain(index)
                        }
                    }
                }

                RowLayout {
                    Layout.fillWidth: true
                    Button {
                        text: qsTr("Проверить список и настройки")
                        font.family: Theme.font
                        onClicked: page.validationText = backend.validateDraft()
                    }
                    Text {
                        Layout.fillWidth: true
                        text: page.validationText.length === 0
                              ? qsTr("Проверка ещё не запускалась.")
                              : page.validationText
                        color: page.validationText.length === 0 ? Theme.muted : Theme.err
                        font.family: Theme.font
                        font.pixelSize: 12
                        wrapMode: Text.WordWrap
                    }
                }
                Text {
                    Layout.fillWidth: true
                    text: qsTr("Поддерживаются ASCII-имена, punycode (xn--…), дефисы и подчёркивания. Wildcard-синтаксис движок не понимает; IDN автоматически не нормализуется.")
                    color: Theme.muted
                    font.family: Theme.font
                    font.pixelSize: 11
                    wrapMode: Text.WordWrap
                }
            }

        }
    }

    Dialog {
        id: pasteDialog
        title: qsTr("Вставить домены")
        modal: true
        anchors.centerIn: Overlay.overlay
        width: Math.min(560, page.width - 60)
        standardButtons: Dialog.Cancel | Dialog.Ok
        onAccepted: { page.addLines(pasteArea.text); pasteArea.clear() }
        TextArea {
            id: pasteArea
            width: parent.width
            height: 220
            placeholderText: qsTr("Один домен на строку или через запятую")
            font.family: "monospace"
            wrapMode: TextArea.Wrap
        }
    }

    Dialog {
        id: importDialog
        title: qsTr("Импорт доменов")
        modal: true
        anchors.centerIn: Overlay.overlay
        width: Math.min(560, page.width - 60)
        standardButtons: Dialog.Cancel | Dialog.Ok
        onAccepted: {
            var text = backend.readTextFile(pathField.text)
            if (text.length > 0) page.addLines(text)
        }
        ColumnLayout {
            width: parent.width
            TextField {
                id: pathField
                Layout.fillWidth: true
                text: "~/domains.txt"
                font.family: Theme.font
            }
            Text {
                Layout.fillWidth: true
                text: qsTr("Читается только указанный файл; строки добавляются к текущему списку.")
                color: Theme.muted
                font.family: Theme.font
                font.pixelSize: 11
                wrapMode: Text.WordWrap
            }
        }
    }

    Dialog {
        id: exportDialog
        title: qsTr("Экспорт доменов")
        modal: true
        anchors.centerIn: Overlay.overlay
        width: Math.min(560, page.width - 60)
        standardButtons: Dialog.Cancel | Dialog.Ok
        onAccepted: backend.exportText(pathField2.text, backend.draftDomains.join("\n") + "\n")
        ColumnLayout {
            width: parent.width
            TextField {
                id: pathField2
                Layout.fillWidth: true
                text: "~/mutekizu-domains.txt"
                font.family: Theme.font
            }
            Text {
                Layout.fillWidth: true
                text: qsTr("Файл содержит только список доменов. Путь не должен указывать на симлинк; запись выполняется от вашего пользователя.")
                color: Theme.muted
                font.family: Theme.font
                font.pixelSize: 11
                wrapMode: Text.WordWrap
            }
        }
    }
}
