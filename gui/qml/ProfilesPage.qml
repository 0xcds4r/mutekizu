import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import Mutekizu

Item {
    id: page

    property string validationText: ""

    function check() {
        validationText = backend.validateDraft()
        if (validationText.length === 0) validationText = qsTr("Проверка пройдена.")
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
                title: qsTr("Профили по доменам")
                Text {
                    Layout.fillWidth: true
                    text: qsTr("Каждая секция [name] задаёт домены, интерфейс (опционально) и только те параметры, которые отличаются от mutekizu.conf. Секции читаются сверху вниз; при auto_profile несколько совпадений используются как цепочка.")
                    color: Theme.muted
                    font.family: Theme.font
                    font.pixelSize: 12
                    wrapMode: Text.WordWrap
                }

                RowLayout {
                    Layout.fillWidth: true
                    Button {
                        text: qsTr("Discord шаблон")
                        font.family: Theme.font
                        onClicked: backend.setProfilesText(backend.profileTemplate("discord"))
                    }
                    Button {
                        text: qsTr("YouTube шаблон")
                        font.family: Theme.font
                        onClicked: backend.setProfilesText(backend.profileTemplate("youtube"))
                    }
                    Item { Layout.fillWidth: true }
                    Button {
                        text: qsTr("Очистить")
                        font.family: Theme.font
                        onClicked: backend.setProfilesText("")
                    }
                    Button {
                        text: qsTr("Откатить")
                        font.family: Theme.font
                        enabled: backend.dirty
                        onClicked: backend.revertDraft()
                    }
                }

                TextArea {
                    id: editor
                    Layout.fillWidth: true
                    Layout.preferredHeight: 430
                    text: backend.draftProfilesText
                    onTextChanged: {
                        if (text !== backend.draftProfilesText)
                            backend.setProfilesText(text)
                    }
                    font.family: "monospace"
                    font.pixelSize: 12
                    color: Theme.text
                    selectionColor: Theme.accent
                    selectedTextColor: Theme.bg
                    selectByMouse: true
                    wrapMode: TextEdit.NoWrap
                    background: Rectangle {
                        color: Theme.bg
                        border.color: Theme.border
                        radius: 6
                    }
                    Connections {
                        target: backend
                        function onDraftChanged() {
                            if (editor.text !== backend.draftProfilesText)
                                editor.text = backend.draftProfilesText
                        }
                    }
                }

                RowLayout {
                    Layout.fillWidth: true
                    Button {
                        text: qsTr("Проверить")
                        font.family: Theme.font
                        onClicked: page.check()
                    }
                    Button {
                        text: qsTr("Применить")
                        font.family: Theme.font
                        enabled: backend.dirty && !backend.busy && !backend.applyRunning
                        onClicked: backend.applyDraft()
                    }
                    Item { Layout.fillWidth: true }
                    Text {
                        text: backend.applyRunning ? backend.applyMessage : ""
                        color: Theme.muted
                        font.family: Theme.font
                        font.pixelSize: 11
                    }
                }

                Text {
                    Layout.fillWidth: true
                    text: page.validationText
                    visible: page.validationText.length > 0
                    color: page.validationText === qsTr("Проверка пройдена.") ? Theme.ok : Theme.err
                    font.family: Theme.font
                    font.pixelSize: 12
                    wrapMode: Text.WordWrap
                }

                Text {
                    Layout.fillWidth: true
                    text: qsTr("Пустой файл допустим. Изменения применяются кнопкой «Применить» и требуют Polkit. Служба перезапустится, если она запущена.")
                    color: Theme.muted
                    font.family: Theme.font
                    font.pixelSize: 11
                    wrapMode: Text.WordWrap
                }
            }
        }
    }
}
