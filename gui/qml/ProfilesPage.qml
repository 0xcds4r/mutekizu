import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import Mutekizu

Item {
    id: page

    property int selected: 0
    property string validationText: ""

    function currentText() {
        return backend.profileList.length > selected
               ? backend.profileList[selected].text : ""
    }

    function selectLast() {
        selected = Math.max(0, backend.profileList.length - 1)
    }

    function syncEditor() {
        editor.text = currentText()
    }

    function check() {
        validationText = backend.validateDraft()
        if (validationText.length === 0) validationText = qsTr("Проверка пройдена.")
    }

    Connections {
        target: backend
        function onProfilesChanged() {
            if (selected >= backend.profileList.length)
                selected = Math.max(0, backend.profileList.length - 1)
            if (!editor.activeFocus && editor.text !== currentText())
                editor.text = currentText()
        }
    }

    RowLayout {
        anchors.fill: parent
        anchors.margins: 20
        spacing: 14

        Card {
            Layout.preferredWidth: 285
            Layout.fillHeight: true
            title: qsTr("Профили")

            RowLayout {
                Layout.fillWidth: true
                Button {
                    text: qsTr("+")
                    font.family: Theme.font
                    onClicked: { backend.addProfile(); page.selectLast(); page.syncEditor() }
                }
                Button {
                    text: qsTr("Копия")
                    font.family: Theme.font
                    enabled: backend.profileList.length > 0
                    onClicked: {
                        backend.duplicateProfile(page.selected)
                        page.selectLast()
                        page.syncEditor()
                    }
                }
                Button {
                    text: qsTr("Удалить")
                    font.family: Theme.font
                    enabled: backend.profileList.length > 0
                    onClicked: { backend.removeProfile(page.selected); page.syncEditor() }
                }
            }

            Rectangle {
                Layout.fillWidth: true
                Layout.fillHeight: true
                color: Theme.bg
                border.color: Theme.border
                radius: 6

                ListView {
                    anchors.fill: parent
                    anchors.margins: 4
                    clip: true
                    model: backend.profileList
                    currentIndex: page.selected
                    onCurrentIndexChanged: page.selected = currentIndex

                    delegate: Rectangle {
                        width: ListView.view.width
                        height: 62
                        radius: 5
                        color: index === page.selected
                               ? Qt.rgba(Theme.accent.r, Theme.accent.g, Theme.accent.b, 0.16)
                               : "transparent"
                        border.color: index === page.selected ? Theme.accent : "transparent"
                        border.width: 1
                        ColumnLayout {
                            anchors.fill: parent
                            anchors.margins: 8
                            spacing: 2
                            Text {
                                Layout.fillWidth: true
                                text: modelData.name
                                color: Theme.text
                                font.family: Theme.font
                                font.pixelSize: 13
                                font.weight: Font.DemiBold
                                elide: Text.ElideRight
                            }
                            Text {
                                Layout.fillWidth: true
                                text: modelData.summary
                                color: Theme.muted
                                font.family: Theme.font
                                font.pixelSize: 10
                                elide: Text.ElideRight
                            }
                        }
                        MouseArea {
                            anchors.fill: parent
                            onClicked: page.selected = index
                        }
                    }
                }
                Text {
                    anchors.centerIn: parent
                    visible: backend.profileList.length === 0
                    text: qsTr("Нет профилей")
                    color: Theme.muted
                    font.family: Theme.font
                }
            }

            Text {
                Layout.fillWidth: true
                text: qsTr("Шаблоны добавляются в конец списка.")
                color: Theme.muted
                font.family: Theme.font
                font.pixelSize: 10
                wrapMode: Text.WordWrap
            }
            RowLayout {
                Layout.fillWidth: true
                Button {
                    text: qsTr("Discord")
                    font.family: Theme.font
                    onClicked: { backend.addProfileTemplate("discord"); page.selectLast(); page.syncEditor() }
                }
                Button {
                    text: qsTr("YouTube")
                    font.family: Theme.font
                    onClicked: { backend.addProfileTemplate("youtube"); page.selectLast(); page.syncEditor() }
                }
            }
        }

        Card {
            Layout.fillWidth: true
            Layout.fillHeight: true
            title: backend.profileList.length > page.selected
                   ? qsTr("Редактор · %1").arg(backend.profileList[page.selected].name)
                   : qsTr("Редактор профиля")

            Text {
                Layout.fillWidth: true
                text: qsTr("Имя профиля задаётся строкой [name]. Домены и интерфейсы — через запятую. Ключи стратегии — только те, что отличаются от mutekizu.conf.")
                color: Theme.muted
                font.family: Theme.font
                font.pixelSize: 11
                wrapMode: Text.WordWrap
            }

            TextArea {
                id: editor
                Layout.fillWidth: true
                Layout.fillHeight: true
                Layout.minimumHeight: 360
                text: page.currentText()
                enabled: backend.profileList.length > 0
                onTextChanged: {
                    if (page.selected < backend.profileList.length &&
                        text !== backend.profileTextAt(page.selected))
                        backend.setProfileBlock(page.selected, text)
                }
                onActiveFocusChanged: {
                    if (!activeFocus) backend.refreshProfiles()
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
            }

            RowLayout {
                Layout.fillWidth: true
                Button {
                    text: qsTr("Проверить")
                    font.family: Theme.font
                    enabled: backend.profileList.length > 0
                    onClicked: page.check()
                }
                Button {
                    text: qsTr("Применить")
                    font.family: Theme.font
                    enabled: backend.dirty && !backend.busy && !backend.applyRunning
                    onClicked: backend.applyDraft()
                }
                Button {
                    text: qsTr("Откатить")
                    font.family: Theme.font
                    enabled: backend.dirty
                    onClicked: { backend.revertDraft(); page.syncEditor() }
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
        }
    }
}
