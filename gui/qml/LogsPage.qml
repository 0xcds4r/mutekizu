import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import Mutekizu

Item {
    id: page
    property int levelFilter: 0
    property var filtered: []

    function refreshFiltered() {
        var out = []
        var levels = ["error", "warn", "info", "debug"]
        for (var i = 0; i < backend.logs.length; ++i) {
            var row = backend.logs[i]
            if (levelFilter === 0 || row.level === levels[levelFilter - 1]) out.push(row)
        }
        filtered = out
    }
    Connections {
        target: backend
        function onLogsChanged() { page.refreshFiltered() }
    }
    Component.onCompleted: refreshFiltered()

    ColumnLayout {
        anchors.fill: parent
        anchors.margins: 20
        spacing: 12

        Card {
            Layout.fillWidth: true
            title: qsTr("Журнал службы")
            RowLayout {
                Layout.fillWidth: true
                Text {
                    Layout.fillWidth: true
                    text: qsTr("Только журнал mutekizu.service, ограниченный объём. Payload, ClientHello и история сайтов не логируются.")
                    color: Theme.muted; font.family: Theme.font; font.pixelSize: 12
                    wrapMode: Text.WordWrap
                }
                ComboBox {
                    model: [qsTr("Все"), qsTr("Ошибки"), qsTr("Предупреждения"), qsTr("Информация"), qsTr("Отладка")]
                    onActivated: { page.levelFilter = index; page.refreshFiltered() }
                }
                Button {
                    text: backend.logPaused ? qsTr("Продолжить") : qsTr("Пауза")
                    font.family: Theme.font
                    onClicked: backend.setLogPaused(!backend.logPaused)
                }
                Button {
                    text: qsTr("Обновить")
                    font.family: Theme.font
                    enabled: !backend.logPaused
                    onClicked: backend.refreshLogs()
                }
            }
            Text {
                Layout.fillWidth: true
                visible: backend.journalError.length > 0
                text: backend.journalError
                color: Theme.err; font.family: Theme.font; font.pixelSize: 12
                wrapMode: Text.WordWrap
            }
            Text {
                Layout.fillWidth: true
                visible: backend.logPaused
                text: qsTr("Обновление приостановлено.")
                color: Theme.warn; font.family: Theme.font; font.pixelSize: 12
            }
        }

        Card {
            Layout.fillWidth: true
            Layout.fillHeight: true
            title: qsTr("События (%1)").arg(page.filtered.length)
            ListView {
                id: list
                Layout.fillWidth: true
                Layout.fillHeight: true
                clip: true
                model: page.filtered
                ScrollBar.vertical: ScrollBar { }
                delegate: RowLayout {
                    width: list.width
                    spacing: 10
                    Text {
                        text: modelData.time
                        color: Theme.muted; font.family: "monospace"; font.pixelSize: 11
                        Layout.preferredWidth: 160
                    }
                    Text {
                        text: modelData.level
                        color: modelData.level === "error" ? Theme.err
                               : modelData.level === "warn" ? Theme.warn
                               : modelData.level === "debug" ? Theme.unknown : Theme.ok
                        font.family: Theme.font; font.pixelSize: 11; font.weight: Font.DemiBold
                        Layout.preferredWidth: 70
                    }
                    Text {
                        Layout.fillWidth: true
                        text: modelData.text
                        color: Theme.text; font.family: "monospace"; font.pixelSize: 11
                        wrapMode: Text.WrapAnywhere
                    }
                }
                Text {
                    anchors.centerIn: parent
                    visible: page.filtered.length === 0
                    text: backend.journalError.length > 0 ? qsTr("Журнал недоступен.")
                                                          : qsTr("Нет событий для выбранного фильтра.")
                    color: Theme.muted; font.family: Theme.font
                }
            }
            RowLayout {
                Layout.fillWidth: true
                Button {
                    text: qsTr("Копировать")
                    font.family: Theme.font
                    onClicked: {
                        var text = ""
                        for (var i = 0; i < page.filtered.length; ++i)
                            text += page.filtered[i].time + " " + page.filtered[i].level + " " + page.filtered[i].text + "\n"
                        clip.text = text
                        clip.selectAll()
                        clip.copy()
                    }
                }
                Button {
                    text: qsTr("Экспорт…")
                    font.family: Theme.font
                    onClicked: exportDialog.open()
                }
                Item { Layout.fillWidth: true }
            }
        }
    }

    TextArea {
        id: clip
        visible: false
        width: 10
        height: 10
    }

    Dialog {
        id: exportDialog
        title: qsTr("Экспорт журнала")
        modal: true
        anchors.centerIn: Overlay.overlay
        width: Math.min(600, page.width - 60)
        standardButtons: Dialog.Cancel | Dialog.Ok
        onAccepted: {
            var text = ""
            for (var i = 0; i < page.filtered.length; ++i)
                text += page.filtered[i].time + " " + page.filtered[i].level + " " + page.filtered[i].text + "\n"
            backend.exportText(pathField.text, text)
        }
        ColumnLayout {
            width: parent.width
            TextField {
                id: pathField
                Layout.fillWidth: true
                text: "~/mutekizu-journal.txt"
                font.family: Theme.font
            }
            Text {
                Layout.fillWidth: true
                text: qsTr("Экспортируется только отфильтрованный журнал службы.")
                color: Theme.muted; font.family: Theme.font; font.pixelSize: 11
            }
        }
    }
}
