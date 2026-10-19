import QtQuick
import QtQuick.Controls
import QtQuick.Controls.Material
import QtQuick.Layouts
import QtQuick.Window
import Mutekizu

ApplicationWindow {
    id: root
    width: initialWidth > 0 ? initialWidth : 1220
    height: initialHeight > 0 ? initialHeight : 820
    minimumWidth: 760
    minimumHeight: 620
    visible: true
    title: qsTr("%1 — локальная настройка TCP/TLS").arg(brandName)
    color: Theme.bg

    property int pageIndex: 0
    property var pageTitles: [
        qsTr("Обзор"), qsTr("Домены"), qsTr("Профили"), qsTr("Настройки"),
        qsTr("Диагностика"), qsTr("Журнал"), qsTr("О программе")
    ]

    function pageFromName(name) {
        var keys = ["overview", "domains", "profiles", "settings", "diagnostics", "logs", "about"]
        var i = keys.indexOf(name)
        return i >= 0 ? i : 0
    }

    Material.theme: Theme.dark ? Material.Dark : Material.Light
    Material.accent: Theme.accent
    Material.primary: Theme.surface
    Material.background: Theme.surface
    Material.foreground: Theme.text

    Component.onCompleted: {
        pageIndex = pageFromName(initialPage)
        if (initialTheme === "dark") Theme.dark = true
        else if (initialTheme === "light") Theme.dark = false
        else Theme.dark = demoMode ? true : backend.systemDark
    }

    Shortcut { sequence: "Alt+1"; onActivated: root.pageIndex = 0 }
    Shortcut { sequence: "Alt+2"; onActivated: root.pageIndex = 1 }
    Shortcut { sequence: "Alt+3"; onActivated: root.pageIndex = 2 }
    Shortcut { sequence: "Alt+4"; onActivated: root.pageIndex = 3 }
    Shortcut { sequence: "Alt+5"; onActivated: root.pageIndex = 4 }
    Shortcut { sequence: "Alt+6"; onActivated: root.pageIndex = 5 }
    Shortcut { sequence: "Alt+7"; onActivated: root.pageIndex = 6 }

    header: Rectangle {
        color: Theme.surface
        implicitHeight: 64
        border.color: Theme.border
        border.width: 0

        RowLayout {
            anchors.fill: parent
            anchors.leftMargin: 20
            anchors.rightMargin: 20
            spacing: 14

            ColumnLayout {
                spacing: 0
                Text {
                    text: brandName
                    color: Theme.text
                    font.family: Theme.font
                    font.pixelSize: 18
                    font.weight: Font.Bold
                }
                Text {
                    text: qsTr("Локальная настройка TCP/TLS · без VPN и прокси")
                    color: Theme.muted
                    font.family: Theme.font
                    font.pixelSize: 11
                }
            }
            Item { Layout.fillWidth: true }
            StatusBadge {
                level: backend.state === "running" ? "ok"
                       : backend.state === "failed" ? "fail"
                       : backend.state === "starting" || backend.state === "stopping" ? "warn"
                       : backend.state === "not-installed" || backend.state === "unavailable" ? "unknown" : "unknown"
                text: backend.stateText
            }
            Rectangle {
                visible: demoMode
                color: Qt.rgba(Theme.warn.r, Theme.warn.g, Theme.warn.b, 0.14)
                border.color: Theme.warn
                radius: 8
                implicitWidth: demoLabel.implicitWidth + 18
                implicitHeight: 30
                Text {
                    id: demoLabel
                    anchors.centerIn: parent
                    text: qsTr("ДЕМО · данные имитируются")
                    color: Theme.warn
                    font.family: Theme.font
                    font.pixelSize: 11
                    font.weight: Font.DemiBold
                }
            }
        }
    }

    footer: Rectangle {
        color: Theme.surface
        implicitHeight: 34
        Text {
            anchors.centerIn: parent
            text: qsTr("Прямое соединение. IP не меняется. Доступность зависит от фильтрации.")
            color: Theme.muted
            font.family: Theme.font
            font.pixelSize: 11
        }
    }

    ColumnLayout {
        anchors.fill: parent
        spacing: 0

        TabBar {
            id: narrowTabs
            visible: root.width < 980
            Layout.fillWidth: true
            currentIndex: root.pageIndex
            onCurrentIndexChanged: root.pageIndex = currentIndex
            Repeater {
                model: root.pageTitles
                TabButton {
                    text: modelData
                    font.family: Theme.font
                }
            }
        }

        RowLayout {
            Layout.fillWidth: true
            Layout.fillHeight: true
            spacing: 0

            Rectangle {
                visible: root.width >= 980
                Layout.preferredWidth: 210
                Layout.fillHeight: true
                color: Theme.surface
                ColumnLayout {
                    anchors.fill: parent
                    anchors.margins: 12
                    spacing: 6
                    Repeater {
                        model: root.pageTitles
                        NavButton {
                            Layout.fillWidth: true
                            text: (["◉ ", "⌁ ", "▤ ", "⚙ ", "✓ ", "☰ ", "ⓘ "][index]) + modelData
                            checked: root.pageIndex === index
                            onClicked: root.pageIndex = index
                        }
                    }
                    Item { Layout.fillHeight: true }
                    Text {
                        text: qsTr("Служба:\n%1").arg(backend.stateText)
                        color: Theme.muted
                        font.family: Theme.font
                        font.pixelSize: 11
                        wrapMode: Text.WordWrap
                    }
                }
            }

            StackLayout {
                Layout.fillWidth: true
                Layout.fillHeight: true
                currentIndex: root.pageIndex

                OverviewPage { onNavigate: root.pageIndex = pageIndex }
                DomainsPage { }
                ProfilesPage { }
                SettingsPage { }
                DiagnosticsPage { }
                LogsPage { }
                AboutPage { }
            }
        }

        Rectangle {
            visible: backend.dirty
            Layout.fillWidth: true
            implicitHeight: 58
            color: Theme.surface2
            border.color: Theme.border
            RowLayout {
                anchors.fill: parent
                anchors.leftMargin: 20
                anchors.rightMargin: 20
                Text {
                    text: qsTr("Есть неприменённые изменения")
                    color: Theme.warn
                    font.family: Theme.font
                    font.pixelSize: 13
                    font.weight: Font.DemiBold
                    Layout.fillWidth: true
                }
                Button {
                    text: qsTr("Отменить правки")
                    font.family: Theme.font
                    onClicked: backend.revertDraft()
                }
                Button {
                    text: qsTr("Проверить и применить")
                    font.family: Theme.font
                    highlighted: true
                    onClicked: applyDialog.open()
                }
            }
        }
    }

    Dialog {
        id: applyDialog
        title: qsTr("Проверить и применить")
        modal: true
        anchors.centerIn: Overlay.overlay
        width: Math.min(760, root.width - 80)
        standardButtons: Dialog.NoButton
        onOpened: {
            diffArea.text = backend.diffText()
            validation.text = backend.validateDraft()
        }
        ColumnLayout {
            width: parent.width
            spacing: 10
            Text {
                text: qsTr("Изменения в конфигурации")
                color: Theme.text
                font.family: Theme.font
                font.pixelSize: 14
                font.weight: Font.DemiBold
            }
            ScrollView {
                Layout.fillWidth: true
                Layout.preferredHeight: 210
                TextArea {
                    id: diffArea
                    readOnly: true
                    selectByMouse: true
                    wrapMode: TextArea.Wrap
                    font.family: "monospace"
                    font.pixelSize: 12
                    color: Theme.text
                    background: Rectangle { color: Theme.surface2; radius: 8 }
                }
            }
            Text {
                id: validation
                Layout.fillWidth: true
                wrapMode: Text.WordWrap
                color: text.length > 0 ? Theme.err : Theme.ok
                font.family: Theme.font
                font.pixelSize: 12
            }
            Text {
                text: qsTr("Для запущенной службы потребуется перезапуск. DNS и QUIC не изменяются.")
                color: Theme.muted
                font.family: Theme.font
                font.pixelSize: 12
                wrapMode: Text.WordWrap
                Layout.fillWidth: true
            }
            Text {
                visible: demoMode
                text: qsTr("ДЕМО: изменения не попадут в систему.")
                color: Theme.warn
                font.family: Theme.font
                font.pixelSize: 12
            }
            Text {
                text: backend.applyMessage
                visible: text.length > 0
                color: Theme.muted
                font.family: Theme.font
                font.pixelSize: 12
                wrapMode: Text.WordWrap
                Layout.fillWidth: true
            }
            RowLayout {
                Layout.fillWidth: true
                Item { Layout.fillWidth: true }
                Button {
                    text: qsTr("Отмена")
                    font.family: Theme.font
                    enabled: !backend.applyRunning
                    onClicked: applyDialog.close()
                }
                Button {
                    text: qsTr("Отменить применение")
                    font.family: Theme.font
                    visible: backend.applyRunning
                    onClicked: backend.cancelApply()
                }
                Button {
                    text: backend.applyRunning ? qsTr("Применяется…") : qsTr("Применить")
                    font.family: Theme.font
                    highlighted: true
                    enabled: !backend.applyRunning && validation.text.length === 0
                    onClicked: backend.applyDraft()
                }
            }
        }
    }
}
