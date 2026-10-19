import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import Mutekizu

Item {
    id: page
    signal navigate(int pageIndex)

    ScrollView {
        anchors.fill: parent
        anchors.margins: 20
        clip: true
        ColumnLayout {
            width: page.width - 40
            spacing: 14

            Card {
                Layout.fillWidth: true
                title: qsTr("Служба")
                subtitle: backend.demo ? qsTr("ДЕМО") : ""
                RowLayout {
                    Layout.fillWidth: true
                    ColumnLayout {
                        Layout.fillWidth: true
                        Layout.alignment: Qt.AlignTop
                        spacing: 4
                        StatusBadge {
                            level: backend.state === "running" ? "ok"
                                   : backend.state === "failed" ? "fail"
                                   : backend.state === "starting" || backend.state === "stopping" ? "warn"
                                   : "unknown"
                            text: backend.stateText
                        }
                        Text {
                            text: qsTr("Активные режимы: %1").arg(backend.activeModes)
                            color: Theme.text
                            font.family: Theme.font
                            font.pixelSize: 13
                            wrapMode: Text.WordWrap
                            Layout.fillWidth: true
                        }
                        Text {
                            text: backend.installed
                                  ? qsTr("Управление службой идёт через systemd D-Bus; авторизацию выполняет Polkit.")
                                  : qsTr("Служба не установлена. Установите пакет/юнит движка, затем обновите состояние.")
                            color: Theme.muted
                            font.family: Theme.font
                            font.pixelSize: 12
                            wrapMode: Text.WordWrap
                            Layout.fillWidth: true
                        }
                    }
                    ColumnLayout {
                        Layout.alignment: Qt.AlignTop
                        spacing: 8
                        Button {
                            text: qsTr("Запустить")
                            highlighted: true
                            font.family: Theme.font
                            enabled: backend.installed && !backend.busy
                                     && (backend.state === "stopped" || backend.state === "failed")
                            onClicked: backend.startService()
                        }
                        Button {
                            text: qsTr("Остановить")
                            highlighted: true
                            font.family: Theme.font
                            enabled: backend.installed && !backend.busy
                                     && (backend.state === "running" || backend.state === "starting")
                            onClicked: backend.stopService()
                        }
                        Button {
                            text: qsTr("Перезапустить")
                            font.family: Theme.font
                            enabled: backend.installed && !backend.busy && backend.state === "running"
                            onClicked: backend.restartService()
                        }
                    }
                }
                Text {
                    visible: backend.busy
                    text: qsTr("Выполняется операция…")
                    color: Theme.warn
                    font.family: Theme.font
                    font.pixelSize: 12
                }
            }

            Card {
                Layout.fillWidth: true
                title: qsTr("Изменения")
                RowLayout {
                    Layout.fillWidth: true
                    StatusBadge {
                        level: backend.dirty ? "warn" : "ok"
                        text: backend.dirty ? qsTr("Есть неприменённые изменения")
                                            : qsTr("Черновик совпадает с сохранённой конфигурацией")
                    }
                    Item { Layout.fillWidth: true }
                    Button {
                        text: qsTr("Перечитать с диска")
                        font.family: Theme.font
                        onClicked: backend.reloadFromDisk()
                    }
                }
                Text {
                    visible: backend.conflict
                    text: qsTr("Файлы изменены извне. Перечитайте конфигурацию перед применением.")
                    color: Theme.err
                    font.family: Theme.font
                    font.pixelSize: 12
                    wrapMode: Text.WordWrap
                    Layout.fillWidth: true
                }
            }

            Card {
                Layout.fillWidth: true
                title: qsTr("Диагностика")
                RowLayout {
                    Layout.fillWidth: true
                    Text {
                        Layout.fillWidth: true
                        text: {
                            if (backend.diagnostics.length === 0)
                                return qsTr("Диагностика ещё не запускалась.")
                            var c = {ok: 0, warn: 0, fail: 0, unknown: 0}
                            for (var i = 0; i < backend.diagnostics.length; ++i) {
                                var l = backend.diagnostics[i].level
                                if (c[l] === undefined) l = "unknown"
                                c[l] += 1
                            }
                            return qsTr("OK: %1 · предупреждений: %2 · ошибок: %3 · не проверено: %4")
                                     .arg(c.ok).arg(c.warn).arg(c.fail).arg(c.unknown)
                        }
                        color: Theme.text
                        font.family: Theme.font
                        font.pixelSize: 13
                        wrapMode: Text.WordWrap
                    }
                    Button {
                        text: qsTr("Открыть диагностику")
                        font.family: Theme.font
                        onClicked: page.navigate(3)
                    }
                    Button {
                        text: qsTr("Проверить")
                        font.family: Theme.font
                        enabled: !backend.busy
                        onClicked: backend.runDoctor()
                    }
                }
            }

            Card {
                Layout.fillWidth: true
                visible: backend.lastError.length > 0
                title: qsTr("Последняя ошибка")
                Text {
                    Layout.fillWidth: true
                    text: backend.lastError
                    color: Theme.err
                    font.family: Theme.font
                    font.pixelSize: 13
                    wrapMode: Text.WordWrap
                }
                Text {
                    Layout.fillWidth: true
                    visible: backend.lastErrorHint.length > 0
                    text: backend.lastErrorHint
                    color: Theme.muted
                    font.family: Theme.font
                    font.pixelSize: 12
                    wrapMode: Text.WordWrap
                }
            }

            Text {
                Layout.fillWidth: true
                text: qsTr("«Работает» означает, что процесс службы активен, а не что конкретный сайт доступен. Доступность зависит от вида фильтрации.")
                color: Theme.muted
                font.family: Theme.font
                font.pixelSize: 12
                wrapMode: Text.WordWrap
            }
        }
    }
}
