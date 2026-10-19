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
                title: qsTr("О программе")
                Text {
                    Layout.fillWidth: true
                    text: qsTr("%1 %2\nGUI для локального anti-DPI. Прямое соединение, без VPN, прокси и туннеля. TLS остаётся сквозным: без MITM и подмены сертификатов.").arg(brandName).arg(appVersion)
                    color: Theme.text; font.family: Theme.font; font.pixelSize: 13
                    wrapMode: Text.WordWrap
                }
                Text {
                    Layout.fillWidth: true
                    text: qsTr("Движок: %1\nРежим: %2").arg(backend.engineVersion).arg(backend.demo ? qsTr("ДЕМО (имитация)") : qsTr("реальная система"))
                    color: Theme.muted; font.family: Theme.font; font.pixelSize: 12
                    wrapMode: Text.WordWrap
                }
            }

        }
    }
}
