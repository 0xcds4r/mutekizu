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

            Card {
                Layout.fillWidth: true
                title: qsTr("Ограничения")
                Text {
                    Layout.fillWidth: true
                    text: qsTr("• Эффективность зависит от вида фильтрации.\n• Полноценная сборка TCP/TLS может нейтрализовать разделение сегментов.\n• IP-блокировки, DNS-подмена и блокировка QUIC этим инструментом не решаются.\n• Доступность страницы YouTube не доказывает работу видео (нужен googlevideo.com).\n• Доступность одного домена Discord не доказывает работу приложения (gateway/CDN).\n• Утилита не обеспечивает анонимность и не скрывает IP назначения.\n• «Служба работает» не означает «сайт доступен».
• Закрытие окна GUI не останавливает отдельно работающую службу.")
                    color: Theme.text; font.family: Theme.font; font.pixelSize: 12
                    wrapMode: Text.WordWrap
                    lineHeight: 1.25
                }
            }

            Card {
                Layout.fillWidth: true
                title: qsTr("Исторические результаты тестов")
                Text {
                    Layout.fillWidth: true
                    text: qsTr("Источник: tests/arena/results/REPORT.md и tests/real_tspu/REPORT.md, 2026-10-20.\n\nСинтетическая лестница DPI: L1/L2 (без сборки TCP) обходились split; L4/L5 (полная сборка TCP + TLS/SNI) блокировали все проверенные стратегии. 28/28 проверок стенда.\n\nРеальный путь (zapret выключен, curl, малые выборки): rutracker 4/14 ≈ 29%; x.com, www.youtube.com, gateway.discord.gg — по 1/5; суммарно 7/34 ≈ 21%; baseline 0/46. Это не прогноз и не текущий индикатор: другие сети, время и клиенты могут дать другой результат.")
                    color: Theme.text; font.family: Theme.font; font.pixelSize: 12
                    wrapMode: Text.WordWrap
                    lineHeight: 1.2
                }
                Text {
                    Layout.fillWidth: true
                    text: qsTr("Проценты приведены вместе с размером выборки и условиями. Не используйте их как обещание обхода.")
                    color: Theme.warn; font.family: Theme.font; font.pixelSize: 11
                    wrapMode: Text.WordWrap
                }
            }

            Card {
                Layout.fillWidth: true
                title: qsTr("Приватность")
                Text {
                    Layout.fillWidth: true
                    text: qsTr("GUI не запрашивает и не хранит пароль sudo. Привилегированные операции: systemd D-Bus (Polkit) и узкий helper через pkexec. Журнал ограничен службой; содержимое соединений и TLS ClientHello не логируется.")
                    color: Theme.muted; font.family: Theme.font; font.pixelSize: 12
                    wrapMode: Text.WordWrap
                }
            }
        }
    }
}
