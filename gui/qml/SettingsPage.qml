import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import Mutekizu

Item {
    id: page
    function setInt(key, value) { backend.setSetting(key, value) }
    function removeTarget(index) {
        var list = backend.draftMssTargets.slice()
        list.splice(index, 1)
        backend.setMssTargets(list)
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
                title: qsTr("Режимы")
                RowLayout {
                    Layout.fillWidth: true
                    ColumnLayout {
                        Layout.fillWidth: true
                        Text { text: qsTr("SNI-splitter"); color: Theme.text; font.family: Theme.font; font.pixelSize: 14 }
                        Text {
                            text: qsTr("Разбивает TCP payload ClientHello для выбранных SNI. Требует NFQUEUE.")
                            color: Theme.muted; font.family: Theme.font; font.pixelSize: 12
                            wrapMode: Text.WordWrap; Layout.fillWidth: true
                        }
                    }
                    Switch {
                        Material.accent: Theme.accent
                        checked: backend.draft["split_enabled"] === true
                        onToggled: backend.setSetting("split_enabled", checked)
                    }
                }
                RowLayout {
                    Layout.fillWidth: true
                    ColumnLayout {
                        Layout.fillWidth: true
                        Text { text: qsTr("MSS-clamp по IP"); color: Theme.text; font.family: Theme.font; font.pixelSize: 14 }
                        Text {
                            text: qsTr("Уменьшает MSS в SYN-ACK для явных IPv4/IPv6. Влияет на весь upload-поток, может затронуть несколько сайтов на общем IP.")
                            color: Theme.muted; font.family: Theme.font; font.pixelSize: 12
                            wrapMode: Text.WordWrap; Layout.fillWidth: true
                        }
                    }
                    Switch {
                        Material.accent: Theme.accent
                        checked: backend.draft["mss_clamp"] === true
                        onToggled: backend.setSetting("mss_clamp", checked)
                    }
                }
                RowLayout {
                    Layout.fillWidth: true
                    Text {
                        Layout.fillWidth: true
                        text: qsTr("Текущее разделение: %1").arg(backend.activeModes)
                        color: Theme.text; font.family: Theme.font; font.pixelSize: 13
                        wrapMode: Text.WordWrap
                    }
                    Button {
                        text: qsTr("IP-цели MSS…")
                        font.family: Theme.font
                        onClicked: mssDialog.open()
                    }
                }
            }

            Card {
                Layout.fillWidth: true
                title: qsTr("Оформление")
                RowLayout {
                    Layout.fillWidth: true
                    Text { text: qsTr("Тема"); color: Theme.text; font.family: Theme.font; Layout.fillWidth: true }
                    ComboBox {
                        id: themeCombo
                        model: [qsTr("Системная"), qsTr("Тёмная"), qsTr("Светлая")]
                        Component.onCompleted: Qt.callLater(function() {
                            currentIndex = Theme.dark ? 1 : 2
                        })
                        Connections {
                            target: Theme
                            function onDarkChanged() { themeCombo.currentIndex = Theme.dark ? 1 : 2 }
                        }
                        onActivated: {
                            if (index === 0) Theme.dark = backend.systemDark
                            else Theme.dark = (index === 1)
                        }
                    }
                }
            }

            Card {
                Layout.fillWidth: true
                title: qsTr("Расширенные параметры")
                Text {
                    Layout.fillWidth: true
                    text: qsTr("Значения взяты из текущей конфигурации backend. Диапазоны проверяются до применения.")
                    color: Theme.muted; font.family: Theme.font; font.pixelSize: 12
                    wrapMode: Text.WordWrap
                }

                GridLayout {
                    Layout.fillWidth: true
                    columns: 3
                    columnSpacing: 12
                    rowSpacing: 8

                    Text { text: qsTr("split_delta"); color: Theme.text; font.family: Theme.font }
                    SpinBox {
                        from: 1; to: 200
                        value: backend.draft["split_delta"] ?? 4
                        onValueModified: page.setInt("split_delta", value)
                    }
                    Text { text: qsTr("Байт внутрь SNI; должно оставаться внутри имени."); color: Theme.muted; font.family: Theme.font; font.pixelSize: 11; Layout.fillWidth: true; wrapMode: Text.WordWrap }

                    Text { text: qsTr("split_stride"); color: Theme.text; font.family: Theme.font }
                    SpinBox {
                        from: 0; to: 64
                        value: backend.draft["split_stride"] ?? 4
                        onValueModified: page.setInt("split_stride", value)
                    }
                    Text { text: qsTr("0 — один разрыв; >0 — границы каждые N байт по SNI. Больше сегментов и нагрузки."); color: Theme.muted; font.family: Theme.font; font.pixelSize: 11; Layout.fillWidth: true; wrapMode: Text.WordWrap }

                    Text { text: qsTr("split_max"); color: Theme.text; font.family: Theme.font }
                    SpinBox {
                        from: 1; to: 128
                        value: backend.draft["split_max"] ?? 64
                        onValueModified: page.setInt("split_max", value)
                    }
                    Text { text: qsTr("Верхняя граница числа границ multi-split."); color: Theme.muted; font.family: Theme.font; font.pixelSize: 11; Layout.fillWidth: true; wrapMode: Text.WordWrap }

                    Text { text: qsTr("split_gap_ms"); color: Theme.warn; font.family: Theme.font }
                    SpinBox {
                        from: 0; to: 100
                        value: backend.draft["split_gap_ms"] ?? 0
                        onValueModified: page.setInt("split_gap_ms", value)
                    }
                    Text { text: qsTr("ЭКСПЕРИМЕНТАЛЬНО. Пауза между raw-сегментами. Улучшение не доказано; в реальном тесте gap 0 был лучшим."); color: Theme.warn; font.family: Theme.font; font.pixelSize: 11; Layout.fillWidth: true; wrapMode: Text.WordWrap }

                    Text { text: qsTr("split_disorder"); color: Theme.text; font.family: Theme.font }
                    Switch {
                        Material.accent: Theme.accent
                        checked: backend.draft["split_disorder"] === true
                        onToggled: backend.setSetting("split_disorder", checked)
                    }
                    Text { text: qsTr("Отправлять сегменты ClientHello в обратном порядке. Сервер склеит по TCP seq, DPI увидит перемешанный поток."); color: Theme.muted; font.family: Theme.font; font.pixelSize: 11; Layout.fillWidth: true; wrapMode: Text.WordWrap }

                    Text { text: qsTr("split_multidisorder"); color: Theme.text; font.family: Theme.font }
                    Switch {
                        Material.accent: Theme.accent
                        checked: backend.draft["split_multidisorder"] === true
                        onToggled: backend.setSetting("split_multidisorder", checked)
                    }
                    Text { text: qsTr("Перемешать сегменты «снаружи внутрь» (последний, первый, предпоследний…). Сервер соберёт по seq, DPI увидит хаос."); color: Theme.muted; font.family: Theme.font; font.pixelSize: 11; Layout.fillWidth: true; wrapMode: Text.WordWrap }

                    Text { text: qsTr("split_jitter_ms"); color: Theme.warn; font.family: Theme.font }
                    SpinBox {
                        from: 0; to: 50
                        value: backend.draft["split_jitter_ms"] ?? 0
                        onValueModified: page.setInt("split_jitter_ms", value)
                    }
                    Text { text: qsTr("Случайная дополнительная пауза между сегментами. Может усилить disorder, но замедляет handshake."); color: Theme.warn; font.family: Theme.font; font.pixelSize: 11; Layout.fillWidth: true; wrapMode: Text.WordWrap }

                    Text { text: qsTr("seqovl_enabled"); color: Theme.warn; font.family: Theme.font }
                    Switch {
                        Material.accent: Theme.accent
                        checked: backend.draft["seqovl_enabled"] === true
                        onToggled: backend.setSetting("seqovl_enabled", checked)
                    }
                    Text { text: qsTr("Отправить low-TTL сегмент с sequence overlap. DPI видит наложение, сервер не получает fake. Экспериментально."); color: Theme.warn; font.family: Theme.font; font.pixelSize: 11; Layout.fillWidth: true; wrapMode: Text.WordWrap }

                    Text { text: qsTr("seqovl_bytes"); color: Theme.text; font.family: Theme.font }
                    SpinBox {
                        from: 1; to: 1400
                        value: backend.draft["seqovl_bytes"] ?? 664
                        onValueModified: page.setInt("seqovl_bytes", value)
                    }
                    Text { text: qsTr("На сколько байт sequence fake уходит назад."); color: Theme.muted; font.family: Theme.font; font.pixelSize: 11; Layout.fillWidth: true; wrapMode: Text.WordWrap }

                    Text { text: qsTr("seqovl_repeats"); color: Theme.text; font.family: Theme.font }
                    SpinBox {
                        from: 1; to: 16
                        value: backend.draft["seqovl_repeats"] ?? 1
                        onValueModified: page.setInt("seqovl_repeats", value)
                    }
                    Text { text: qsTr("Сколько раз отправить overlapping fake."); color: Theme.muted; font.family: Theme.font; font.pixelSize: 11; Layout.fillWidth: true; wrapMode: Text.WordWrap }

                    Text { text: qsTr("udp_fake_enabled"); color: Theme.warn; font.family: Theme.font }
                    Switch {
                        Material.accent: Theme.accent
                        checked: backend.draft["udp_fake_enabled"] === true
                        onToggled: backend.setSetting("udp_fake_enabled", checked)
                    }
                    Text { text: qsTr("Fake STUN для Discord RTC/voice: UDP 19294-19344, 50000-50100, 443. Низкий TTL. Нужен для голоса."); color: Theme.warn; font.family: Theme.font; font.pixelSize: 11; Layout.fillWidth: true; wrapMode: Text.WordWrap }

                    Text { text: qsTr("udp_fake_ttl"); color: Theme.text; font.family: Theme.font }
                    SpinBox {
                        from: 1; to: 64
                        value: backend.draft["udp_fake_ttl"] ?? 3
                        onValueModified: page.setInt("udp_fake_ttl", value)
                    }
                    Text { text: qsTr("TTL/hop limit fake UDP."); color: Theme.muted; font.family: Theme.font; font.pixelSize: 11; Layout.fillWidth: true; wrapMode: Text.WordWrap }

                    Text { text: qsTr("udp_fake_repeats"); color: Theme.text; font.family: Theme.font }
                    SpinBox {
                        from: 1; to: 16
                        value: backend.draft["udp_fake_repeats"] ?? 3
                        onValueModified: page.setInt("udp_fake_repeats", value)
                    }
                    Text { text: qsTr("Сколько fake STUN отправить на каждый UDP-пакет."); color: Theme.muted; font.family: Theme.font; font.pixelSize: 11; Layout.fillWidth: true; wrapMode: Text.WordWrap }

                    Text { text: qsTr("fake_enabled"); color: Theme.warn; font.family: Theme.font }
                    Switch {
                        Material.accent: Theme.accent
                        checked: backend.draft["fake_enabled"] === true
                        onToggled: backend.setSetting("fake_enabled", checked)
                    }
                    Text { text: qsTr("Перед настоящим ClientHello отправить fake с низким TTL и чужим SNI. DPI видит fake, сервер — нет. Экспериментально."); color: Theme.warn; font.family: Theme.font; font.pixelSize: 11; Layout.fillWidth: true; wrapMode: Text.WordWrap }

                    Text { text: qsTr("fake_ttl"); color: Theme.text; font.family: Theme.font }
                    SpinBox {
                        from: 1; to: 64
                        value: backend.draft["fake_ttl"] ?? 3
                        onValueModified: page.setInt("fake_ttl", value)
                    }
                    Text { text: qsTr("TTL/hop limit fake-пакета. Должен истечь до сервера, но после DPI."); color: Theme.muted; font.family: Theme.font; font.pixelSize: 11; Layout.fillWidth: true; wrapMode: Text.WordWrap }

                    Text { text: qsTr("fake_repeats"); color: Theme.text; font.family: Theme.font }
                    SpinBox {
                        from: 1; to: 16
                        value: backend.draft["fake_repeats"] ?? 3
                        onValueModified: page.setInt("fake_repeats", value)
                    }
                    Text { text: qsTr("Сколько fake-пакетов отправить."); color: Theme.muted; font.family: Theme.font; font.pixelSize: 11; Layout.fillWidth: true; wrapMode: Text.WordWrap }

                    Text { text: qsTr("fake_sni"); color: Theme.text; font.family: Theme.font }
                    TextField {
                        Layout.fillWidth: false
                        implicitWidth: 220
                        text: backend.draft["fake_sni"] ?? "www.google.com"
                        font.family: Theme.font
                        onEditingFinished: backend.setSetting("fake_sni", text)
                    }
                    Text { text: qsTr("SNI внутри fake ClientHello (например, www.google.com)."); color: Theme.muted; font.family: Theme.font; font.pixelSize: 11; Layout.fillWidth: true; wrapMode: Text.WordWrap }

                    Text { text: qsTr("mss (кусок)"); color: Theme.text; font.family: Theme.font }
                    SpinBox {
                        from: 200; to: 9000
                        value: backend.draft["mss"] ?? 1200
                        onValueModified: page.setInt("mss", value)
                    }
                    Text { text: qsTr("Размер payload нового сегмента. Это НЕ режим MSS-clamp."); color: Theme.muted; font.family: Theme.font; font.pixelSize: 11; Layout.fillWidth: true; wrapMode: Text.WordWrap }

                    Text { text: qsTr("mss_value"); color: Theme.text; font.family: Theme.font }
                    SpinBox {
                        from: 88; to: 536
                        value: backend.draft["mss_value"] ?? 96
                        onValueModified: page.setInt("mss_value", value)
                    }
                    Text { text: qsTr("Значение MSS для SYN-ACK (только при MSS-clamp)."); color: Theme.muted; font.family: Theme.font; font.pixelSize: 11; Layout.fillWidth: true; wrapMode: Text.WordWrap }

                    Text { text: qsTr("inspect_packets"); color: Theme.text; font.family: Theme.font }
                    SpinBox {
                        from: 1; to: 64
                        value: backend.draft["inspect_packets"] ?? 10
                        onValueModified: page.setInt("inspect_packets", value)
                    }
                    Text { text: qsTr("Сколько первых пакетов original-направления попадает в NFQUEUE."); color: Theme.muted; font.family: Theme.font; font.pixelSize: 11; Layout.fillWidth: true; wrapMode: Text.WordWrap }

                    Text { text: qsTr("queue_num"); color: Theme.text; font.family: Theme.font }
                    SpinBox {
                        from: 1; to: 65535
                        value: backend.draft["queue_num"] ?? 2000
                        onValueModified: page.setInt("queue_num", value)
                    }
                    Text { text: qsTr("Номер NFQUEUE; не должен конфликтовать с другими инструментами."); color: Theme.muted; font.family: Theme.font; font.pixelSize: 11; Layout.fillWidth: true; wrapMode: Text.WordWrap }

                    Text { text: qsTr("fwmark"); color: Theme.text; font.family: Theme.font }
                    TextField {
                        text: backend.draft["fwmark"] ?? ""
                        font.family: "monospace"
                        onEditingFinished: backend.setSetting("fwmark", text)
                    }
                    Text { text: qsTr("Метка raw-пакетов; проверяется конфликт с policy routing."); color: Theme.muted; font.family: Theme.font; font.pixelSize: 11; Layout.fillWidth: true; wrapMode: Text.WordWrap }

                    Text { text: qsTr("ports"); color: Theme.text; font.family: Theme.font }
                    TextField {
                        text: backend.draft["ports"] ?? "443"
                        font.family: "monospace"
                        onEditingFinished: backend.setSetting("ports", text)
                    }
                    Text { text: qsTr("Список TCP-портов через запятую."); color: Theme.muted; font.family: Theme.font; font.pixelSize: 11; Layout.fillWidth: true; wrapMode: Text.WordWrap }

                    Text { text: qsTr("max_queue_len"); color: Theme.text; font.family: Theme.font }
                    SpinBox { from: 1; to: 65535; value: backend.draft["max_queue_len"] ?? 256; onValueModified: page.setInt("max_queue_len", value) }
                    Text { text: qsTr("Максимальная длина очереди."); color: Theme.muted; font.family: Theme.font; font.pixelSize: 11; Layout.fillWidth: true; wrapMode: Text.WordWrap }

                    Text { text: qsTr("copy_range"); color: Theme.text; font.family: Theme.font }
                    SpinBox { from: 64; to: 65535; value: backend.draft["copy_range"] ?? 65535; onValueModified: page.setInt("copy_range", value) }
                    Text { text: qsTr("Сколько байт пакета копировать в userspace."); color: Theme.muted; font.family: Theme.font; font.pixelSize: 11; Layout.fillWidth: true; wrapMode: Text.WordWrap }

                    Text { text: qsTr("max_flows"); color: Theme.text; font.family: Theme.font }
                    SpinBox { from: 1; to: 65536; value: backend.draft["max_flows"] ?? 1024; onValueModified: page.setInt("max_flows", value) }
                    Text { text: qsTr("Предел числа flow-состояний в памяти."); color: Theme.muted; font.family: Theme.font; font.pixelSize: 11; Layout.fillWidth: true; wrapMode: Text.WordWrap }

                    Text { text: qsTr("flow_buffer"); color: Theme.text; font.family: Theme.font }
                    SpinBox { from: 512; to: 65535; value: backend.draft["flow_buffer"] ?? 8192; onValueModified: page.setInt("flow_buffer", value) }
                    Text { text: qsTr("Буфер сборки ClientHello на поток."); color: Theme.muted; font.family: Theme.font; font.pixelSize: 11; Layout.fillWidth: true; wrapMode: Text.WordWrap }

                    Text { text: qsTr("flow_timeout_s"); color: Theme.text; font.family: Theme.font }
                    SpinBox { from: 1; to: 3600; value: backend.draft["flow_timeout_s"] ?? 30; onValueModified: page.setInt("flow_timeout_s", value) }
                    Text { text: qsTr("Время жизни состояния потока."); color: Theme.muted; font.family: Theme.font; font.pixelSize: 11; Layout.fillWidth: true; wrapMode: Text.WordWrap }

                    Text { text: qsTr("log_level"); color: Theme.text; font.family: Theme.font }
                    ComboBox {
                        model: ["error", "warn", "info", "debug"]
                        currentIndex: Math.max(0, ["error", "warn", "info", "debug"].indexOf(backend.draft["log_level"]))
                        onActivated: backend.setSetting("log_level", model[index])
                    }
                    Text { text: qsTr("Уровень журнала службы."); color: Theme.muted; font.family: Theme.font; font.pixelSize: 11; Layout.fillWidth: true; wrapMode: Text.WordWrap }

                    Text { text: qsTr("IPv4 / IPv6"); color: Theme.text; font.family: Theme.font }
                    RowLayout {
                        Switch { checked: backend.draft["ipv4"] === true; onToggled: backend.setSetting("ipv4", checked) }
                        Text { text: "IPv4"; color: Theme.muted; font.family: Theme.font; font.pixelSize: 11 }
                        Switch { checked: backend.draft["ipv6"] === true; onToggled: backend.setSetting("ipv6", checked) }
                        Text { text: "IPv6"; color: Theme.muted; font.family: Theme.font; font.pixelSize: 11 }
                    }
                    Text { text: qsTr("Должен быть включён хотя бы один стек."); color: Theme.muted; font.family: Theme.font; font.pixelSize: 11; Layout.fillWidth: true; wrapMode: Text.WordWrap }

                    Text { text: qsTr("auto_profile"); color: Theme.text; font.family: Theme.font }
                    Switch {
                        Material.accent: Theme.accent
                        checked: backend.draft["auto_profile"] !== false
                        onToggled: backend.setSetting("auto_profile", checked)
                    }
                    Text { text: qsTr("Если несколько профилей в profiles.conf покрывают домен, при неудачной попытке переключаться на следующий. Успех = клиент отправил данные после ClientHello."); color: Theme.muted; font.family: Theme.font; font.pixelSize: 11; Layout.fillWidth: true; wrapMode: Text.WordWrap }

                    Text { text: qsTr("auto_retry_window_s"); color: Theme.text; font.family: Theme.font }
                    SpinBox {
                        from: 1; to: 300
                        value: backend.draft["auto_retry_window_s"] ?? 10
                        onValueModified: page.setInt("auto_retry_window_s", value)
                    }
                    Text { text: qsTr("Окно, в котором новый коннект к тому же SNI считается повтором после сбоя."); color: Theme.muted; font.family: Theme.font; font.pixelSize: 11; Layout.fillWidth: true; wrapMode: Text.WordWrap }

                    Text { text: qsTr("auto_discover"); color: Theme.text; font.family: Theme.font }
                    Switch {
                        Material.accent: Theme.accent
                        checked: backend.draft["auto_discover"] !== false
                        onToggled: backend.setSetting("auto_discover", checked)
                    }
                    Text { text: qsTr("Для неизвестного SNI один раз пробует прямой TLS-handshake (без split). Если ответа нет — запоминает домен и разрывает следующее соединение. Доп. соединение и раскрытие SNI тому же серверу."); color: Theme.muted; font.family: Theme.font; font.pixelSize: 11; Layout.fillWidth: true; wrapMode: Text.WordWrap }

                    Text { text: qsTr("log_sni"); color: Theme.text; font.family: Theme.font }
                    Switch { checked: backend.draft["log_sni"] === true; onToggled: backend.setSetting("log_sni", checked) }
                    Text { text: qsTr("Писать совпавший hostname в journal. По умолчанию выключено."); color: Theme.muted; font.family: Theme.font; font.pixelSize: 11; Layout.fillWidth: true; wrapMode: Text.WordWrap }
                }
            }
        }
    }

    Dialog {
        id: mssDialog
        title: qsTr("IP-цели MSS-clamp")
        modal: true
        anchors.centerIn: Overlay.overlay
        width: Math.min(620, page.width - 60)
        standardButtons: Dialog.Close
        ColumnLayout {
            width: parent.width
            Text {
                Layout.fillWidth: true
                text: qsTr("Только литеральные IPv4/IPv6. Домены и CIDR запрещены. Общий IP/CDN может затронуть несколько сайтов; эффект — на весь upload.")
                color: Theme.muted; font.family: Theme.font; font.pixelSize: 12; wrapMode: Text.WordWrap
            }
            RowLayout {
                Layout.fillWidth: true
                TextField {
                    id: mssAdd
                    Layout.fillWidth: true
                    placeholderText: "192.0.2.10 / 2001:db8::10"
                    font.family: Theme.font
                    onAccepted: { if (text.trim().length) { backend.addMssTarget(text); clear() } }
                }
                Button {
                    text: qsTr("Добавить")
                    font.family: Theme.font
                    onClicked: { if (mssAdd.text.trim().length) { backend.addMssTarget(mssAdd.text); mssAdd.clear() } }
                }
            }
            Repeater {
                model: backend.draftMssTargets
                RowLayout {
                    Layout.fillWidth: true
                    TextField {
                        Layout.fillWidth: true
                        text: modelData
                        font.family: "monospace"
                        onEditingFinished: {
                            var list = backend.draftMssTargets.slice()
                            list[index] = text
                            backend.setMssTargets(list)
                        }
                    }
                    Button {
                        text: qsTr("Удалить")
                        font.family: Theme.font
                        onClicked: page.removeTarget(index)
                    }
                }
            }
            Text {
                Layout.fillWidth: true
                visible: backend.draftMssTargets.length === 0
                text: qsTr("Список пуст; при включённом MSS-clamp применение будет отклонено.")
                color: Theme.warn; font.family: Theme.font; font.pixelSize: 12
            }
        }
    }
}
