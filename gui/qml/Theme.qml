pragma Singleton
import QtQuick

QtObject {
    property bool dark: true

    readonly property color bg: dark ? "#0f1215" : "#f3f5f8"
    readonly property color surface: dark ? "#171b20" : "#ffffff"
    readonly property color surface2: dark ? "#1e242b" : "#eef1f5"
    readonly property color border: dark ? "#2a323c" : "#d7dde5"
    readonly property color text: dark ? "#e8ecf2" : "#1b2027"
    readonly property color muted: dark ? "#9aa6b5" : "#5d6877"
    readonly property color accent: dark ? "#79a8ff" : "#2f6fdb"
    readonly property color ok: dark ? "#63d39a" : "#1f8f5f"
    readonly property color warn: dark ? "#e6b95e" : "#9a6a10"
    readonly property color err: dark ? "#f08080" : "#b02a2a"
    readonly property color unknown: dark ? "#9aa6b5" : "#6b7280"
    readonly property int radius: 10
    readonly property int spacing: 14
    readonly property string font: "Noto Sans"
}
