import QtQuick
import QtQuick.Layouts
import Mutekizu

RowLayout {
    id: badge
    property string level: "unknown"
    property string text: ""
    spacing: 6

    function levelColor() {
        if (level === "ok") return Theme.ok
        if (level === "warn") return Theme.warn
        if (level === "fail") return Theme.err
        if (level === "running") return Theme.ok
        if (level === "starting" || level === "stopping") return Theme.warn
        if (level === "failed") return Theme.err
        return Theme.unknown
    }
    function symbol() {
        if (level === "ok" || level === "running") return "✓"
        if (level === "warn" || level === "starting" || level === "stopping") return "!"
        if (level === "fail" || level === "failed") return "×"
        return "–"
    }

    Rectangle {
        width: 20; height: 20; radius: 10
        color: Qt.rgba(badge.levelColor().r, badge.levelColor().g, badge.levelColor().b, 0.16)
        Text {
            anchors.centerIn: parent
            text: badge.symbol()
            color: badge.levelColor()
            font.family: Theme.font
            font.pixelSize: 12
            font.weight: Font.Bold
        }
    }
    Text {
        text: badge.text
        color: badge.levelColor()
        font.family: Theme.font
        font.pixelSize: 13
        font.weight: Font.DemiBold
        Layout.fillWidth: true
    }
}
