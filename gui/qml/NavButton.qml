import QtQuick
import QtQuick.Controls
import Mutekizu

Button {
    id: control
    checkable: true
    leftPadding: 14
    rightPadding: 14
    topPadding: 10
    bottomPadding: 10
    font.family: Theme.font
    font.pixelSize: 14
    flat: false

    background: Rectangle {
        radius: 8
        color: control.checked ? Theme.surface2 : "transparent"
        border.color: control.checked ? Theme.accent : "transparent"
        border.width: 1
    }
    contentItem: Text {
        text: control.text
        color: control.checked ? Theme.text : Theme.muted
        font: control.font
        verticalAlignment: Text.AlignVCenter
        elide: Text.ElideRight
    }
}
