import QtQuick
import QtQuick.Layouts
import Mutekizu

Rectangle {
    id: card
    default property alias content: body.data
    property alias title: titleLabel.text
    property string subtitle: ""

    color: Theme.surface
    radius: Theme.radius
    border.color: Theme.border
    border.width: 1
    implicitHeight: layout.implicitHeight + 32

    ColumnLayout {
        id: layout
        anchors.fill: parent
        anchors.margins: 16
        spacing: 10

        RowLayout {
            Layout.fillWidth: true
            Text {
                id: titleLabel
                color: Theme.text
                font.family: Theme.font
                font.pixelSize: 15
                font.weight: Font.DemiBold
                Layout.fillWidth: true
            }
            Text {
                text: card.subtitle
                visible: text.length > 0
                color: Theme.muted
                font.family: Theme.font
                font.pixelSize: 12
            }
        }
        ColumnLayout {
            id: body
            Layout.fillWidth: true
            spacing: 8
        }
    }
}
