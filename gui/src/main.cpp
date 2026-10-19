#include "backend.hpp"
#include "branding.hpp"

#include <QAction>
#include <QApplication>
#include <QCommandLineParser>
#include <QDir>
#include <QEventLoop>
#include <QFileInfo>
#include <QIcon>
#include <QLocalServer>
#include <QLocalSocket>
#include <QMenu>
#include <QSystemTrayIcon>
#include <QImage>
#include <QQmlApplicationEngine>
#include <QQmlContext>
#include <QQuickStyle>
#include <QQuickWindow>
#include <QTimer>

#include <cstdio>
#include <functional>
#include <memory>
#include <unistd.h>

namespace {

bool waitMs(int ms)
{
    QEventLoop loop;
    QTimer::singleShot(ms, &loop, &QEventLoop::quit);
    loop.exec();
    return true;
}

int selfTest()
{
    int failures = 0;
    auto check = [&failures](bool ok, const char* what) {
        std::printf("%s: %s\n", ok ? "ok" : "FAIL", what);
        if (!ok) ++failures;
    };

    Backend b(true);
    check(b.demo(), "demo backend");
    check(b.state() == "stopped", "initial state stopped");
    check(b.installed(), "demo service installed");
    check(b.configAvailable(), "demo config available");

    b.startService();
    check(b.state() == "starting", "start -> starting");
    waitMs(900);
    check(b.state() == "running", "start -> running");
    b.stopService();
    check(b.state() == "stopping", "stop -> stopping");
    waitMs(700);
    check(b.state() == "stopped", "stop -> stopped");

    b.setDomains({QStringLiteral("bad domain")});
    check(!b.validateDraft().isEmpty(), "invalid domain rejected");
    b.setDomains({QStringLiteral("example.com"), QStringLiteral("sub.example.com")});
    check(b.validateDraft().isEmpty(), "valid domains accepted");

    const int initialProfiles = b.profileList().size();
    check(initialProfiles >= 1, "demo profiles are parsed");
    b.addProfileTemplate("youtube");
    check(b.profileList().size() > initialProfiles, "profile template is appended");
    const int newIndex = b.profileList().size() - 1;
    const QString before = b.profileTextAt(newIndex);
    check(before.contains("youtube"), "new profile block is present");
    b.setProfileBlock(newIndex, before + "split_jitter_ms = 2\n");
    check(b.draftProfilesText().contains("split_jitter_ms = 2"),
          "profile edit reaches draft text");
    b.refreshProfiles();
    check(b.profileTextAt(newIndex).contains("split_jitter_ms = 2"),
          "profile edit survives refresh");
    b.setProfileValue(newIndex, "domains", "example.org");
    check(b.profileValue(newIndex, "domains") == "example.org",
          "quick profile fields update the block");
    b.setProfileValue(newIndex, "interfaces", "");
    check(b.profileValue(newIndex, "interfaces").isEmpty(),
          "empty interface removes the key");
    b.duplicateProfile(0);
    check(b.profileList().size() > initialProfiles + 1, "profile is duplicated");
    const int beforeRemove = b.profileList().size();
    b.removeProfile(0);
    check(b.profileList().size() == beforeRemove - 1, "profile is removed");
    check(!b.draftProfilesText().contains("[discord-safe]"),
          "removed profile is gone from text");

    b.setSetting("split_delta", 0);
    check(!b.validateDraft().isEmpty(), "invalid split_delta rejected");
    b.setSetting("split_delta", 4);

    b.setSetting("mss_clamp", true);
    b.setMssTargets({QStringLiteral("example.com")});
    check(!b.validateDraft().isEmpty(), "domain rejected as MSS target");
    b.setMssTargets({QStringLiteral("192.0.2.10"), QStringLiteral("2001:db8::10")});
    check(b.validateDraft().isEmpty(), "valid MSS targets accepted");
    b.setMssTargets({QStringLiteral("192.0.2.0/24")});
    check(!b.validateDraft().isEmpty(), "CIDR rejected as MSS target");

    b.revertDraft();
    b.setDomains({QStringLiteral("rutracker.org"), QStringLiteral("example.com")});
    check(b.dirty(), "draft is dirty");
    b.applyDraft();
    check(!b.dirty(), "demo apply clears dirty");

    b.runDoctor();
    waitMs(2500);
    check(!b.diagnostics().isEmpty(), "doctor pipeline returns structured checks");
    check(!b.busy(), "doctor releases busy state");

    Backend real(false);
    if (!real.helperAvailable()) {
        real.setDomains({QStringLiteral("example.com")});
        real.applyDraft();
        check(real.lastError().contains(QStringLiteral("helper")),
              "real apply refuses when privileged helper is not installed");
    } else {
        // Never invoke pkexec from an automated self-test: it would prompt.
        check(true, "installed helper present; privileged apply not exercised");
    }

    std::printf("%s (%d failure(s))\n", failures == 0 ? "ALL OK" : "FAILED", failures);
    return failures == 0 ? 0 : 1;
}

} // namespace

int main(int argc, char** argv)
{
    QApplication app(argc, argv);
    QApplication::setApplicationName(QStringLiteral("mutekizu-gui"));
    QApplication::setOrganizationName(QStringLiteral("mutekizu"));
    QApplication::setApplicationDisplayName(QString::fromUtf8(kDisplayName));
    QApplication::setDesktopFileName(QStringLiteral("mutekizu"));
    QApplication::setWindowIcon(QIcon::fromTheme(QStringLiteral("mutekizu")));

    QCommandLineParser parser;
    parser.setApplicationDescription(QStringLiteral("Mutekizu desktop GUI"));
    parser.addHelpOption();
    parser.addOption({QStringLiteral("demo"), QStringLiteral("Use the mock backend; no system changes.")});
    parser.addOption({QStringLiteral("self-test"), QStringLiteral("Run non-GUI backend self-tests.")});
    parser.addOption({QStringLiteral("probe-real"), QStringLiteral("Print real service/config state and exit.")});
    parser.addOption({QStringLiteral("screenshot"), QStringLiteral("Save a screenshot to this path."),
                      QStringLiteral("path")});
    parser.addOption({QStringLiteral("page"), QStringLiteral("Initial page for screenshots."),
                      QStringLiteral("page"), QStringLiteral("overview")});
    parser.addOption({QStringLiteral("demo-running"),
                      QStringLiteral("Start the mock service before showing/screenshotting.")});
    parser.addOption({QStringLiteral("theme"), QStringLiteral("system, dark or light."),
                      QStringLiteral("theme"), QStringLiteral("system")});
    parser.addOption({QStringLiteral("background"),
                      QStringLiteral("Start hidden; relaunch the desktop entry to show.")});
    parser.addOption({QStringLiteral("quit"),
                      QStringLiteral("Ask the running GUI instance to quit.")});
    parser.addOption({QStringLiteral("width"), QStringLiteral("Window width."),
                      QStringLiteral("px"), QStringLiteral("1220")});
    parser.addOption({QStringLiteral("height"), QStringLiteral("Window height."),
                      QStringLiteral("px"), QStringLiteral("820")});
    parser.process(app);

    if (parser.isSet("self-test")) return selfTest();

    const bool demo = parser.isSet("demo");
    Backend backend(demo);
    if (demo && parser.isSet("demo-running")) {
        backend.startService();
        waitMs(900);
    }

    if (parser.isSet("probe-real")) {
        std::printf("state=%s installed=%d config=%d engine=%s helper=%d\n",
                    backend.state().toUtf8().constData(), backend.installed(),
                    backend.configAvailable(), backend.engineVersion().toUtf8().constData(),
                    backend.helperAvailable());
        return 0;
    }

    // One GUI instance is enough: a second desktop launch asks the running one
    // to show its window instead of creating a duplicate tray/app process.
    const bool interactive = !parser.isSet("screenshot") &&
                             !parser.isSet("self-test") &&
                             !parser.isSet("probe-real");
    const QString serverName = QStringLiteral("mutekizu-gui-%1").arg(static_cast<qulonglong>(getuid()));
    if (interactive) {
        QLocalSocket probe;
        probe.connectToServer(serverName);
        if (probe.waitForConnected(250)) {
            probe.write(parser.isSet("quit") ? "quit" : "show");
            probe.waitForBytesWritten(250);
            return 0;
        }
    }
    if (parser.isSet("quit")) return 0;

    QLocalServer::removeServer(serverName);
    QLocalServer server;
    if (interactive) (void)server.listen(serverName);

    QQuickStyle::setStyle(QStringLiteral("Material"));

    const bool trayAvailable = QSystemTrayIcon::isSystemTrayAvailable();
    QQmlApplicationEngine engine;
    engine.rootContext()->setContextProperty(QStringLiteral("backend"), &backend);
    engine.rootContext()->setContextProperty(QStringLiteral("brandName"), backend.displayName());
    engine.rootContext()->setContextProperty(QStringLiteral("appVersion"),
                                             QStringLiteral(MUTEKIZU_VERSION));
    engine.rootContext()->setContextProperty(QStringLiteral("demoMode"), demo);
    engine.rootContext()->setContextProperty(QStringLiteral("initialPage"),
                                             parser.value("page"));
    engine.rootContext()->setContextProperty(QStringLiteral("initialTheme"),
                                             parser.value("theme"));
    engine.rootContext()->setContextProperty(QStringLiteral("initialWidth"),
                                             parser.value("width").toInt());
    engine.rootContext()->setContextProperty(QStringLiteral("initialHeight"),
                                             parser.value("height").toInt());
    engine.rootContext()->setContextProperty(QStringLiteral("trayAvailable"),
                                             trayAvailable);
    engine.loadFromModule("Mutekizu", "Main");
    if (engine.rootObjects().isEmpty()) return 1;

    auto* window = qobject_cast<QQuickWindow*>(engine.rootObjects().first());
    if (!window) return 2;

    auto showWindow = [window] {
        window->show();
        window->raise();
        window->requestActivate();
    };

    if (interactive) {
        QObject::connect(&server, &QLocalServer::newConnection, &app, [&server, &app, showWindow] {
            while (QLocalSocket* c = server.nextPendingConnection()) {
                auto handled = std::make_shared<bool>(false);
                auto handle = [c, showWindow, &app, handled] {
                    if (*handled) return;
                    const QByteArray command = c->readAll();
                    if (command.isEmpty()) return;
                    *handled = true;
                    if (command.contains("quit")) app.quit();
                    else if (command.contains("show")) showWindow();
                    c->disconnectFromServer();
                };
                QObject::connect(c, &QLocalSocket::readyRead, c, handle);
                QObject::connect(c, &QLocalSocket::disconnected, c,
                                 &QLocalSocket::deleteLater);
                // The peer may have written before newConnection was handled.
                if (c->bytesAvailable() > 0 || c->waitForReadyRead(200)) handle();
            }
        });
    }

    if (interactive) app.setQuitOnLastWindowClosed(false);

    if (trayAvailable && interactive) {
        auto* tray = new QSystemTrayIcon(QIcon::fromTheme(QStringLiteral("mutekizu")), &app);
        auto* menu = new QMenu();
        QAction* show = menu->addAction(QStringLiteral("Открыть Mutekizu"));
        menu->addSeparator();
        QAction* quit = menu->addAction(QStringLiteral("Выход"));
        QObject::connect(show, &QAction::triggered, &app, showWindow);
        QObject::connect(quit, &QAction::triggered, &app, &QApplication::quit);
        QObject::connect(tray, &QSystemTrayIcon::activated, &app,
                         [showWindow](QSystemTrayIcon::ActivationReason reason) {
                             if (reason == QSystemTrayIcon::Trigger ||
                                 reason == QSystemTrayIcon::DoubleClick)
                                 showWindow();
                         });
        tray->setContextMenu(menu);
        tray->setToolTip(QString::fromUtf8(kDisplayName));
        tray->show();
    }

    // Background does not depend on a tray host: Hyprland/GNOME sessions may
    // not expose StatusNotifierItem. The desktop entry is single-instance and
    // asks the hidden process to show its window.
    if (interactive && parser.isSet("background")) window->hide();

    if (parser.isSet("screenshot")) {
        const QString path = parser.value("screenshot");
        window->show();
        QTimer::singleShot(900, &app, [window, path, &app] {
            const QImage img = window->grabWindow();
            if (!img.save(path)) std::fprintf(stderr, "cannot save screenshot %s\n", path.toUtf8().constData());
            else std::printf("screenshot: %s (%dx%d)\n", path.toUtf8().constData(), img.width(), img.height());
            app.quit();
        });
    }
    return app.exec();
}
