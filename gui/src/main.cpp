#include "backend.hpp"
#include "branding.hpp"

#include <QCommandLineParser>
#include <QDir>
#include <QEventLoop>
#include <QFileInfo>
#include <QGuiApplication>
#include <QIcon>
#include <QImage>
#include <QQmlApplicationEngine>
#include <QQmlContext>
#include <QQuickStyle>
#include <QQuickWindow>
#include <QTimer>

#include <cstdio>
#include <functional>

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
    QGuiApplication app(argc, argv);
    QGuiApplication::setApplicationName(QStringLiteral("mutekizu-gui"));
    QGuiApplication::setOrganizationName(QStringLiteral("mutekizu"));
    QGuiApplication::setApplicationDisplayName(QString::fromUtf8(kDisplayName));
    QGuiApplication::setDesktopFileName(QStringLiteral("mutekizu"));
    QGuiApplication::setWindowIcon(QIcon::fromTheme(QStringLiteral("mutekizu")));

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

    QQuickStyle::setStyle(QStringLiteral("Material"));

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
    engine.loadFromModule("Mutekizu", "Main");
    if (engine.rootObjects().isEmpty()) return 1;

    if (parser.isSet("screenshot")) {
        const QString path = parser.value("screenshot");
        auto* window = qobject_cast<QQuickWindow*>(engine.rootObjects().first());
        if (!window) return 2;
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
