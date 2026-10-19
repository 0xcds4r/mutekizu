#include "backend.hpp"

#include <QCoreApplication>
#include <QCryptographicHash>
#include <QDateTime>
#include <QDBusError>
#include <QDBusMessage>
#include <QDBusPendingCallWatcher>
#include <QDBusPendingReply>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QGuiApplication>
#include <QHostAddress>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QProcess>
#include <QRegularExpression>
#include <QSaveFile>
#include <QSet>
#include <QStandardPaths>
#include <QStyleHints>
#include <QTemporaryDir>
#include <QTimer>
#include <QVariant>

namespace {
constexpr const char* kService = "mutekizu.service";
constexpr const char* kSysBus = "org.freedesktop.systemd1";
constexpr const char* kSysPath = "/org/freedesktop/systemd1";
constexpr const char* kManager = "org.freedesktop.systemd1.Manager";
constexpr const char* kUnit = "org.freedesktop.systemd1.Unit";
constexpr const char* kProperties = "org.freedesktop.DBus.Properties";
constexpr const char* kConfigDir = "/etc/mutekizu";
}

Backend::Backend(bool demo, QObject* parent) : QObject(parent), m_demo(demo)
{
    m_configPath = QString::fromLatin1(kConfigDir) + "/mutekizu.conf";
    m_domainsPath = QString::fromLatin1(kConfigDir) + "/domains.txt";
    m_targetsPath = QString::fromLatin1(kConfigDir) + "/mss_targets.txt";
    m_profilesPath = QString::fromLatin1(kConfigDir) + "/profiles.conf";

    if (m_demo) {
        loadDemo();
        setState("stopped");
        m_installed = true;
    } else {
        loadReal();
        readServiceState();
    }

    QProcess ver;
    if (!enginePath().isEmpty()) ver.start(enginePath(), {"version"});
    if (ver.waitForFinished(2000) && ver.exitCode() == 0) {
        m_engineVersion = QString::fromUtf8(ver.readAllStandardOutput()).trimmed();
    } else {
        m_engineVersion = tr("движок не найден");
    }
    m_helperAvailable = haveInstalledHelper();

    connect(&m_refreshTimer, &QTimer::timeout, this, [this] {
        if (!m_demo) readServiceState();
    });
    m_refreshTimer.start(2000);
}

Backend::~Backend()
{
    if (m_doctorProcess) m_doctorProcess->kill();
    if (m_logProcess) m_logProcess->kill();
    if (m_applyProcess) m_applyProcess->kill();
}

QVariantMap Backend::defaults()
{
    QVariantMap m;
    m["split_enabled"] = true;
    m["mss_clamp"] = false;
    m["split_delta"] = 4;
    m["split_stride"] = 4;
    m["split_max"] = 64;
    m["split_gap_ms"] = 0;
    m["split_disorder"] = true;
    m["split_multidisorder"] = false;
    m["split_jitter_ms"] = 0;
    m["fake_enabled"] = true;
    m["fake_ttl"] = 3;
    m["fake_repeats"] = 3;
    m["fake_sni"] = QStringLiteral("www.microsoft.com");
    m["fake_bad_checksum"] = false;
    m["fake_seq_offset"] = 0;
    m["fake_timestamp"] = false;
    m["seqovl_enabled"] = true;
    m["seqovl_bytes"] = 646;
    m["seqovl_repeats"] = 1;
    m["udp_fake_enabled"] = true;
    m["udp_fake_ttl"] = 4;
    m["udp_fake_repeats"] = 5;
    m["udp_fake_type"] = QStringLiteral("stun");
    m["mss"] = 1200;
    m["mss_value"] = 96;
    m["inspect_packets"] = 10;
    m["queue_num"] = 2000;
    m["fwmark"] = QStringLiteral("0x44495054");
    m["max_queue_len"] = 256;
    m["copy_range"] = 65535;
    m["ipv4"] = true;
    m["ipv6"] = false;
    m["ports"] = QStringLiteral("443,8080,80,83");
    m["log_level"] = QStringLiteral("info");
    m["log_sni"] = false;
    m["max_flows"] = 1024;
    m["flow_buffer"] = 8192;
    m["flow_timeout_s"] = 30;
    m["auto_discover"] = true;
    m["auto_profile"] = true;
    m["auto_retry_window_s"] = 10;
    m["reply_observe"] = true;
    m["reply_queue_num"] = 2001;
    m["reply_inspect_packets"] = 3;
    m["ip_frag_enabled"] = false;
    m["ip_frag_queue_num"] = 2002;
    m["ip_frag_size"] = 512;
    m["ip_frag_inspect_packets"] = 10;
    m["ip_frag_ports"] = QStringLiteral("80,443,5222");
    return m;
}

void Backend::loadDemo()
{
    m_settings = defaults();
    m_draft = m_settings;
    m_domains = {QStringLiteral("instagram.com"), QStringLiteral("x.com"),
                 QStringLiteral("t.me"), QStringLiteral("torproject.org"),
                 QStringLiteral("proton.me")};
    m_draftDomains = m_domains;
    m_mssTargets = {};
    m_draftMssTargets = m_mssTargets;
    m_profilesText = profileTemplate(QStringLiteral("discord"));
    m_draftProfilesText = m_profilesText;
    rebuildProfileBlocks();
    m_configAvailable = true;
    m_diagnostics = {
        QVariantMap{{"level", "ok"}, {"text", "Демо-среда: ядро, nftables и модули доступны"}},
        QVariantMap{{"level", "ok"}, {"text", "Демо-среда: capabilities присутствуют"}},
        QVariantMap{{"level", "warn"}, {"text", "Демо: номер очереди 2000 не проверяется в реальном firewall"}},
        QVariantMap{{"level", "ok"}, {"text", "Демо: конфигурация валидна"}},
        QVariantMap{{"level", "unknown"}, {"text", "Демо: состояние службы имитируется"}},
    };
    m_diagnosticsRaw = tr("Демо-режим: это не результат реальной диагностики.");
    m_logs = {
        QVariantMap{{"time", "10:00:01"}, {"level", "info"}, {"text", "Демо: служба запущена"}},
        QVariantMap{{"time", "10:00:03"}, {"level", "info"}, {"text", "Демо: режим SNI-split активен"}},
        QVariantMap{{"time", "10:01:12"}, {"level", "warn"}, {"text", "Демо: предупреждение о MTU"}},
    };
    m_dirty = false;
    m_conflict = false;
    m_configAvailable = true;
}

void Backend::loadReal()
{
    m_settings = defaults();
    m_draft = m_settings;
    m_domains.clear();
    m_draftDomains.clear();
    m_mssTargets.clear();
    m_draftMssTargets.clear();
    m_profilesText.clear();
    m_draftProfilesText.clear();
    loadFiles();
    m_draft = m_settings;
    m_draftDomains = m_domains;
    m_draftMssTargets = m_mssTargets;
    m_draftProfilesText = m_profilesText;
    rebuildProfileBlocks();
    m_dirty = false;
    m_conflict = false;
    rememberHashes();
}

void Backend::loadFiles()
{
    QVariantMap loaded = defaults();
    QFile cf(m_configPath);
    m_configAvailable = cf.open(QIODevice::ReadOnly | QIODevice::Text);
    if (m_configAvailable) {
        const QStringList lines = QString::fromUtf8(cf.readAll()).split('\n');
        for (QString line : lines) {
            const int hash = line.indexOf('#');
            if (hash >= 0) line.truncate(hash);
            line = line.trimmed();
            if (line.isEmpty()) continue;
            const int eq = line.indexOf('=');
            if (eq <= 0) continue;
            const QString key = line.left(eq).trimmed();
            const QString value = line.mid(eq + 1).trimmed();
            if (!loaded.contains(key)) continue; // preserve only known keys
            const QVariant cur = loaded.value(key);
            if (cur.typeId() == QMetaType::Bool) {
                loaded[key] = (value == "true" || value == "1" || value == "yes" || value == "on");
            } else if (cur.typeId() == QMetaType::Int || cur.typeId() == QMetaType::UInt) {
                bool ok = false;
                const int n = value.toInt(&ok);
                if (ok) loaded[key] = n;
            } else {
                loaded[key] = value;
            }
        }
    }

    auto readList = [](const QString& path) {
        QStringList out;
        QFile f(path);
        if (!f.open(QIODevice::ReadOnly | QIODevice::Text)) return out;
        for (QString line : QString::fromUtf8(f.readAll()).split('\n')) {
            const int hash = line.indexOf('#');
            if (hash >= 0) line.truncate(hash);
            line = line.trimmed();
            if (!line.isEmpty() && !out.contains(line, Qt::CaseInsensitive)) out << line;
        }
        return out;
    };

    m_settings = loaded;
    m_domains = readList(m_domainsPath);
    m_mssTargets = readList(m_targetsPath);
    QFile pf(m_profilesPath);
    m_profilesText = pf.open(QIODevice::ReadOnly | QIODevice::Text)
                         ? QString::fromUtf8(pf.readAll()) : QString();
    m_draftProfilesText = m_profilesText;
    rebuildProfileBlocks();
}


void Backend::setState(const QString& state)
{
    if (m_state == state) return;
    m_state = state;
    emit stateChanged();
    emit busyChanged();
}

QString Backend::stateText() const
{
    if (m_state == "not-installed") return tr("Служба не установлена");
    if (m_state == "stopped") return tr("Остановлена");
    if (m_state == "starting") return tr("Запускается");
    if (m_state == "running") return tr("Работает");
    if (m_state == "stopping") return tr("Останавливается");
    if (m_state == "failed") return tr("Завершилась с ошибкой");
    if (m_state == "unavailable") return tr("Состояние недоступно");
    return tr("Неизвестно");
}

QString Backend::activeModes() const
{
    QStringList modes;
    if (m_settings.value("split_enabled").toBool()) {
        const int stride = m_settings.value("split_stride").toInt();
        modes << (stride > 0 ? tr("SNI-split (multi, шаг %1)").arg(stride)
                             : tr("SNI-split (один разрыв)"));
    }
    if (m_settings.value("mss_clamp").toBool()) modes << tr("MSS-clamp по IP");
    if (m_settings.value("split_disorder").toBool()) modes << tr("disorder");
    if (m_settings.value("fake_enabled").toBool())
        modes << tr("fake SNI %1").arg(m_settings.value("fake_sni").toString());
    if (m_settings.value("udp_fake_enabled").toBool()) modes << tr("UDP fake STUN");
    if (modes.isEmpty()) return tr("Нет активных режимов");
    return modes.join(QStringLiteral(" · "));
}

bool Backend::systemDark() const
{
    return QGuiApplication::styleHints()->colorScheme() == Qt::ColorScheme::Dark;
}

void Backend::setBusy(bool busy)
{
    if (m_busy == busy) return;
    m_busy = busy;
    emit busyChanged();
}

void Backend::setError(const QString& message, const QString& hint)
{
    m_lastError = message;
    m_lastErrorHint = hint;
    emit errorChanged();
}

void Backend::clearError()
{
    if (m_lastError.isEmpty() && m_lastErrorHint.isEmpty()) return;
    m_lastError.clear();
    m_lastErrorHint.clear();
    emit errorChanged();
}

void Backend::recomputeDirty()
{
    const bool d = m_draft != m_settings || m_draftDomains != m_domains ||
                   m_draftMssTargets != m_mssTargets ||
                   m_draftProfilesText != m_profilesText;
    if (d != m_dirty) {
        m_dirty = d;
        emit dirtyChanged();
    }
    emit draftChanged();
}

void Backend::setSetting(const QString& key, const QVariant& value)
{
    if (!m_draft.contains(key)) {
        setError(tr("Неизвестный параметр: %1").arg(key), tr("Изменение не применено."));
        return;
    }
    m_draft[key] = value;
    recomputeDirty();
}

void Backend::setDomains(const QStringList& domains)
{
    m_draftDomains = domains;
    recomputeDirty();
}

void Backend::setMssTargets(const QStringList& targets)
{
    m_draftMssTargets = targets;
    recomputeDirty();
}

void Backend::setProfilesText(const QString& text)
{
    m_draftProfilesText = text;
    rebuildProfileBlocks();
    recomputeDirty();
}

QString Backend::profileTextAt(int index) const
{
    if (index < 0 || index >= m_profileList.size()) return {};
    return m_profileList.at(index).toMap().value(QStringLiteral("text")).toString();
}

void Backend::rebuildProfileBlocks()
{
    m_profilePreamble.clear();
    m_profileList.clear();
    QString preamble;
    QString current;
    bool in_block = false;

    auto flush = [this](QString& block) {
        if (block.isEmpty()) return;
        QString name;
        QString summary;
        const QStringList lines = block.split('\n');
        for (const QString& line : lines) {
            const QString t = line.trimmed();
            if (name.isEmpty() && t.startsWith('[') && t.endsWith(']'))
                name = t.mid(1, t.size() - 2).trimmed();
            if (summary.isEmpty()) {
                const int eq = t.indexOf('=');
                if (eq > 0 && t.left(eq).trimmed() == "domains")
                    summary = t.mid(eq + 1).trimmed();
            }
        }
        if (name.isEmpty()) return;
        QVariantMap m;
        m["name"] = name;
        m["summary"] = summary.isEmpty() ? tr("домены не заданы") : summary;
        m["text"] = block;
        m_profileList.append(m);
        block.clear();
    };

    for (QString line : m_draftProfilesText.split('\n')) {
        const QString t = line.trimmed();
        if (t.startsWith('[') && t.endsWith(']')) {
            flush(current);
            in_block = true;
        }
        if (in_block) {
            current += line + '\n';
        } else {
            preamble += line + '\n';
        }
    }
    flush(current);
    m_profilePreamble = preamble;
    emit profilesChanged();
}

void Backend::setProfileBlock(int index, const QString& text)
{
    if (index < 0 || index >= m_profileList.size()) return;
    QVariantMap m = m_profileList.at(index).toMap();
    m["text"] = text;
    m_profileList[index] = m;

    // Keep the canonical text in sync without reparsing on every keystroke:
    // reparsing here would rewrite the editor's trailing newline and move the
    // cursor. The list summary is refreshed when the editor loses focus.
    QString full = m_profilePreamble;
    for (const QVariant& v : m_profileList) {
        QString block = v.toMap().value("text").toString();
        if (block.isEmpty()) continue;
        if (!full.isEmpty() && !full.endsWith('\n')) full += '\n';
        if (!full.isEmpty() && !full.endsWith("\n\n")) full += '\n';
        if (!block.endsWith('\n')) block += '\n';
        full += block;
    }
    m_draftProfilesText = full;
    recomputeDirty();
}

void Backend::refreshProfiles()
{
    rebuildProfileBlocks();
}

QString Backend::profileValue(int index, const QString& key) const
{
    if (index < 0 || index >= m_profileList.size()) return {};
    const QString block = m_profileList.at(index).toMap().value("text").toString();
    for (const QString& line : block.split('\n')) {
        const QString t = line.trimmed();
        if (key == "name" && t.startsWith('[') && t.endsWith(']'))
            return t.mid(1, t.size() - 2).trimmed();
        const int eq = t.indexOf('=');
        if (eq > 0 && t.left(eq).trimmed() == key)
            return t.mid(eq + 1).trimmed();
    }
    return {};
}

void Backend::setProfileValue(int index, const QString& key, const QString& value)
{
    if (index < 0 || index >= m_profileList.size()) return;
    QString block = m_profileList.at(index).toMap().value("text").toString();
    QStringList lines = block.split('\n');
    if (key == "name") {
        const QString name = value.trimmed();
        if (name.isEmpty()) return;
        for (QString& line : lines) {
            const QString t = line.trimmed();
            if (t.startsWith('[') && t.endsWith(']')) {
                line = QStringLiteral("[%1]").arg(name);
                break;
            }
        }
    } else {
        bool found = false;
        for (int i = 0; i < lines.size(); ++i) {
            const QString t = lines[i].trimmed();
            const int eq = t.indexOf('=');
            if (eq > 0 && t.left(eq).trimmed() == key) {
                if (value.trimmed().isEmpty())
                    lines.removeAt(i);
                else
                    lines[i] = QStringLiteral("%1 = %2").arg(key, value.trimmed());
                found = true;
                break;
            }
        }
        if (!found && !value.trimmed().isEmpty()) {
            while (!lines.isEmpty() && lines.last().trimmed().isEmpty()) lines.removeLast();
            lines << QStringLiteral("%1 = %2").arg(key, value.trimmed());
            lines << QString();
        }
    }
    QString edited = lines.join('\n');
    if (!edited.endsWith('\n')) edited += '\n';
    setProfileBlock(index, edited);
    refreshProfiles();
}

void Backend::addProfile()
{
    QString name = QStringLiteral("profile");
    int n = 1;
    while (m_draftProfilesText.contains(QStringLiteral("[%1]").arg(name))) {
        name = QStringLiteral("profile%1").arg(n++);
    }
    setProfilesText(m_draftProfilesText + QStringLiteral("\n[%1]\ndomains = \n").arg(name));
}

void Backend::addProfileTemplate(const QString& kind)
{
    setProfilesText(m_draftProfilesText + QLatin1Char('\n') + profileTemplate(kind));
}

void Backend::removeProfile(int index)
{
    if (index < 0 || index >= m_profileList.size()) return;
    QString full = m_profilePreamble;
    for (int i = 0; i < m_profileList.size(); ++i) {
        if (i == index) continue;
        QString block = m_profileList.at(i).toMap().value("text").toString();
        if (!block.endsWith('\n')) block += '\n';
        full += block;
    }
    setProfilesText(full);
}

void Backend::duplicateProfile(int index)
{
    if (index < 0 || index >= m_profileList.size()) return;
    QString block = m_profileList.at(index).toMap().value("text").toString();
    const int nl = block.indexOf('\n');
    QString header = nl >= 0 ? block.left(nl) : block;
    const int end = header.lastIndexOf(']');
    const QString base = (header.startsWith('[') && end > 0)
                             ? header.mid(1, end - 1) : QStringLiteral("profile");
    QString name = base + QStringLiteral("-copy");
    int n = 1;
    while (m_draftProfilesText.contains(QStringLiteral("[%1]").arg(name)))
        name = base + QStringLiteral("-copy%1").arg(n++);
    block.replace(0, end + 1, QStringLiteral("[%1]").arg(name));
    setProfilesText(m_draftProfilesText + QLatin1Char('\n') + block);
}

QString Backend::profileTemplate(const QString& kind) const
{
    if (kind == QStringLiteral("youtube")) {
        return QStringLiteral(
            "# Профиль YouTube: только split, без fake/seqovl.\n"
            "[youtube]\n"
            "domains = youtube.com, googlevideo.com, ytimg.com, youtubei.googleapis.com\n"
            "split_delta = 4\n"
            "split_stride = 4\n"
            "split_disorder = false\n"
            "fake_enabled = false\n"
            "seqovl_enabled = false\n");
    }
    return QStringLiteral(
        "# Discord: агрессивный TCP + UDP STUN для RTC.\n"
        "[discord-safe]\n"
        "domains = discord.com, discord.gg, gateway.discord.gg\n"
        "split_disorder = true\n"
        "fake_enabled = false\n"
        "seqovl_enabled = false\n\n"
        "[discord-aggressive]\n"
        "domains = discord.com, discord.gg, gateway.discord.gg\n"
        "split_disorder = true\n"
        "fake_enabled = true\n"
        "fake_sni = www.microsoft.com\n"
        "seqovl_enabled = true\n"
        "seqovl_bytes = 646\n");
}

void Backend::addDomain(const QString& domain)
{
    const QString d = domain.trimmed();
    if (!d.isEmpty()) {
        m_draftDomains << d;
        recomputeDirty();
    }
}

void Backend::addMssTarget(const QString& target)
{
    const QString a = target.trimmed();
    if (!a.isEmpty()) {
        m_draftMssTargets << a;
        recomputeDirty();
    }
}

void Backend::revertDraft()
{
    m_draft = m_settings;
    m_draftDomains = m_domains;
    m_draftMssTargets = m_mssTargets;
    m_draftProfilesText = m_profilesText;
    rebuildProfileBlocks();
    m_conflict = false;
    emit conflictChanged();
    recomputeDirty();
    clearError();
}

void Backend::reloadFromDisk()
{
    if (!m_demo) {
        loadFiles();
        m_draft = m_settings;
        m_draftDomains = m_domains;
        m_draftMssTargets = m_mssTargets;
        m_draftProfilesText = m_profilesText;
        rebuildProfileBlocks();
        rememberHashes();
    }
    m_conflict = false;
    emit conflictChanged();
    m_dirty = false;
    emit dirtyChanged();
    emit draftChanged();
    clearError();
}

QString Backend::fileHash(const QString& path) const
{
    QFile f(path);
    if (!f.open(QIODevice::ReadOnly)) return QStringLiteral("missing");
    return QString::fromLatin1(QCryptographicHash::hash(f.readAll(), QCryptographicHash::Sha256).toHex());
}

void Backend::rememberHashes()
{
    m_hashes.clear();
    for (const QString& p : {m_configPath, m_domainsPath, m_targetsPath, m_profilesPath})
        m_hashes[p] = fileHash(p);
}

bool Backend::hashesChanged() const
{
    for (auto it = m_hashes.cbegin(); it != m_hashes.cend(); ++it) {
        if (fileHash(it.key()) != it.value()) return true;
    }
    return false;
}

void Backend::readServiceState()
{
    if (m_demo) return;
    const QDBusConnection bus = QDBusConnection::systemBus();
    if (!bus.isConnected()) {
        m_installed = false;
        setState("unavailable");
        setError(tr("Системный D-Bus недоступен"), tr("Проверьте, запущен ли systemd/D-Bus."));
        return;
    }
    QDBusMessage load = QDBusMessage::createMethodCall(kSysBus, kSysPath, kManager, "LoadUnit");
    load << QString::fromLatin1(kService);
    const QDBusMessage reply = bus.call(load);
    if (reply.type() == QDBusMessage::ErrorMessage) {
        m_installed = false;
        m_unitPath.clear();
        setState("not-installed");
        return;
    }
    const QString path = reply.arguments().value(0).value<QDBusObjectPath>().path();
    if (path.isEmpty()) {
        m_installed = false;
        setState("not-installed");
        return;
    }
    m_installed = true;
    if (m_unitPath != path) {
        m_unitPath = path;
        connectUnitSignals(path);
    }
    QDBusMessage get = QDBusMessage::createMethodCall(kSysBus, path, kProperties, "GetAll");
    get << QString::fromLatin1(kUnit);
    const QDBusMessage propsReply = bus.call(get);
    if (propsReply.type() == QDBusMessage::ErrorMessage) {
        setState("unavailable");
        return;
    }
    const QVariantMap props = qdbus_cast<QVariantMap>(propsReply.arguments().value(0));
    const QString loadState = props.value("LoadState").toString();
    if (loadState == "not-found") {
        m_installed = false;
        setState("not-installed");
        return;
    }
    const QString active = props.value("ActiveState").toString();
    const QString sub = props.value("SubState").toString();
    if (active == "active" && (sub == "running" || sub == "listening")) setState("running");
    else if (active == "activating" || active == "reloading") setState("starting");
    else if (active == "deactivating") setState("stopping");
    else if (active == "failed") setState("failed");
    else if (active == "inactive") setState("stopped");
    else setState("unknown");
}

void Backend::connectUnitSignals(const QString& path)
{
    auto bus = QDBusConnection::systemBus();
    if (!m_connectedPath.isEmpty() && m_connectedPath != path) {
        bus.disconnect(kSysBus, m_connectedPath, kProperties, "PropertiesChanged",
                       this, SLOT(onPropertiesChanged(QString,QVariantMap,QStringList)));
    }
    bus.connect(kSysBus, path, kProperties, "PropertiesChanged", this,
                SLOT(onPropertiesChanged(QString,QVariantMap,QStringList)));
    m_connectedPath = path;
}

void Backend::onPropertiesChanged(const QString&, const QVariantMap&, const QStringList&)
{
    if (!m_demo) readServiceState();
}

void Backend::refreshService()
{
    if (m_demo) return;
    readServiceState();
}

void Backend::dbusCall(const QString& method, const QVariantList& args,
                       std::function<void(bool, const QString&)> done)
{
    if (m_demo) {
        done(true, {});
        return;
    }
    QDBusMessage msg = QDBusMessage::createMethodCall(kSysBus, kSysPath, kManager, method);
    for (const QVariant& a : args) msg << a;
    auto* watcher = new QDBusPendingCallWatcher(QDBusConnection::systemBus().asyncCall(msg), this);
    setBusy(true);
    connect(watcher, &QDBusPendingCallWatcher::finished, this,
            [this, watcher, done](QDBusPendingCallWatcher* w) {
                QDBusPendingReply<> reply = *w;
                const bool ok = !reply.isError();
                QString err;
                if (!ok) {
                    err = reply.error().message();
                    setError(tr("systemd: %1").arg(err),
                             tr("Операция не выполнена. Проверьте Polkit-агент и права."));
                } else {
                    clearError();
                }
                setBusy(false);
                readServiceState();
                done(ok, err);
                watcher->deleteLater();
            });
}

void Backend::startService()
{
    if (m_demo) {
        if (m_state == "running" || m_state == "starting") return;
        setState("starting");
        clearError();
        QTimer::singleShot(700, this, [this] {
            if (m_state == "starting") {
                setState("running");
                m_logs.prepend(QVariantMap{{"time", QDateTime::currentDateTime().toString("HH:mm:ss")},
                                           {"level", "info"}, {"text", "Демо: служба запущена"}});
                emit logsChanged();
            }
        });
        return;
    }
    dbusCall("StartUnit", {QString::fromLatin1(kService), QStringLiteral("replace")},
             [](bool, const QString&) {});
}

void Backend::stopService()
{
    if (m_demo) {
        if (m_state == "stopped" || m_state == "stopping") return;
        setState("stopping");
        clearError();
        QTimer::singleShot(500, this, [this] {
            if (m_state == "stopping") {
                setState("stopped");
                m_logs.prepend(QVariantMap{{"time", QDateTime::currentDateTime().toString("HH:mm:ss")},
                                           {"level", "info"}, {"text", "Демо: служба остановлена"}});
                emit logsChanged();
            }
        });
        return;
    }
    dbusCall("StopUnit", {QString::fromLatin1(kService), QStringLiteral("replace")},
             [](bool, const QString&) {});
}

void Backend::restartService()
{
    if (m_demo) {
        if (m_state == "running") {
            setState("starting");
            QTimer::singleShot(600, this, [this] { setState("running"); });
        }
        return;
    }
    if (m_installed)
        dbusCall("RestartUnit", {QString::fromLatin1(kService), QStringLiteral("replace")},
                 [](bool, const QString&) {});
}

QString Backend::enginePath() const
{
    const QString app = QCoreApplication::applicationDirPath();
    const QStringList candidates{
        app + "/mutekizu",
        app + "/../mutekizu",
        QStringLiteral("/usr/local/bin/mutekizu"),
        QStringLiteral("/usr/bin/mutekizu"),
    };
    for (const QString& c : candidates)
        if (QFileInfo(c).isExecutable()) return c;
    return {};
}

QString Backend::helperPath() const
{
    const QString app = QCoreApplication::applicationDirPath();
    const QStringList candidates{
        QStringLiteral("/usr/libexec/mutekizu-config-helper"),
        app + "/mutekizu-config-helper",
        app + "/../mutekizu-config-helper",
    };
    for (const QString& c : candidates)
        if (QFileInfo(c).isExecutable()) return c;
    return {};
}

bool Backend::haveInstalledHelper() const
{
    const QFileInfo inst(QStringLiteral("/usr/libexec/mutekizu-config-helper"));
    if (!inst.exists() || inst.isSymLink() || !inst.isExecutable()) return false;
    if (inst.ownerId() != 0) return false;
    return QFileInfo(QStringLiteral("/usr/bin/pkexec")).isExecutable();
}

void Backend::runProcessSync(const QString& program, const QStringList& args,
                             QString* out, QString* err, int timeoutMs) const
{
    if (out) out->clear();
    if (err) err->clear();
    if (program.isEmpty()) {
        if (err) *err = tr("Программа не найдена");
        return;
    }
    QProcess p;
    p.setProcessChannelMode(QProcess::SeparateChannels);
    p.start(program, args);
    if (!p.waitForStarted(2000)) {
        if (err) *err = p.errorString();
        return;
    }
    if (!p.waitForFinished(timeoutMs)) {
        p.kill();
        p.waitForFinished(1000);
        if (err) *err = tr("Таймаут выполнения");
        return;
    }
    if (out) *out = QString::fromUtf8(p.readAllStandardOutput());
    if (err) *err = QString::fromUtf8(p.readAllStandardError());
}

QString Backend::settingsToConfig(const QVariantMap& s, const QString& domainsPath,
                                  const QString& targetsPath) const
{
    auto b = [](const QVariant& v) { return v.toBool() ? "true" : "false"; };
    QString out;
    auto add = [&out](const QString& key, const QString& value) {
        out += key + '=' + value + '\n';
    };
    add("split_enabled", b(s.value("split_enabled")));
    add("mss_clamp", b(s.value("mss_clamp")));
    add("split_delta", QString::number(s.value("split_delta").toInt()));
    add("split_stride", QString::number(s.value("split_stride").toInt()));
    add("split_max", QString::number(s.value("split_max").toInt()));
    add("split_gap_ms", QString::number(s.value("split_gap_ms").toInt()));
    add("split_disorder", b(s.value("split_disorder")));
    add("split_multidisorder", b(s.value("split_multidisorder")));
    add("split_jitter_ms", QString::number(s.value("split_jitter_ms").toInt()));
    add("fake_enabled", b(s.value("fake_enabled")));
    add("fake_ttl", QString::number(s.value("fake_ttl").toInt()));
    add("fake_repeats", QString::number(s.value("fake_repeats").toInt()));
    add("fake_sni", s.value("fake_sni").toString());
    add("fake_bad_checksum", b(s.value("fake_bad_checksum")));
    add("fake_seq_offset", QString::number(s.value("fake_seq_offset").toInt()));
    add("fake_timestamp", b(s.value("fake_timestamp")));
    add("seqovl_enabled", b(s.value("seqovl_enabled")));
    add("seqovl_bytes", QString::number(s.value("seqovl_bytes").toInt()));
    add("seqovl_repeats", QString::number(s.value("seqovl_repeats").toInt()));
    add("udp_fake_enabled", b(s.value("udp_fake_enabled")));
    add("udp_fake_ttl", QString::number(s.value("udp_fake_ttl").toInt()));
    add("udp_fake_repeats", QString::number(s.value("udp_fake_repeats").toInt()));
    add("udp_fake_type", s.value("udp_fake_type").toString());
    add("mss", QString::number(s.value("mss").toInt()));
    add("mss_value", QString::number(s.value("mss_value").toInt()));
    add("inspect_packets", QString::number(s.value("inspect_packets").toInt()));
    add("queue_num", QString::number(s.value("queue_num").toInt()));
    add("fwmark", s.value("fwmark").toString());
    add("max_queue_len", QString::number(s.value("max_queue_len").toInt()));
    add("copy_range", QString::number(s.value("copy_range").toInt()));
    add("ipv4", b(s.value("ipv4")));
    add("ipv6", b(s.value("ipv6")));
    add("ports", s.value("ports").toString());
    add("domains_file", domainsPath);
    add("profiles_file", QStringLiteral("/etc/mutekizu/profiles.conf"));
    add("mss_targets_file", targetsPath);
    add("log_level", s.value("log_level").toString());
    add("log_sni", b(s.value("log_sni")));
    add("max_flows", QString::number(s.value("max_flows").toInt()));
    add("flow_buffer", QString::number(s.value("flow_buffer").toInt()));
    add("flow_timeout_s", QString::number(s.value("flow_timeout_s").toInt()));
    add("auto_discover", b(s.value("auto_discover")));
    add("auto_profile", b(s.value("auto_profile")));
    add("auto_retry_window_s", QString::number(s.value("auto_retry_window_s").toInt()));
    add("reply_observe", b(s.value("reply_observe")));
    add("reply_queue_num", QString::number(s.value("reply_queue_num").toInt()));
    add("reply_inspect_packets", QString::number(s.value("reply_inspect_packets").toInt()));
    add("ip_frag_enabled", b(s.value("ip_frag_enabled")));
    add("ip_frag_queue_num", QString::number(s.value("ip_frag_queue_num").toInt()));
    add("ip_frag_size", QString::number(s.value("ip_frag_size").toInt()));
    add("ip_frag_inspect_packets", QString::number(s.value("ip_frag_inspect_packets").toInt()));
    add("ip_frag_targets_file", QStringLiteral("/etc/mutekizu/ip_frag_targets.txt"));
    add("ip_frag_ports", s.value("ip_frag_ports").toString());
    add("auto_domains_file", QStringLiteral("/var/lib/mutekizu/auto-domains.txt"));
    return out;
}

QString Backend::domainsToText(const QStringList& list) const
{
    QString out;
    for (const QString& d : list) out += d + '\n';
    return out;
}

QString Backend::targetsToText(const QStringList& list) const
{
    QString out;
    for (const QString& a : list) out += a + '\n';
    return out;
}

bool Backend::validDomain(const QString& d)
{
    if (d.isEmpty() || d.size() > 253) return false;
    if (d.startsWith('.') || d.endsWith('.')) return false;
    static const QRegularExpression re("^[A-Za-z0-9_.-]+$");
    return re.match(d).hasMatch();
}

bool Backend::validAddress(const QString& a)
{
    QHostAddress addr;
    return addr.setAddress(a) && !a.contains('/');
}

QString Backend::validateDraft()
{
    const int delta = m_draft.value("split_delta").toInt();
    const int stride = m_draft.value("split_stride").toInt();
    const int maxs = m_draft.value("split_max").toInt();
    const int gap = m_draft.value("split_gap_ms").toInt();
    const int chunk = m_draft.value("mss").toInt();
    const int mssValue = m_draft.value("mss_value").toInt();
    const int inspect = m_draft.value("inspect_packets").toInt();
    const int queue = m_draft.value("queue_num").toInt();
    const int maxq = m_draft.value("max_queue_len").toInt();
    const int copy = m_draft.value("copy_range").toInt();
    const int maxFlows = m_draft.value("max_flows").toInt();
    const int buf = m_draft.value("flow_buffer").toInt();
    const int timeout = m_draft.value("flow_timeout_s").toInt();
    const bool v4 = m_draft.value("ipv4").toBool();
    const bool v6 = m_draft.value("ipv6").toBool();
    const bool split = m_draft.value("split_enabled").toBool();
    const bool mss = m_draft.value("mss_clamp").toBool();

    if (!v4 && !v6) return tr("Должен быть включён IPv4 или IPv6.");
    if (!split && !mss) return tr("Должен быть включён хотя бы один режим: SNI-split или MSS-clamp.");
    if (delta < 1 || delta > 200) return tr("split_delta: допустимо 1..200.");
    if (stride < 0 || stride > 64) return tr("split_stride: допустимо 0..64.");
    if (maxs < 1 || maxs > 128) return tr("split_max: допустимо 1..128.");
    if (gap < 0 || gap > 100) return tr("split_gap_ms: допустимо 0..100.");
    if (chunk < 200 || chunk > 9000) return tr("mss (размер куска): допустимо 200..9000.");
    if (mssValue < 88 || mssValue > 536) return tr("mss_value: допустимо 88..536.");
    if (inspect < 1 || inspect > 64) return tr("inspect_packets: допустимо 1..64.");
    if (queue < 1 || queue > 65535) return tr("queue_num: допустимо 1..65535.");
    if (maxq < 1 || maxq > 65535) return tr("max_queue_len: допустимо 1..65535.");
    if (copy < 64 || copy > 65535) return tr("copy_range: допустимо 64..65535.");
    if (maxFlows < 1 || maxFlows > 65536) return tr("max_flows: допустимо 1..65536.");
    if (buf < 512 || buf > 65535) return tr("flow_buffer: допустимо 512..65535.");
    if (timeout < 1 || timeout > 3600) return tr("flow_timeout_s: допустимо 1..3600.");

    bool hexOk = false;
    const uint fw = m_draft.value("fwmark").toString().toUInt(&hexOk, 0);
    if (!hexOk || fw == 0 || fw == 0xffffffffu) return tr("fwmark: нужен ненулевой 32-битный hex.");

    const QString ports = m_draft.value("ports").toString();
    if (ports.isEmpty()) return tr("ports: укажите хотя бы один порт.");
    for (const QString& p : ports.split(',')) {
        bool ok = false;
        const int n = p.trimmed().toInt(&ok);
        if (!ok || n < 1 || n > 65535) return tr("ports: недопустимый порт '%1'.").arg(p);
    }

    if (split) {
        if (m_draftDomains.isEmpty()) return tr("Режим SNI-split включён, но список доменов пуст.");
        QSet<QString> seen;
        for (const QString& d0 : m_draftDomains) {
            const QString d = d0.trimmed();
            if (!validDomain(d)) return tr("Недопустимый домен: '%1'.").arg(d0);
            const QString k = d.toLower();
            if (seen.contains(k)) return tr("Дубликат домена: '%1'.").arg(d);
            seen.insert(k);
        }
        if (m_draftDomains.size() > 8192) return tr("Слишком много доменов (максимум 8192).");
    }
    if (mss) {
        if (m_draftMssTargets.isEmpty()) return tr("MSS-clamp включён, но список IP-целей пуст.");
        QSet<QString> seen;
        for (const QString& a : m_draftMssTargets) {
            if (!validAddress(a.trimmed())) return tr("Недопустимый IP (домены и CIDR запрещены): '%1'.").arg(a);
            if (seen.contains(a)) return tr("Дубликат IP: '%1'.").arg(a);
            seen.insert(a);
        }
    }

    const QString eng = enginePath();
    if (eng.isEmpty()) return tr("Движок mutekizu не найден; проверка backend невозможна.");
    QTemporaryDir dir;
    if (!dir.isValid()) return tr("Не удалось создать временный каталог.");
    const QString conf = dir.filePath("mutekizu.conf");
    const QString dom = dir.filePath("domains.txt");
    const QString tgt = dir.filePath("mss_targets.txt");
    const QString prof = dir.filePath("profiles.conf");
    auto write = [](const QString& path, const QString& text) {
        QFile f(path);
        return f.open(QIODevice::WriteOnly | QIODevice::Truncate) &&
               f.write(text.toUtf8()) == text.toUtf8().size();
    };
    if (!write(conf, settingsToConfig(m_draft, dom, tgt) +
                        QStringLiteral("\nprofiles_file=%1\n").arg(prof)) ||
        !write(dom, domainsToText(m_draftDomains)) ||
        !write(tgt, targetsToText(m_draftMssTargets)) ||
        !write(prof, m_draftProfilesText))
        return tr("Не удалось записать временную конфигурацию.");

    QProcess p;
    p.start(eng, {"validate", "-c", conf});
    if (!p.waitForFinished(8000)) {
        p.kill();
        return tr("validate: таймаут.");
    }
    if (p.exitCode() != 0) {
        return tr("Backend отклонил конфигурацию:\n%1")
            .arg(QString::fromUtf8(p.readAllStandardOutput() + p.readAllStandardError()).trimmed());
    }
    return {};
}

QString Backend::diffText()
{
    QStringList lines;
    for (auto it = m_draft.cbegin(); it != m_draft.cend(); ++it) {
        if (m_settings.value(it.key()) != it.value())
            lines << QStringLiteral("%1: %2 → %3")
                         .arg(it.key(), m_settings.value(it.key()).toString(), it.value().toString());
    }
    for (const QString& d : m_draftDomains)
        if (!m_domains.contains(d)) lines << "+ домен " + d;
    for (const QString& d : m_domains)
        if (!m_draftDomains.contains(d)) lines << "- домен " + d;
    for (const QString& a : m_draftMssTargets)
        if (!m_mssTargets.contains(a)) lines << "+ MSS IP " + a;
    for (const QString& a : m_mssTargets)
        if (!m_draftMssTargets.contains(a)) lines << "- MSS IP " + a;
    if (m_draftProfilesText != m_profilesText)
        lines << tr("profiles.conf изменён");
    return lines.isEmpty() ? tr("Изменений нет.") : lines.join('\n');
}

QString Backend::helperJson() const
{
    QJsonObject root;
    root["version"] = 1;
    QVariantMap s = m_draft;
    s["domains_file"] = QStringLiteral("/etc/mutekizu/domains.txt");
    s["mss_targets_file"] = QStringLiteral("/etc/mutekizu/mss_targets.txt");
    root["settings"] = QJsonObject::fromVariantMap(s);
    root["domains"] = QJsonArray::fromStringList(m_draftDomains);
    root["mss_targets"] = QJsonArray::fromStringList(m_draftMssTargets);
    root["profiles"] = m_draftProfilesText;
    return QString::fromUtf8(QJsonDocument(root).toJson(QJsonDocument::Compact));
}

void Backend::applyDraft()
{
    if (m_applyRunning) return;
    if (m_conflict) {
        setError(tr("Файлы изменены извне"), tr("Перечитайте конфигурацию и повторите правку."));
        return;
    }
    const QString err = validateDraft();
    if (!err.isEmpty()) {
        setError(tr("Проверка не пройдена"), err);
        m_applyMessage = err;
        emit applyStateChanged();
        return;
    }

    if (m_demo) {
        m_settings = m_draft;
        m_domains = m_draftDomains;
        m_mssTargets = m_draftMssTargets;
        m_profilesText = m_draftProfilesText;
        rebuildProfileBlocks();
        m_dirty = false;
        emit dirtyChanged();
        emit configChanged();
        emit draftChanged();
        m_applyMessage = tr("Демо: изменения применены (имитация, система не менялась)");
        emit applyStateChanged();
        m_logs.prepend(QVariantMap{{"time", QDateTime::currentDateTime().toString("HH:mm:ss")},
                                   {"level", "info"}, {"text", "Демо: конфигурация применена"}});
        emit logsChanged();
        return;
    }

    if (!haveInstalledHelper()) {
        setError(tr("Привилегированный helper не установлен"),
                 tr("Установите GUI: sudo gui/install-gui.sh. Запись в /etc без helper запрещена."));
        m_applyMessage = m_lastError;
        emit applyStateChanged();
        return;
    }
    if (hashesChanged()) {
        m_conflict = true;
        emit conflictChanged();
        setError(tr("Файлы изменены извне после загрузки"),
                 tr("Перечитайте конфигурацию; молча перезаписывать нельзя."));
        return;
    }

    m_applyRunning = true;
    m_applyMessage = tr("Ожидание авторизации Polkit…");
    emit applyStateChanged();
    clearError();

    m_applyProcess = new QProcess(this);
    m_applyProcess->setProcessChannelMode(QProcess::SeparateChannels);
    connect(m_applyProcess, &QProcess::finished, this, [this](int code, QProcess::ExitStatus status) {
        const QString out = QString::fromUtf8(m_applyProcess->readAllStandardOutput());
        const QString err = QString::fromUtf8(m_applyProcess->readAllStandardError());
        m_applyProcess->deleteLater();
        m_applyProcess = nullptr;
        m_applyRunning = false;
        if (status != QProcess::NormalExit || code != 0) {
            QString msg = err.trimmed();
            if (msg.isEmpty()) msg = out.trimmed();
            if (msg.isEmpty()) msg = tr("Авторизация отменена или helper завершился с ошибкой.");
            setError(tr("Не удалось сохранить конфигурацию"), msg);
            m_applyMessage = msg;
            emit applyStateChanged();
            return;
        }
        loadFiles();
        m_draft = m_settings;
        m_draftDomains = m_domains;
        m_draftMssTargets = m_mssTargets;
        m_draftProfilesText = m_profilesText;
        rebuildProfileBlocks();
        rememberHashes();
        m_dirty = false;
        m_conflict = false;
        emit dirtyChanged();
        emit conflictChanged();
        emit configChanged();
        emit draftChanged();
        m_applyMessage = tr("Конфигурация сохранена.");
        emit applyStateChanged();
        if (m_installed && (m_state == "running" || m_state == "starting"))
            restartService();
    });
    connect(m_applyProcess, &QProcess::errorOccurred, this, [this](QProcess::ProcessError) {
        if (!m_applyProcess) return;
        m_applyRunning = false;
        setError(tr("Не удалось запустить helper"), m_applyProcess->errorString());
        m_applyMessage = m_lastError;
        m_applyProcess->deleteLater();
        m_applyProcess = nullptr;
        emit applyStateChanged();
    });
    m_applyProcess->start(QStringLiteral("/usr/bin/pkexec"), {helperPath()});
    if (!m_applyProcess->waitForStarted(2000)) {
        m_applyRunning = false;
        setError(tr("Не удалось запустить pkexec"), tr("Проверьте Polkit и установку helper."));
        m_applyProcess->deleteLater();
        m_applyProcess = nullptr;
        emit applyStateChanged();
        return;
    }
    m_applyProcess->write(helperJson().toUtf8());
    m_applyProcess->closeWriteChannel();
}

void Backend::cancelApply()
{
    if (m_applyProcess) {
        m_applyProcess->kill();
        m_applyMessage = tr("Применение отменено.");
        emit applyStateChanged();
    }
}

QVariantList Backend::parseDoctor(const QString& text) const
{
    QVariantList out;
    const QStringList lines = text.split('\n');
    for (const QString& raw : lines) {
        const QString line = raw.trimmed();
        if (line.isEmpty()) continue;
        QString level, msg;
        if (line.startsWith("[ ok ]")) { level = "ok"; msg = line.mid(6).trimmed(); }
        else if (line.startsWith("[warn]")) { level = "warn"; msg = line.mid(6).trimmed(); }
        else if (line.startsWith("[fail]")) { level = "fail"; msg = line.mid(6).trimmed(); }
        else if (line.startsWith("note:")) { level = "unknown"; msg = line.mid(5).trimmed(); }
        else {
            if (out.isEmpty()) continue;
            auto last = out.last().toMap();
            last["text"] = last.value("text").toString() + '\n' + line;
            out.last() = last;
            continue;
        }
        out << QVariantMap{{"level", level}, {"text", msg}};
    }
    return out;
}

void Backend::runDoctor()
{
    if (m_doctorProcess) return;
    if (enginePath().isEmpty()) {
        m_diagnostics = {QVariantMap{{"level", "fail"}, {"text", tr("Движок mutekizu не найден")}}};
        m_diagnosticsRaw = m_lastError;
        emit diagnosticsChanged();
        return;
    }
    m_doctorTemp = std::make_unique<QTemporaryDir>();
    QString conf = m_configPath;
    if (!m_configAvailable || !m_demo) {
        const QString dom = m_doctorTemp->filePath("domains.txt");
        const QString tgt = m_doctorTemp->filePath("mss_targets.txt");
        conf = m_doctorTemp->filePath("mutekizu.conf");
        auto write = [](const QString& path, const QString& text) {
            QFile f(path);
            return f.open(QIODevice::WriteOnly | QIODevice::Truncate) && f.write(text.toUtf8()) >= 0;
        };
        write(conf, settingsToConfig(m_draft, dom, tgt));
        write(dom, domainsToText(m_draftDomains));
        write(tgt, targetsToText(m_draftMssTargets));
    }
    m_doctorProcess = new QProcess(this);
    setBusy(true);
    m_doctorProcess->setProcessChannelMode(QProcess::MergedChannels);
    connect(m_doctorProcess, &QProcess::finished, this, [this](int, QProcess::ExitStatus) {
        const QString text = QString::fromUtf8(m_doctorProcess->readAllStandardOutput());
        m_diagnosticsRaw = text;
        m_diagnostics = parseDoctor(text);
        if (m_diagnostics.isEmpty()) {
            m_diagnostics = {QVariantMap{{"level", "fail"},
                                         {"text", tr("doctor не вернул структурированных строк")}}};
        }
        m_doctorProcess->deleteLater();
        m_doctorProcess = nullptr;
        m_doctorTemp.reset();
        setBusy(false);
        emit diagnosticsChanged();
    });
    connect(m_doctorProcess, &QProcess::errorOccurred, this, [this](QProcess::ProcessError) {
        setError(tr("Не удалось запустить doctor"), m_doctorProcess->errorString());
        m_doctorProcess->deleteLater();
        m_doctorProcess = nullptr;
        setBusy(false);
    });
    m_doctorProcess->start(enginePath(), {"doctor", "-c", conf});
    QTimer::singleShot(12000, this, [this] {
        if (m_doctorProcess) {
            m_doctorProcess->kill();
            setError(tr("doctor: таймаут"), tr("Диагностика не завершилась за 12 секунд."));
        }
    });
}

void Backend::refreshLogs()
{
    if (m_logPaused || m_logProcess) return;
    const QString jc = QStandardPaths::findExecutable("journalctl");
    if (jc.isEmpty()) {
        m_journalError = tr("journalctl не найден");
        emit logsChanged();
        return;
    }
    m_logProcess = new QProcess(this);
    m_logProcess->setProcessChannelMode(QProcess::SeparateChannels);
    connect(m_logProcess, &QProcess::finished, this, [this, jc](int code, QProcess::ExitStatus) {
        const QString err = QString::fromUtf8(m_logProcess->readAllStandardError());
        const QString out = QString::fromUtf8(m_logProcess->readAllStandardOutput());
        m_logProcess->deleteLater();
        m_logProcess = nullptr;
        if (code != 0) {
            m_journalError = err.trimmed().isEmpty()
                                 ? tr("Нет доступа к журналу службы (код %1)").arg(code)
                                 : err.trimmed();
            m_logs.clear();
            emit logsChanged();
            return;
        }
        m_journalError.clear();
        QVariantList rows;
        for (const QString& line : out.split('\n')) {
            if (line.trimmed().isEmpty()) continue;
            QString level = "info";
            const QString lower = line.toLower();
            if (lower.contains("error") || lower.contains("ошибка") || lower.contains("fail")) level = "error";
            else if (lower.contains("warn")) level = "warn";
            else if (lower.contains("debug")) level = "debug";
            QString time;
            const QStringList parts = line.split(' ');
            if (!parts.isEmpty()) time = parts.first();
            rows << QVariantMap{{"time", time}, {"level", level}, {"text", line}};
        }
        m_logs = rows;
        emit logsChanged();
    });
    connect(m_logProcess, &QProcess::errorOccurred, this, [this](QProcess::ProcessError) {
        m_journalError = m_logProcess->errorString();
        m_logProcess->deleteLater();
        m_logProcess = nullptr;
        emit logsChanged();
    });
    m_logProcess->start(jc, {"-u", QString::fromLatin1(kService), "--no-pager", "-n", "200",
                             "--output=short-iso", "--since=-1h"});
    QTimer::singleShot(9000, this, [this] {
        if (m_logProcess) m_logProcess->kill();
    });
}

void Backend::setLogPaused(bool paused)
{
    if (m_logPaused == paused) return;
    m_logPaused = paused;
    emit logsChanged();
}

QString Backend::readTextFile(const QString& path)
{
    QString p = path.trimmed();
    if (p.startsWith("~/")) p = QDir::homePath() + p.mid(1);
    QFile f(p);
    if (!f.open(QIODevice::ReadOnly | QIODevice::Text)) {
        setError(tr("Не удалось прочитать файл"), f.errorString());
        return {};
    }
    return QString::fromUtf8(f.readAll());
}

bool Backend::exportText(const QString& path, const QString& text)
{
    if (path.trimmed().isEmpty()) {
        setError(tr("Не указан путь для экспорта"));
        return false;
    }
    QString p = path.trimmed();
    if (p.startsWith("~/")) p = QDir::homePath() + p.mid(1);
    QSaveFile f(p);
    if (!f.open(QIODevice::WriteOnly)) {
        setError(tr("Не удалось открыть файл"), f.errorString());
        return false;
    }
    if (f.write(text.toUtf8()) < 0 || !f.commit()) {
        setError(tr("Не удалось записать файл"), f.errorString());
        return false;
    }
    m_applyMessage = tr("Экспортировано: %1").arg(path);
    emit applyStateChanged();
    return true;
}

void Backend::simulateFailure()
{
    if (!m_demo) return;
    setState("failed");
    setError(tr("Демо: имитация ошибки службы"),
             tr("Это демонстрационный статус, не реальная ошибка."));
}
