// Narrow privileged writer for mutekizu configuration.
//
// It accepts only one structured JSON document on stdin and writes exactly the
// three fixed files under /etc/mutekizu. It never accepts paths, commands or
// a service name. It is not setuid; the GUI runs it through pkexec, so Polkit
// performs the interactive authorization.
#include <QCoreApplication>
#include <QDir>
#include <QFile>
#include <QHostAddress>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QRegularExpression>
#include <QSet>
#include <QStringList>

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <string>

namespace {

constexpr const char* kDir = "/etc/mutekizu";
constexpr const char* kConfig = "mutekizu.conf";
constexpr const char* kDomains = "domains.txt";
constexpr const char* kTargets = "mss_targets.txt";
constexpr const char* kProfiles = "profiles.conf";
constexpr std::size_t kMaxInput = 64 * 1024;

std::string err;
bool fail(const QString& s)
{
    err = s.toStdString();
    return false;
}

bool validDomain(const QString& d)
{
    if (d.isEmpty() || d.size() > 253) return false;
    if (d.startsWith('.') || d.endsWith('.')) return false;
    static const QRegularExpression re("^[A-Za-z0-9_.-]+$");
    return re.match(d).hasMatch();
}

bool validAddress(const QString& a)
{
    QHostAddress h;
    return !a.contains('/') && h.setAddress(a);
}

bool isInt(const QJsonValue& v, int lo, int hi, int& out)
{
    if (!v.isDouble()) return false;
    const double d = v.toDouble();
    if (d != static_cast<double>(static_cast<int>(d))) return false;
    if (d < lo || d > hi) return false;
    out = static_cast<int>(d);
    return true;
}

bool parsePorts(const QString& text, QString& normalized)
{
    QStringList parts;
    for (const QString& raw : text.split(',')) {
        bool ok = false;
        const int n = raw.trimmed().toInt(&ok);
        if (!ok || n < 1 || n > 65535) return false;
        parts << QString::number(n);
    }
    if (parts.isEmpty()) return false;
    normalized = parts.join(',');
    return true;
}

struct Payload {
    QJsonObject settings;
    QStringList domains;
    QStringList targets;
    QString profiles;
    bool hasProfiles = false;
};

bool parsePayload(const QByteArray& bytes, Payload& p)
{
    QJsonParseError pe{};
    const QJsonDocument doc = QJsonDocument::fromJson(bytes, &pe);
    if (pe.error != QJsonParseError::NoError || !doc.isObject())
        return fail(QStringLiteral("invalid JSON: %1").arg(pe.errorString()));
    const QJsonObject root = doc.object();
    if (root.value("version").toInt() != 1)
        return fail(QStringLiteral("unsupported schema version"));
    if (!root.value("settings").isObject())
        return fail(QStringLiteral("settings must be an object"));
    if (!root.value("domains").isArray() || !root.value("mss_targets").isArray())
        return fail(QStringLiteral("domains and mss_targets must be arrays"));

    p.settings = root.value("settings").toObject();
    if (root.contains("profiles")) {
        if (!root.value("profiles").isString())
            return fail(QStringLiteral("profiles must be a string"));
        p.profiles = root.value("profiles").toString();
        if (p.profiles.size() > 262144)
            return fail(QStringLiteral("profiles file is too large"));
        p.hasProfiles = true;
    }
    static const QStringList allowed{
        "split_enabled", "mss_clamp", "split_delta", "split_stride", "split_max",
        "split_gap_ms", "split_disorder", "split_multidisorder", "split_jitter_ms",
        "fake_enabled", "fake_ttl", "fake_repeats", "fake_sni", "fake_bad_checksum",
        "fake_seq_offset", "fake_timestamp", "seqovl_enabled",
        "seqovl_bytes", "seqovl_repeats", "udp_fake_enabled", "udp_fake_ttl",
        "udp_fake_repeats", "udp_fake_type", "mss", "mss_value", "inspect_packets",
        "queue_num", "fwmark",
        "max_queue_len", "copy_range", "ipv4", "ipv6", "ports", "log_level", "log_sni",
        "max_flows", "flow_buffer", "flow_timeout_s", "domains_file", "profiles_file", "mss_targets_file",
        "auto_discover", "auto_domains_file", "auto_profile", "auto_retry_window_s",
        "reply_observe", "reply_queue_num", "reply_inspect_packets",
        "ip_frag_enabled", "ip_frag_queue_num", "ip_frag_size",
        "ip_frag_inspect_packets", "ip_frag_targets_file", "ip_frag_ports"};
    for (auto it = p.settings.begin(); it != p.settings.end(); ++it) {
        if (!allowed.contains(it.key()))
            return fail(QStringLiteral("unknown setting: %1").arg(it.key()));
    }

    auto requireBool = [&](const char* key, bool& out) {
        const QJsonValue v = p.settings.value(key);
        if (!v.isBool()) return fail(QStringLiteral("%1 must be boolean").arg(key));
        out = v.toBool();
        return true;
    };
    bool split = false, mss = false, v4 = false, v6 = false, logSni = false;
    bool autoDiscover = true, autoProfile = true, replyObserve = true;
    bool ipFragEnabled = false;
    bool splitDisorder = false, splitMultidisorder = false;
    bool fakeEnabled = false, seqovlEnabled = false, udpFakeEnabled = false;
    bool fakeBadChecksum = false, fakeTimestamp = false;
    if (!requireBool("split_enabled", split) || !requireBool("mss_clamp", mss) ||
        !requireBool("ipv4", v4) || !requireBool("ipv6", v6) ||
        !requireBool("log_sni", logSni))
        return false;
    if (p.settings.contains("auto_discover") &&
        !requireBool("auto_discover", autoDiscover))
        return false;
    if (p.settings.contains("auto_profile") &&
        !requireBool("auto_profile", autoProfile))
        return false;
    if (p.settings.contains("reply_observe") &&
        !requireBool("reply_observe", replyObserve))
        return false;
    if (p.settings.contains("ip_frag_enabled") &&
        !requireBool("ip_frag_enabled", ipFragEnabled))
        return false;
    if (p.settings.contains("split_disorder") &&
        !requireBool("split_disorder", splitDisorder))
        return false;
    if (p.settings.contains("split_multidisorder") &&
        !requireBool("split_multidisorder", splitMultidisorder))
        return false;
    if (p.settings.contains("seqovl_enabled") &&
        !requireBool("seqovl_enabled", seqovlEnabled))
        return false;
    if (p.settings.contains("udp_fake_enabled") &&
        !requireBool("udp_fake_enabled", udpFakeEnabled))
        return false;
    if (p.settings.contains("fake_enabled") &&
        !requireBool("fake_enabled", fakeEnabled))
        return false;
    if (p.settings.contains("fake_bad_checksum") &&
        !requireBool("fake_bad_checksum", fakeBadChecksum))
        return false;
    if (p.settings.contains("fake_timestamp") &&
        !requireBool("fake_timestamp", fakeTimestamp))
        return false;
    if (!v4 && !v6) return fail(QStringLiteral("at least one of ipv4/ipv6 must be enabled"));
    if (!split && !mss) return fail(QStringLiteral("at least one mode must be enabled"));

    int delta = 0, stride = 0, maxs = 0, gap = 0, chunk = 0, mssValue = 0, inspect = 0;
    int queue = 0, maxq = 0, copy = 0, maxFlows = 0, buf = 0, timeout = 0;
    int fakeTtl = 0, fakeRepeats = 0, splitJitter = 0, seqovlBytes = 0, seqovlRepeats = 0;
    int fakeSeqOffset = 0;
    int udpFakeTtl = 0, udpFakeRepeats = 0, autoRetryWindow = 0;
    int replyQueue = 0, replyInspect = 0, ipFragQueue = 0, ipFragSize = 0, ipFragInspect = 0;
    if (!isInt(p.settings.value("split_delta"), 1, 200, delta) ||
        !isInt(p.settings.value("split_stride"), 0, 64, stride) ||
        !isInt(p.settings.value("split_max"), 1, 128, maxs) ||
        !isInt(p.settings.value("split_gap_ms"), 0, 100, gap) ||
        !isInt(p.settings.value("mss"), 200, 9000, chunk) ||
        !isInt(p.settings.value("mss_value"), 88, 536, mssValue) ||
        !isInt(p.settings.value("inspect_packets"), 1, 64, inspect) ||
        !isInt(p.settings.value("queue_num"), 1, 65535, queue) ||
        !isInt(p.settings.value("max_queue_len"), 1, 65535, maxq) ||
        !isInt(p.settings.value("copy_range"), 64, 65535, copy) ||
        !isInt(p.settings.value("max_flows"), 1, 65536, maxFlows) ||
        !isInt(p.settings.value("flow_buffer"), 512, 65535, buf) ||
        !isInt(p.settings.value("flow_timeout_s"), 1, 3600, timeout))
        return fail(QStringLiteral("numeric setting out of range or wrong type"));

    splitJitter = 0;
    fakeTtl = 3;
    fakeRepeats = 3;
    seqovlBytes = 646;
    seqovlRepeats = 1;
    udpFakeTtl = 4;
    udpFakeRepeats = 5;
    autoRetryWindow = 10;
    replyQueue = 2001;
    replyInspect = 3;
    ipFragQueue = 2002;
    ipFragSize = 512;
    ipFragInspect = 10;
    if (p.settings.contains("ip_frag_queue_num") &&
        !isInt(p.settings.value("ip_frag_queue_num"), 1, 65535, ipFragQueue))
        return fail(QStringLiteral("invalid ip_frag_queue_num"));
    if (p.settings.contains("ip_frag_size") &&
        !isInt(p.settings.value("ip_frag_size"), 128, 9000, ipFragSize))
        return fail(QStringLiteral("invalid ip_frag_size"));
    if (p.settings.contains("ip_frag_inspect_packets") &&
        !isInt(p.settings.value("ip_frag_inspect_packets"), 1, 64, ipFragInspect))
        return fail(QStringLiteral("invalid ip_frag_inspect_packets"));
    if (p.settings.contains("reply_queue_num") &&
        !isInt(p.settings.value("reply_queue_num"), 1, 65535, replyQueue))
        return fail(QStringLiteral("invalid reply_queue_num"));
    if (p.settings.contains("reply_inspect_packets") &&
        !isInt(p.settings.value("reply_inspect_packets"), 1, 16, replyInspect))
        return fail(QStringLiteral("invalid reply_inspect_packets"));
    if (p.settings.contains("auto_retry_window_s") &&
        !isInt(p.settings.value("auto_retry_window_s"), 1, 300, autoRetryWindow))
        return fail(QStringLiteral("invalid auto_retry_window_s"));
    if (p.settings.contains("split_jitter_ms") &&
        !isInt(p.settings.value("split_jitter_ms"), 0, 50, splitJitter))
        return fail(QStringLiteral("invalid split_jitter_ms"));
    if (p.settings.contains("seqovl_bytes") &&
        !isInt(p.settings.value("seqovl_bytes"), 1, 1400, seqovlBytes))
        return fail(QStringLiteral("invalid seqovl_bytes"));
    if (p.settings.contains("seqovl_repeats") &&
        !isInt(p.settings.value("seqovl_repeats"), 1, 16, seqovlRepeats))
        return fail(QStringLiteral("invalid seqovl_repeats"));
    if (p.settings.contains("udp_fake_ttl") &&
        !isInt(p.settings.value("udp_fake_ttl"), 1, 64, udpFakeTtl))
        return fail(QStringLiteral("invalid udp_fake_ttl"));
    if (p.settings.contains("udp_fake_repeats") &&
        !isInt(p.settings.value("udp_fake_repeats"), 1, 16, udpFakeRepeats))
        return fail(QStringLiteral("invalid udp_fake_repeats"));
    if (p.settings.contains("fake_ttl") &&
        !isInt(p.settings.value("fake_ttl"), 1, 64, fakeTtl))
        return fail(QStringLiteral("invalid fake_ttl"));
    if (p.settings.contains("fake_repeats") &&
        !isInt(p.settings.value("fake_repeats"), 1, 16, fakeRepeats))
        return fail(QStringLiteral("invalid fake_repeats"));
    if (p.settings.contains("fake_seq_offset") &&
        !isInt(p.settings.value("fake_seq_offset"), -32768, 32767, fakeSeqOffset))
        return fail(QStringLiteral("invalid fake_seq_offset"));
    const QString udpFakeType = (p.settings.contains("udp_fake_type")
                                     ? p.settings.value("udp_fake_type").toString()
                                     : QStringLiteral("stun"));
    if (udpFakeType != "stun" && udpFakeType != "quic" &&
        udpFakeType != "discord" && udpFakeType != "random")
        return fail(QStringLiteral("invalid udp_fake_type"));

    const QString fakeSni = (p.settings.contains("fake_sni")
                                 ? p.settings.value("fake_sni").toString()
                                 : QStringLiteral("www.microsoft.com")).trimmed();
    if (fakeSni.isEmpty() || !validDomain(fakeSni))
        return fail(QStringLiteral("invalid fake_sni"));

    const QString fw = p.settings.value("fwmark").toString();
    bool hexOk = false;
    const uint fwmark = fw.toUInt(&hexOk, 0);
    if (!hexOk || fwmark == 0 || fwmark == 0xffffffffu)
        return fail(QStringLiteral("invalid fwmark"));
    QString ports;
    if (!parsePorts(p.settings.value("ports").toString(), ports))
        return fail(QStringLiteral("invalid ports"));
    const QString logLevel = p.settings.value("log_level").toString();
    if (!QStringList{"error", "warn", "info", "debug"}.contains(logLevel))
        return fail(QStringLiteral("invalid log_level"));

    p.domains.clear();
    QSet<QString> seen;
    const QJsonArray da = root.value("domains").toArray();
    if (da.size() > 8192) return fail(QStringLiteral("too many domains"));
    for (const QJsonValue& v : da) {
        if (!v.isString()) return fail(QStringLiteral("domain must be a string"));
        const QString d = v.toString().trimmed();
        if (!validDomain(d)) return fail(QStringLiteral("invalid domain: %1").arg(d));
        if (seen.contains(d.toLower())) return fail(QStringLiteral("duplicate domain: %1").arg(d));
        seen.insert(d.toLower());
        p.domains << d;
    }
    if (split && p.domains.isEmpty()) return fail(QStringLiteral("split enabled but domains empty"));

    p.targets.clear();
    QSet<QString> addrs;
    const QJsonArray ta = root.value("mss_targets").toArray();
    if (ta.size() > 512) return fail(QStringLiteral("too many mss targets"));
    for (const QJsonValue& v : ta) {
        if (!v.isString()) return fail(QStringLiteral("mss target must be a string"));
        const QString a = v.toString().trimmed();
        if (!validAddress(a)) return fail(QStringLiteral("invalid IP: %1").arg(a));
        const QHostAddress h(a);
        const QString canon = h.toString();
        if (addrs.contains(canon)) return fail(QStringLiteral("duplicate IP: %1").arg(canon));
        addrs.insert(canon);
        p.targets << canon;
    }
    if (mss && p.targets.isEmpty()) return fail(QStringLiteral("mss clamp enabled but targets empty"));

    // The helper owns the paths; any supplied path is ignored.
    p.settings["domains_file"] = QStringLiteral("/etc/mutekizu/domains.txt");
    p.settings["profiles_file"] = QStringLiteral("/etc/mutekizu/profiles.conf");
    p.settings["ip_frag_targets_file"] = QStringLiteral("/etc/mutekizu/ip_frag_targets.txt");
    p.settings["mss_targets_file"] = QStringLiteral("/etc/mutekizu/mss_targets.txt");
    p.settings["auto_domains_file"] = QStringLiteral("/var/lib/mutekizu/auto-domains.txt");
    return true;
}

QString configText(const Payload& p)
{
    auto b = [](bool v) { return v ? "true" : "false"; };
    QString out;
    auto add = [&out](const char* k, const QString& v) { out += QString::fromLatin1(k) + '=' + v + '\n'; };
    const QJsonObject& s = p.settings;
    add("split_enabled", b(s.value("split_enabled").toBool()));
    add("mss_clamp", b(s.value("mss_clamp").toBool()));
    add("split_delta", QString::number(s.value("split_delta").toInt()));
    add("split_stride", QString::number(s.value("split_stride").toInt()));
    add("split_max", QString::number(s.value("split_max").toInt()));
    add("split_gap_ms", QString::number(s.value("split_gap_ms").toInt()));
    add("split_disorder", b(s.value("split_disorder").toBool(false)));
    add("split_multidisorder", b(s.value("split_multidisorder").toBool(false)));
    add("split_jitter_ms", QString::number(s.value("split_jitter_ms").toInt(0)));
    add("fake_enabled", b(s.value("fake_enabled").toBool(true)));
    add("fake_ttl", QString::number(s.value("fake_ttl").toInt(3)));
    add("fake_repeats", QString::number(s.value("fake_repeats").toInt(3)));
    add("fake_sni", s.contains("fake_sni") ? s.value("fake_sni").toString()
                                           : QStringLiteral("www.microsoft.com"));
    add("fake_bad_checksum", b(s.value("fake_bad_checksum").toBool(false)));
    add("fake_seq_offset", QString::number(s.value("fake_seq_offset").toInt(0)));
    add("fake_timestamp", b(s.value("fake_timestamp").toBool(false)));
    add("seqovl_enabled", b(s.value("seqovl_enabled").toBool(true)));
    add("seqovl_bytes", QString::number(s.value("seqovl_bytes").toInt(646)));
    add("seqovl_repeats", QString::number(s.value("seqovl_repeats").toInt(1)));
    add("udp_fake_enabled", b(s.value("udp_fake_enabled").toBool(true)));
    add("udp_fake_ttl", QString::number(s.value("udp_fake_ttl").toInt(4)));
    add("udp_fake_repeats", QString::number(s.value("udp_fake_repeats").toInt(5)));
    add("udp_fake_type", s.value("udp_fake_type").toString(QStringLiteral("stun")));
    add("mss", QString::number(s.value("mss").toInt()));
    add("mss_value", QString::number(s.value("mss_value").toInt()));
    add("inspect_packets", QString::number(s.value("inspect_packets").toInt()));
    add("queue_num", QString::number(s.value("queue_num").toInt()));
    add("fwmark", s.value("fwmark").toString());
    add("max_queue_len", QString::number(s.value("max_queue_len").toInt()));
    add("copy_range", QString::number(s.value("copy_range").toInt()));
    add("ipv4", b(s.value("ipv4").toBool()));
    add("ipv6", b(s.value("ipv6").toBool()));
    add("ports", s.value("ports").toString());
    add("domains_file", QStringLiteral("/etc/mutekizu/domains.txt"));
    add("profiles_file", QStringLiteral("/etc/mutekizu/profiles.conf"));
    add("mss_targets_file", QStringLiteral("/etc/mutekizu/mss_targets.txt"));
    add("log_level", s.value("log_level").toString());
    add("log_sni", b(s.value("log_sni").toBool()));
    add("max_flows", QString::number(s.value("max_flows").toInt()));
    add("flow_buffer", QString::number(s.value("flow_buffer").toInt()));
    add("flow_timeout_s", QString::number(s.value("flow_timeout_s").toInt()));
    add("auto_discover", b(s.value("auto_discover").toBool(true)));
    add("auto_profile", b(s.value("auto_profile").toBool(true)));
    add("auto_retry_window_s", QString::number(s.value("auto_retry_window_s").toInt(10)));
    add("reply_observe", b(s.value("reply_observe").toBool(true)));
    add("reply_queue_num", QString::number(s.value("reply_queue_num").toInt(2001)));
    add("reply_inspect_packets", QString::number(s.value("reply_inspect_packets").toInt(3)));
    add("ip_frag_enabled", b(s.value("ip_frag_enabled").toBool(false)));
    add("ip_frag_queue_num", QString::number(s.value("ip_frag_queue_num").toInt(2002)));
    add("ip_frag_size", QString::number(s.value("ip_frag_size").toInt(512)));
    add("ip_frag_inspect_packets", QString::number(s.value("ip_frag_inspect_packets").toInt(10)));
    add("ip_frag_targets_file", QStringLiteral("/etc/mutekizu/ip_frag_targets.txt"));
    add("ip_frag_ports", s.value("ip_frag_ports").toString());
    add("auto_domains_file", QStringLiteral("/var/lib/mutekizu/auto-domains.txt"));
    return out;
}

bool writeAll(int dirfd, const char* name, const QByteArray& data, bool backup)
{
    const QString tmpName = QStringLiteral(".%1.tmp.%2").arg(QString::fromLatin1(name)).arg(getpid());
    const QByteArray tmp = tmpName.toUtf8();
    const int fd = openat(dirfd, tmp.constData(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0644);
    if (fd < 0) return fail(QStringLiteral("openat temp %1: %2").arg(tmpName, QString::fromLocal8Bit(std::strerror(errno))));
    std::size_t off = 0;
    while (off < static_cast<std::size_t>(data.size())) {
        const ssize_t n = ::write(fd, data.constData() + off, static_cast<std::size_t>(data.size()) - off);
        if (n < 0) {
            if (errno == EINTR) continue;
            ::close(fd);
            unlinkat(dirfd, tmp.constData(), 0);
            return fail(QStringLiteral("write: %1").arg(QString::fromLocal8Bit(std::strerror(errno))));
        }
        off += static_cast<std::size_t>(n);
    }
    if (fchown(fd, 0, 0) != 0 || fchmod(fd, 0644) != 0 || fsync(fd) != 0) {
        ::close(fd);
        unlinkat(dirfd, tmp.constData(), 0);
        return fail(QStringLiteral("fchown/fchmod/fsync"));
    }
    ::close(fd);
    if (backup) {
        const QString bak = QString::fromLatin1(name) + ".bak";
        renameat(dirfd, name, dirfd, bak.toUtf8().constData()); // best effort; ENOENT is fine
        errno = 0;
    }
    if (renameat(dirfd, tmp.constData(), dirfd, name) != 0) {
        unlinkat(dirfd, tmp.constData(), 0);
        return fail(QStringLiteral("renameat: %1").arg(QString::fromLocal8Bit(std::strerror(errno))));
    }
    return true;
}

bool rollbackWritten(int dirfd, const char* const* names, int count)
{
    bool ok = true;
    for (int i = count - 1; i >= 0; --i) {
        const QString bak = QString::fromLatin1(names[i]) + ".bak";
        struct stat st{};
        if (fstatat(dirfd, bak.toUtf8().constData(), &st, AT_SYMLINK_NOFOLLOW) == 0) {
            if (renameat(dirfd, bak.toUtf8().constData(), dirfd, names[i]) != 0) ok = false;
        } else {
            unlinkat(dirfd, names[i], 0); // file did not exist before
        }
    }
    return ok;
}

bool writeFiles(const Payload& p)
{
    struct stat st{};
    if (lstat(kDir, &st) != 0) {
        if (mkdir(kDir, 0755) != 0)
            return fail(QStringLiteral("mkdir %1: %2").arg(kDir, QString::fromLocal8Bit(std::strerror(errno))));
        if (lstat(kDir, &st) != 0) return fail(QStringLiteral("lstat %1").arg(kDir));
    }
    if (!S_ISDIR(st.st_mode)) return fail(QStringLiteral("/etc/mutekizu is not a directory"));
    if (st.st_uid != 0) return fail(QStringLiteral("/etc/mutekizu is not owned by root"));
    const int dirfd = open(kDir, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (dirfd < 0) return fail(QStringLiteral("open %1: %2").arg(kDir, QString::fromLocal8Bit(std::strerror(errno))));

    auto noSymlink = [&](const char* name) -> bool {
        struct stat t{};
        if (lstat((std::string(kDir) + "/" + name).c_str(), &t) == 0 && S_ISLNK(t.st_mode))
            return fail(QStringLiteral("refusing symlink: %1").arg(name));
        return true;
    };
    if (!noSymlink(kConfig) || !noSymlink(kDomains) || !noSymlink(kTargets) ||
        !noSymlink(kProfiles)) { ::close(dirfd); return false; }

    QByteArray domains;
    for (const QString& d : p.domains) domains += d.toUtf8() + '\n';
    QByteArray targets;
    for (const QString& a : p.targets) targets += a.toUtf8() + '\n';

    std::vector<const char*> names{kConfig, kDomains, kTargets};
    std::vector<QByteArray> payloads{configText(p).toUtf8(), domains, targets};
    if (p.hasProfiles) {
        names.push_back(kProfiles);
        payloads.push_back(p.profiles.toUtf8());
    }
    for (std::size_t i = 0; i < names.size(); ++i) {
        if (!writeAll(dirfd, names[i], payloads[i], true)) {
            const std::string saved = err;
            rollbackWritten(dirfd, names.data(), static_cast<int>(i));
            ::close(dirfd);
            err = saved;
            return false;
        }
    }
    ::close(dirfd);
    return true;
}

} // namespace

int main(int argc, char** argv)
{
    QCoreApplication app(argc, argv);
    const bool checkOnly = (argc > 1 && QString::fromLocal8Bit(argv[1]) == "--check");
    if (argc > 1 && !checkOnly) {
        std::fprintf(stderr, "usage: %s [--check]\n", argv[0]);
        return 2;
    }
    if (!checkOnly && geteuid() != 0) {
        std::fprintf(stderr, "{\"ok\":false,\"error\":\"root privileges required\"}\n");
        return 1;
    }

    QByteArray input;
    char buf[4096];
    ssize_t n = 0;
    while ((n = ::read(STDIN_FILENO, buf, sizeof(buf))) > 0) {
        input.append(buf, static_cast<int>(n));
        if (input.size() > static_cast<int>(kMaxInput)) {
            std::fprintf(stderr, "{\"ok\":false,\"error\":\"input too large\"}\n");
            return 2;
        }
    }
    if (n < 0) {
        std::fprintf(stderr, "{\"ok\":false,\"error\":\"read failed\"}\n");
        return 2;
    }

    Payload p;
    if (!parsePayload(input, p)) {
        std::fprintf(stderr, "{\"ok\":false,\"error\":\"%s\"}\n", err.c_str());
        return 2;
    }
    if (checkOnly) {
        std::printf("{\"ok\":true}\n");
        return 0;
    }
    if (!writeFiles(p)) {
        std::fprintf(stderr, "{\"ok\":false,\"error\":\"%s\"}\n", err.c_str());
        return 3;
    }
    std::printf("{\"ok\":true}\n");
    return 0;
}
