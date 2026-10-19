#pragma once

#include <QDBusConnection>
#include <QHash>
#include <QTemporaryDir>
#include <QDBusObjectPath>
#include <QObject>
#include <QProcess>
#include <QStringList>
#include <QTimer>
#include <QVariantList>
#include <QVariantMap>

#include "branding.hpp"

#include <functional>
#include <memory>

class Backend : public QObject {
    Q_OBJECT

    Q_PROPERTY(bool demo READ demo CONSTANT)
    Q_PROPERTY(QString displayName READ displayName CONSTANT)
    Q_PROPERTY(QString engineVersion READ engineVersion NOTIFY metaChanged)
    Q_PROPERTY(QString state READ state NOTIFY stateChanged)
    Q_PROPERTY(QString stateText READ stateText NOTIFY stateChanged)
    Q_PROPERTY(bool installed READ installed NOTIFY stateChanged)
    Q_PROPERTY(bool running READ running NOTIFY stateChanged)
    Q_PROPERTY(bool busy READ busy NOTIFY busyChanged)
    Q_PROPERTY(bool configAvailable READ configAvailable NOTIFY configChanged)
    Q_PROPERTY(bool helperAvailable READ helperAvailable NOTIFY metaChanged)
    Q_PROPERTY(bool systemDark READ systemDark NOTIFY metaChanged)
    Q_PROPERTY(bool dirty READ dirty NOTIFY dirtyChanged)
    Q_PROPERTY(bool conflict READ conflict NOTIFY conflictChanged)
    Q_PROPERTY(QVariantMap settings READ settings NOTIFY draftChanged)
    Q_PROPERTY(QVariantMap draft READ draft NOTIFY draftChanged)
    Q_PROPERTY(QStringList domains READ domains NOTIFY draftChanged)
    Q_PROPERTY(QStringList draftDomains READ draftDomains NOTIFY draftChanged)
    Q_PROPERTY(QStringList mssTargets READ mssTargets NOTIFY draftChanged)
    Q_PROPERTY(QStringList draftMssTargets READ draftMssTargets NOTIFY draftChanged)
    Q_PROPERTY(QString profilesText READ profilesText NOTIFY draftChanged)
    Q_PROPERTY(QString draftProfilesText READ draftProfilesText NOTIFY draftChanged)
    Q_PROPERTY(QVariantList profileList READ profileList NOTIFY profilesChanged)
    Q_PROPERTY(QString activeModes READ activeModes NOTIFY draftChanged)
    Q_PROPERTY(QString lastError READ lastError NOTIFY errorChanged)
    Q_PROPERTY(QString lastErrorHint READ lastErrorHint NOTIFY errorChanged)
    Q_PROPERTY(QVariantList diagnostics READ diagnostics NOTIFY diagnosticsChanged)
    Q_PROPERTY(QString diagnosticsRaw READ diagnosticsRaw NOTIFY diagnosticsChanged)
    Q_PROPERTY(QVariantList logs READ logs NOTIFY logsChanged)
    Q_PROPERTY(QString journalError READ journalError NOTIFY logsChanged)
    Q_PROPERTY(bool logPaused READ logPaused WRITE setLogPaused NOTIFY logsChanged)
    Q_PROPERTY(bool applyRunning READ applyRunning NOTIFY applyStateChanged)
    Q_PROPERTY(QString applyMessage READ applyMessage NOTIFY applyStateChanged)

public:
    explicit Backend(bool demo, QObject* parent = nullptr);
    ~Backend() override;

    bool demo() const { return m_demo; }
    QString displayName() const { return QString::fromUtf8(kDisplayName); }
    QString engineVersion() const { return m_engineVersion; }
    QString state() const { return m_state; }
    QString stateText() const;
    bool installed() const { return m_installed; }
    bool running() const { return m_state == "running"; }
    bool busy() const { return m_busy; }
    bool configAvailable() const { return m_configAvailable; }
    bool helperAvailable() const { return m_helperAvailable; }
    bool systemDark() const;
    bool dirty() const { return m_dirty; }
    bool conflict() const { return m_conflict; }
    QVariantMap settings() const { return m_settings; }
    QVariantMap draft() const { return m_draft; }
    QStringList domains() const { return m_domains; }
    QStringList draftDomains() const { return m_draftDomains; }
    QStringList mssTargets() const { return m_mssTargets; }
    QStringList draftMssTargets() const { return m_draftMssTargets; }
    QString profilesText() const { return m_profilesText; }
    QString draftProfilesText() const { return m_draftProfilesText; }
    QVariantList profileList() const { return m_profileList; }
    QString activeModes() const;
    QString lastError() const { return m_lastError; }
    QString lastErrorHint() const { return m_lastErrorHint; }
    QVariantList diagnostics() const { return m_diagnostics; }
    QString diagnosticsRaw() const { return m_diagnosticsRaw; }
    QVariantList logs() const { return m_logs; }
    QString journalError() const { return m_journalError; }
    bool logPaused() const { return m_logPaused; }
    bool applyRunning() const { return m_applyRunning; }
    QString applyMessage() const { return m_applyMessage; }

    Q_INVOKABLE void refreshService();
    Q_INVOKABLE void startService();
    Q_INVOKABLE void stopService();
    Q_INVOKABLE void restartService();
    Q_INVOKABLE void runDoctor();
    Q_INVOKABLE void refreshLogs();
    Q_INVOKABLE void setLogPaused(bool paused);
    Q_INVOKABLE void setSetting(const QString& key, const QVariant& value);
    Q_INVOKABLE void setDomains(const QStringList& domains);
    Q_INVOKABLE void setMssTargets(const QStringList& targets);
    Q_INVOKABLE void setProfilesText(const QString& text);
    Q_INVOKABLE QString profileTemplate(const QString& kind) const;
    Q_INVOKABLE QString profileTextAt(int index) const;
    Q_INVOKABLE void setProfileBlock(int index, const QString& text);
    Q_INVOKABLE void addProfile();
    Q_INVOKABLE void addProfileTemplate(const QString& kind);
    Q_INVOKABLE void removeProfile(int index);
    Q_INVOKABLE void duplicateProfile(int index);
    Q_INVOKABLE void refreshProfiles();
    Q_INVOKABLE QString profileValue(int index, const QString& key) const;
    Q_INVOKABLE void setProfileValue(int index, const QString& key, const QString& value);
    Q_INVOKABLE void addDomain(const QString& domain);
    Q_INVOKABLE void addMssTarget(const QString& target);
    Q_INVOKABLE void revertDraft();
    Q_INVOKABLE void reloadFromDisk();
    Q_INVOKABLE QString validateDraft();
    Q_INVOKABLE QString diffText();
    Q_INVOKABLE void applyDraft();
    Q_INVOKABLE void cancelApply();
    Q_INVOKABLE bool exportText(const QString& path, const QString& text);
    Q_INVOKABLE QString readTextFile(const QString& path);
    Q_INVOKABLE void simulateFailure();

signals:
    void stateChanged();
    void busyChanged();
    void configChanged();
    void draftChanged();
    void dirtyChanged();
    void conflictChanged();
    void errorChanged();
    void diagnosticsChanged();
    void logsChanged();
    void metaChanged();
    void applyStateChanged();
    void profilesChanged();

private slots:
    void onPropertiesChanged(const QString& iface, const QVariantMap& changed,
                             const QStringList& invalidated);

private:
    void loadDemo();
    void loadReal();
    void loadFiles();
    void setState(const QString& state);
    void setError(const QString& message, const QString& hint = {});
    void clearError();
    void setBusy(bool busy);
    void recomputeDirty();
    void rebuildProfileBlocks();
    static QVariantMap defaults();
    static bool validDomain(const QString& d);
    static bool validAddress(const QString& a);
    QString settingsToConfig(const QVariantMap& settings, const QString& domainsPath,
                             const QString& targetsPath) const;
    QString domainsToText(const QStringList& list) const;
    QString targetsToText(const QStringList& list) const;
    QString enginePath() const;
    QString helperPath() const;
    bool haveInstalledHelper() const;
    QString helperJson() const;
    void runProcessSync(const QString& program, const QStringList& args,
                        QString* out, QString* err, int timeoutMs) const;
    QVariantList parseDoctor(const QString& text) const;
    void readServiceState();
    void connectUnitSignals(const QString& path);
    void dbusCall(const QString& method, const QVariantList& args,
                  std::function<void(bool, const QString&)> done);
    QString fileHash(const QString& path) const;
    void rememberHashes();
    bool hashesChanged() const;

    bool m_demo = false;
    QString m_state = "unknown";
    bool m_installed = false;
    bool m_busy = false;
    bool m_configAvailable = false;
    bool m_helperAvailable = false;
    bool m_dirty = false;
    bool m_conflict = false;
    bool m_logPaused = false;
    bool m_applyRunning = false;
    QString m_applyMessage;
    QString m_engineVersion;
    QString m_lastError;
    QString m_lastErrorHint;
    QString m_diagnosticsRaw;
    QString m_journalError;
    QString m_unitPath;
    QVariantMap m_settings;
    QVariantMap m_draft;
    QStringList m_domains;
    QStringList m_draftDomains;
    QStringList m_mssTargets;
    QStringList m_draftMssTargets;
    QString m_profilesText;
    QString m_draftProfilesText;
    QString m_profilePreamble;
    QVariantList m_profileList;
    QVariantList m_diagnostics;
    QVariantList m_logs;
    QHash<QString, QString> m_hashes;
    QTimer m_refreshTimer;
    QTimer m_demoTimer;
    QProcess* m_doctorProcess = nullptr;
    QProcess* m_logProcess = nullptr;
    QProcess* m_applyProcess = nullptr;
    QString m_configPath;
    QString m_domainsPath;
    QString m_targetsPath;
    QString m_profilesPath;
    QString m_connectedPath;
    std::unique_ptr<QTemporaryDir> m_doctorTemp;
};
