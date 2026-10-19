// Small unit tests for the TLS parser and the strategy decision.
#include "config.hpp"
#include "profiles.hpp"
#include "strategy.hpp"
#include "tls_clienthello.hpp"
#include "tls_probe.hpp"

#include <cstdint>
#include <cstdio>
#include <fstream>
#include <string>
#include <vector>

#include <unistd.h>

namespace {

int g_fail = 0;

void check(bool cond, const char* what)
{
    if (!cond) { ++g_fail; std::printf("FAIL: %s\n", what); }
    else std::printf("ok: %s\n", what);
}

std::vector<std::uint8_t> make_client_hello(const std::string& host,
                                            bool truncate_before_name = false,
                                            bool bad_record_type = false)
{
    std::vector<std::uint8_t> body;
    auto u8 = [&](std::uint8_t v) { body.push_back(v); };
    auto u16 = [&](std::uint16_t v) { body.push_back(v >> 8); body.push_back(v & 0xff); };
    auto u24 = [&](std::uint32_t v) {
        body.push_back((v >> 16) & 0xff); body.push_back((v >> 8) & 0xff); body.push_back(v & 0xff);
    };

    u16(0x0303);            // legacy_version
    for (int i = 0; i < 32; ++i) u8(static_cast<std::uint8_t>(i));
    u8(0);                  // session id
    u16(2); u16(0x1301);    // cipher suites
    u8(1); u8(0);           // compression

    // extensions
    std::vector<std::uint8_t> sni;
    sni.push_back(static_cast<std::uint8_t>((host.size() + 3) >> 8));
    sni.push_back(static_cast<std::uint8_t>((host.size() + 3) & 0xff));
    sni.push_back(0); // host_name
    sni.push_back(static_cast<std::uint8_t>(host.size() >> 8));
    sni.push_back(static_cast<std::uint8_t>(host.size() & 0xff));
    sni.insert(sni.end(), host.begin(), host.end());

    std::vector<std::uint8_t> exts;
    exts.push_back(0x00); exts.push_back(0x00); // server_name
    exts.push_back(static_cast<std::uint8_t>(sni.size() >> 8));
    exts.push_back(static_cast<std::uint8_t>(sni.size() & 0xff));
    exts.insert(exts.end(), sni.begin(), sni.end());

    u16(static_cast<std::uint16_t>(exts.size()));
    body.insert(body.end(), exts.begin(), exts.end());

    std::vector<std::uint8_t> hs;
    hs.push_back(0x01); // client_hello
    hs.push_back(static_cast<std::uint8_t>((body.size() >> 16) & 0xff));
    hs.push_back(static_cast<std::uint8_t>((body.size() >> 8) & 0xff));
    hs.push_back(static_cast<std::uint8_t>(body.size() & 0xff));
    hs.insert(hs.end(), body.begin(), body.end());

    std::vector<std::uint8_t> rec;
    rec.push_back(bad_record_type ? 0x17 : 0x16);
    rec.push_back(0x03); rec.push_back(0x01);
    rec.push_back(static_cast<std::uint8_t>(hs.size() >> 8));
    rec.push_back(static_cast<std::uint8_t>(hs.size() & 0xff));
    rec.insert(rec.end(), hs.begin(), hs.end());

    if (truncate_before_name) {
        // Keep the record header and handshake header, but cut inside the SNI name.
        rec.resize(rec.size() - host.size() + 2);
    }
    return rec;
}

} // namespace

int main()
{
    {
        const std::string path = "/tmp/mutekizu-unit-profiles-" + std::to_string(::getpid());
        {
            std::ofstream f(path);
            f << "[discord]\n"
                 "domains = discord.com, gateway.discord.gg\n"
                 "split_delta = 6\n"
                 "split_disorder = true\n"
                 "fake_enabled = true\n"
                 "fake_sni = www.microsoft.com\n"
                 "seqovl_enabled = true\n"
                 "seqovl_bytes = 646\n"
                 "[youtube]\n"
                 "domains = youtube.com, googlevideo.com\n"
                 "split_stride = 0\n";
        }
        std::vector<dpi::Profile> profiles;
        std::string perr;
        const bool loaded = dpi::load_profiles(path, profiles, perr);
        check(loaded && profiles.size() == 2 && profiles[0].name == "discord" &&
              profiles[0].domains.size() == 2 && profiles[0].split_delta == 6 &&
              profiles[0].fake_enabled == true && profiles[0].seqovl_bytes == 646 &&
              profiles[1].split_stride == 0,
              "domain profiles parse");
        std::remove(path.c_str());
    }
    {
        const std::string path = "/tmp/mutekizu-unit-config-" + std::to_string(::getpid());
        {
            std::ofstream f(path);
            f << "split_enabled=true\n"
                 "domains_file=/tmp/domains\n"
                 "mss_targets_file=/tmp/targets\n"
                 "split_disorder=true\n"
                 "split_multidisorder=true\n"
                 "split_jitter_ms=5\n"
                 "fake_enabled=true\n"
                 "fake_ttl=7\n"
                 "fake_repeats=4\n"
                 "fake_sni=probe.example\n"
                 "seqovl_enabled=true\n"
                 "seqovl_bytes=700\n"
                 "seqovl_repeats=2\n"
                 "udp_fake_enabled=true\n"
                 "udp_fake_ttl=4\n"
                 "udp_fake_repeats=5\n"
                 "auto_profile=true\n"
                 "auto_retry_window_s=12\n";
        }
        dpi::Config c;
        std::string err;
        const bool loaded = dpi::load_config(path, c, err);
        check(loaded && c.split_disorder && c.split_multidisorder &&
              c.split_jitter_ms == 5 && c.fake_enabled && c.fake_ttl == 7 &&
              c.fake_repeats == 4 && c.fake_sni == "probe.example" &&
              c.seqovl_enabled && c.seqovl_bytes == 700 && c.seqovl_repeats == 2 &&
              c.udp_fake_enabled && c.udp_fake_ttl == 4 && c.udp_fake_repeats == 5 &&
              c.auto_profile && c.auto_retry_window_s == 12,
              "advanced desync config keys parse");
        std::remove(path.c_str());
    }
    using namespace dpi;
    {
        auto data = make_client_hello("test.example");
        ClientHelloInfo info;
        const auto rc = parse_client_hello(data.data(), data.size(), info, 8192);
        check(rc == ParseResult::Ok, "full ClientHello parses");
        check(info.sni == "test.example", "SNI extracted");
        check(info.sni_offset > 0 && info.sni_offset + info.sni_length <= data.size(),
              "SNI offset in bounds");
    }
    {
        auto data = make_client_hello("test.example", true);
        ClientHelloInfo info;
        const auto rc = parse_client_hello(data.data(), data.size(), info, 8192);
        check(rc == ParseResult::NeedMore, "incomplete SNI returns NeedMore");
    }
    {
        auto data = make_client_hello("test.example");
        ClientHelloInfo info;
        const auto rc = parse_client_hello(data.data(), 3, info, 8192);
        check(rc == ParseResult::NeedMore, "short buffer returns NeedMore");
    }
    {
        auto data = make_client_hello("test.example", false, true);
        ClientHelloInfo info;
        const auto rc = parse_client_hello(data.data(), data.size(), info, 8192);
        check(rc == ParseResult::NotTls, "non-handshake record returns NotTls");
    }
    {
        auto data = make_client_hello("test.example");
        data[3] = 0xff; data[4] = 0xff; // record length beyond supplied buffer
        ClientHelloInfo info;
        const auto rc = parse_client_hello(data.data(), data.size(), info, 1024);
        check(rc == ParseResult::TooLarge || rc == ParseResult::NeedMore,
              "oversized record is rejected or needs more");
    }
    {
        const auto probe = build_probe_client_hello("probe.example");
        ClientHelloInfo pi;
        const auto rc = parse_client_hello(probe.data(), probe.size(), pi, 4096);
        check(rc == ParseResult::Ok && pi.sni == "probe.example",
              "probe ClientHello parses with its SNI");
    }
    {
        DomainSet set;
        set.domains = {"example.com", "test.example"};
        set.normalize();
        check(set.matches("test.example"), "exact domain matches");
        check(set.matches("a.test.example"), "subdomain matches");
        check(!set.matches("badexample.com"), "suffix boundary respected");

        auto data = make_client_hello("test.example");
        ClientHelloInfo info;
        parse_client_hello(data.data(), data.size(), info, 8192);
        const auto d = decide(info, set, StrategyConfig{4, 0, 64});
        check(d.action == Decision::Action::Split, "target SNI split decision");
        check(!d.boundaries.empty(), "at least one split boundary");
        bool inside = true;
        for (std::size_t b : d.boundaries)
            inside = inside && b > info.sni_offset && b < info.sni_offset + info.sni_length;
        check(inside, "all split boundaries lie strictly inside the hostname");

        const auto d2 = decide(info, DomainSet{{"other.example"}}, StrategyConfig{4});
        check(d2.action == Decision::Action::Accept, "non-target is not split");
    }

    std::printf("%s (%d failure(s))\n", g_fail == 0 ? "ALL OK" : "FAILED", g_fail);
    return g_fail == 0 ? 0 : 1;
}
