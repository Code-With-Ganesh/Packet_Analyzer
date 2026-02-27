#include "types.h"
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cctype>

namespace DPI {

std::string FiveTuple::toString() const {
    std::ostringstream ss;
    
    // Format IP addresses
    auto formatIP = [](uint32_t ip) {
        std::ostringstream s;
        s << ((ip >> 0) & 0xFF) << "."
          << ((ip >> 8) & 0xFF) << "."
          << ((ip >> 16) & 0xFF) << "."
          << ((ip >> 24) & 0xFF);
        return s.str();
    };
    
    ss << formatIP(src_ip) << ":" << src_port
       << " -> "
       << formatIP(dst_ip) << ":" << dst_port
       << " (" << (protocol == 6 ? "TCP" : protocol == 17 ? "UDP" : "?") << ")";
    
    return ss.str();
}

std::string appTypeToString(AppType type) {
    switch (type) {
        case AppType::UNKNOWN:    return "Unknown";
        case AppType::HTTP:       return "HTTP";
        case AppType::HTTPS:      return "HTTPS";
        case AppType::DNS:        return "DNS";
        case AppType::TLS:        return "TLS";
        case AppType::QUIC:       return "QUIC";
        case AppType::GOOGLE:     return "Google";
        case AppType::FACEBOOK:   return "Facebook";
        case AppType::YOUTUBE:    return "YouTube";
        case AppType::TWITTER:    return "Twitter/X";
        case AppType::INSTAGRAM:  return "Instagram";
        case AppType::NETFLIX:    return "Netflix";
        case AppType::AMAZON:     return "Amazon";
        case AppType::MICROSOFT:  return "Microsoft";
        case AppType::APPLE:      return "Apple";
        case AppType::WHATSAPP:   return "WhatsApp";
        case AppType::TELEGRAM:   return "Telegram";
        case AppType::TIKTOK:     return "TikTok";
        case AppType::SPOTIFY:    return "Spotify";
        case AppType::ZOOM:       return "Zoom";
        case AppType::DISCORD:    return "Discord";
        case AppType::GITHUB:     return "GitHub";
        case AppType::CLOUDFLARE: return "Cloudflare";
        default:                  return "Unknown";
    }
}

// Map SNI/domain to application type
AppType sniToAppType(const std::string& sni) {
    if (sni.empty()) return AppType::UNKNOWN;
    
    // Convert to lowercase for matching
    std::string lower_sni = sni;
    std::transform(lower_sni.begin(), lower_sni.end(), lower_sni.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    
    // Check for known patterns
    // Google (including YouTube, which is owned by Google)
    if (lower_sni.find("google") != std::string::npos ||
        lower_sni.find("gstatic") != std::string::npos ||
        lower_sni.find("googleapis") != std::string::npos ||
        lower_sni.find("ggpht") != std::string::npos ||
        lower_sni.find("gvt1") != std::string::npos) {
        return AppType::GOOGLE;
    }
    
    // YouTube
    if (lower_sni.find("youtube") != std::string::npos ||
        lower_sni.find("ytimg") != std::string::npos ||
        lower_sni.find("youtu.be") != std::string::npos ||
        lower_sni.find("yt3.ggpht") != std::string::npos) {
        return AppType::YOUTUBE;
    }
    
    // Facebook/Meta
    if (lower_sni.find("facebook") != std::string::npos ||
        lower_sni.find("fbcdn") != std::string::npos ||
        lower_sni.find("fb.com") != std::string::npos ||
        lower_sni.find("fbsbx") != std::string::npos ||
        lower_sni.find("meta.com") != std::string::npos) {
        return AppType::FACEBOOK;
    }
    
    // Instagram (owned by Meta)
    if (lower_sni.find("instagram") != std::string::npos ||
        lower_sni.find("cdninstagram") != std::string::npos) {
        return AppType::INSTAGRAM;
    }
    
    // WhatsApp (owned by Meta)
    if (lower_sni.find("whatsapp") != std::string::npos ||
        lower_sni.find("wa.me") != std::string::npos) {
        return AppType::WHATSAPP;
    }
    
    // Twitter/X
    if (lower_sni.find("twitter") != std::string::npos ||
        lower_sni.find("twimg") != std::string::npos ||
        lower_sni.find("x.com") != std::string::npos ||
        lower_sni.find("t.co") != std::string::npos) {
        return AppType::TWITTER;
    }
    
    // Netflix
    if (lower_sni.find("netflix") != std::string::npos ||
        lower_sni.find("nflxvideo") != std::string::npos ||
        lower_sni.find("nflximg") != std::string::npos) {
        return AppType::NETFLIX;
    }
    
    // Amazon
    if (lower_sni.find("amazon") != std::string::npos ||
        lower_sni.find("amazonaws") != std::string::npos ||
        lower_sni.find("cloudfront") != std::string::npos ||
        lower_sni.find("aws") != std::string::npos) {
        return AppType::AMAZON;
    }
    
    // Microsoft
    if (lower_sni.find("microsoft") != std::string::npos ||
        lower_sni.find("msn.com") != std::string::npos ||
        lower_sni.find("office") != std::string::npos ||
        lower_sni.find("azure") != std::string::npos ||
        lower_sni.find("live.com") != std::string::npos ||
        lower_sni.find("outlook") != std::string::npos ||
        lower_sni.find("bing") != std::string::npos) {
        return AppType::MICROSOFT;
    }
    
    // Apple
    if (lower_sni.find("apple") != std::string::npos ||
        lower_sni.find("icloud") != std::string::npos ||
        lower_sni.find("mzstatic") != std::string::npos ||
        lower_sni.find("itunes") != std::string::npos) {
        return AppType::APPLE;
    }
    
    // Telegram
    if (lower_sni.find("telegram") != std::string::npos ||
        lower_sni.find("t.me") != std::string::npos) {
        return AppType::TELEGRAM;
    }
    
    // TikTok
    if (lower_sni.find("tiktok") != std::string::npos ||
        lower_sni.find("tiktokcdn") != std::string::npos ||
        lower_sni.find("musical.ly") != std::string::npos ||
        lower_sni.find("bytedance") != std::string::npos) {
        return AppType::TIKTOK;
    }
    
    // Spotify
    if (lower_sni.find("spotify") != std::string::npos ||
        lower_sni.find("scdn.co") != std::string::npos) {
        return AppType::SPOTIFY;
    }
    
    // Zoom
    if (lower_sni.find("zoom") != std::string::npos) {
        return AppType::ZOOM;
    }
    
    // Discord
    if (lower_sni.find("discord") != std::string::npos ||
        lower_sni.find("discordapp") != std::string::npos) {
        return AppType::DISCORD;
    }
    
    // GitHub
    if (lower_sni.find("github") != std::string::npos ||
        lower_sni.find("githubusercontent") != std::string::npos) {
        return AppType::GITHUB;
    }
    
    // Cloudflare
    if (lower_sni.find("cloudflare") != std::string::npos ||
        lower_sni.find("cf-") != std::string::npos) {
        return AppType::CLOUDFLARE;
    }
    
    // If SNI is present but not recognized, still mark as TLS/HTTPS
    return AppType::HTTPS;
}

// ============================================================================
// IP Address based App Detection (QUIC ke liye — SNI encrypted hoti hai)
// Known IP ranges se app identify karte hain
// ============================================================================
AppType ipToAppType(uint32_t ip) {
    // IP bytes (little-endian storage mein)
    uint8_t o1 = (ip)       & 0xFF;  // First octet
    uint8_t o2 = (ip >> 8)  & 0xFF;  // Second octet
    uint8_t o3 = (ip >> 16) & 0xFF;  // Third octet

    // -----------------------------------------------------------------------
    // YouTube / Google IP ranges
    // YouTube videos: 142.250.x.x, 172.217.x.x, 216.58.x.x, 74.125.x.x
    // Google APIs:    142.250.x.x, 173.194.x.x
    // -----------------------------------------------------------------------
    if (o1 == 142 && o2 == 250)  return AppType::YOUTUBE;   // YouTube CDN
    if (o1 == 172 && o2 == 217)  return AppType::GOOGLE;
    if (o1 == 216 && o2 == 58)   return AppType::GOOGLE;
    if (o1 == 74  && o2 == 125)  return AppType::YOUTUBE;   // YouTube streams
    if (o1 == 173 && o2 == 194)  return AppType::GOOGLE;
    if (o1 == 34  && o2 == 64)   return AppType::GOOGLE;    // Google Cloud
    if (o1 == 34  && o2 == 65)   return AppType::GOOGLE;
    if (o1 == 34  && o2 == 66)   return AppType::GOOGLE;
    if (o1 == 34  && o2 == 67)   return AppType::YOUTUBE;

    // -----------------------------------------------------------------------
    // Facebook / Instagram / WhatsApp
    // Meta IP range: 157.240.x.x, 31.13.x.x, 179.60.x.x, 66.220.x.x
    // -----------------------------------------------------------------------
    if (o1 == 157 && o2 == 240)  return AppType::FACEBOOK;
    if (o1 == 31  && o2 == 13)   return AppType::FACEBOOK;
    if (o1 == 179 && o2 == 60)   return AppType::WHATSAPP;
    if (o1 == 66  && o2 == 220)  return AppType::FACEBOOK;
    if (o1 == 69  && o2 == 171)  return AppType::INSTAGRAM;
    if (o1 == 185 && o2 == 60)   return AppType::WHATSAPP;

    // -----------------------------------------------------------------------
    // Netflix
    // Netflix CDN: 198.38.x.x, 198.45.x.x, 23.246.x.x, 37.77.x.x
    // -----------------------------------------------------------------------
    if (o1 == 198 && o2 == 38)   return AppType::NETFLIX;
    if (o1 == 198 && o2 == 45)   return AppType::NETFLIX;
    if (o1 == 23  && o2 == 246)  return AppType::NETFLIX;
    if (o1 == 37  && o2 == 77)   return AppType::NETFLIX;

    // -----------------------------------------------------------------------
    // Microsoft / Office 365
    // Azure: 13.64-107.x, 20.x.x.x, 40.x.x.x, 52.x.x.x
    // -----------------------------------------------------------------------
    if (o1 == 20)                return AppType::MICROSOFT;
    if (o1 == 40  && o2 <= 127)  return AppType::MICROSOFT;
    if (o1 == 13  && o2 == 107)  return AppType::MICROSOFT;
    if (o1 == 52  && o2 >= 96)   return AppType::MICROSOFT;

    // -----------------------------------------------------------------------
    // Apple / iCloud
    // Apple: 17.x.x.x (entire /8 block Apple ka hai!)
    // -----------------------------------------------------------------------
    if (o1 == 17)                return AppType::APPLE;

    // -----------------------------------------------------------------------
    // Amazon / AWS / Prime Video
    // AWS: 52.0-95.x, 54.x.x.x, 3.x.x.x
    // -----------------------------------------------------------------------
    if (o1 == 54)                return AppType::AMAZON;
    if (o1 == 3   && o2 <= 128)  return AppType::AMAZON;

    // -----------------------------------------------------------------------
    // Cloudflare (1.1.1.1, 1.0.0.1, 104.16-31.x.x)
    // -----------------------------------------------------------------------
    if (o1 == 1   && (o2 == 1 || o2 == 0))   return AppType::CLOUDFLARE;
    if (o1 == 104 && o2 >= 16 && o2 <= 31)   return AppType::CLOUDFLARE;
    if (o1 == 104 && o2 >= 200 && o2 <= 255) return AppType::CLOUDFLARE;

    // -----------------------------------------------------------------------
    // Discord: 66.22.x.x, 162.159.x.x (Cloudflare-hosted)
    // -----------------------------------------------------------------------
    if (o1 == 66  && o2 == 22)   return AppType::DISCORD;

    // -----------------------------------------------------------------------
    // Telegram: 91.108.x.x, 149.154.x.x, 185.76.151.x
    // -----------------------------------------------------------------------
    if (o1 == 91  && o2 == 108)  return AppType::TELEGRAM;
    if (o1 == 149 && o2 == 154)  return AppType::TELEGRAM;

    // -----------------------------------------------------------------------
    // TikTok / ByteDance: 184.84.x.x, 23.57.x.x
    // -----------------------------------------------------------------------
    if (o1 == 184 && o2 == 84)   return AppType::TIKTOK;

    // -----------------------------------------------------------------------
    // Spotify: 35.186.x.x, 35.188.x.x (Google Cloud pe hosted)
    // -----------------------------------------------------------------------
    if (o1 == 35  && (o2 == 186 || o2 == 188)) return AppType::SPOTIFY;

    return AppType::UNKNOWN;
}

} // namespace DPI
