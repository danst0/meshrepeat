#include "WifiTcpBridge.h"

#include "wire/CborWriter.h"
#include "wire/CborReader.h"
#include "certs/isrg_root_x1.h"

#include <Preferences.h>
#include <WiFi.h>
#include <esp_log.h>

// Wir leihen uns das MeshCore-Logging-Macro, damit wir denselben Stil haben
// wie der Rest des Repeaters.
#ifndef MESH_DEBUG_PRINTLN
  #define MESH_DEBUG_PRINTLN(...) do { Serial.printf(__VA_ARGS__); Serial.println(); } while (0)
#endif

namespace mcbridge {

namespace {
constexpr const char* NVS_NAMESPACE = "mcbridge";
constexpr uint8_t  PROTO_VERSION    = 1;
constexpr uint16_t MAX_FRAME_BYTES  = 8192;
constexpr uint32_t BACKOFF_INITIAL_MS = 1000;
constexpr uint32_t BACKOFF_MAX_MS     = 60000;

bool isDefaultPassword(const char* p) {
  return strcmp(p, "password") == 0;
}
}  // namespace

WifiTcpBridge::WifiTcpBridge(NodePrefs* prefs, mesh::PacketManager* mgr, mesh::RTCClock* rtc)
    : BridgeBase(prefs, mgr, rtc) {}

bool WifiTcpBridge::loadConfig() {
  Preferences p;
  if (!p.begin(NVS_NAMESPACE, true)) return false;
  _cfg.enabled = p.getBool("en", false);
  p.getString("host", _cfg.host, sizeof(_cfg.host));
  _cfg.port = p.getUShort("port", 443);
  p.getString("path", _cfg.path, sizeof(_cfg.path));
  p.getString("tok", _cfg.token, sizeof(_cfg.token));
  size_t got = p.getBytes("site", _cfg.site_id, sizeof(_cfg.site_id));
  if (got != sizeof(_cfg.site_id)) memset(_cfg.site_id, 0, sizeof(_cfg.site_id));
  p.getString("scope", _cfg.scope, sizeof(_cfg.scope));
  p.getString("ssid", _cfg.wifi_ssid, sizeof(_cfg.wifi_ssid));
  p.getString("psk",  _cfg.wifi_psk,  sizeof(_cfg.wifi_psk));
  p.end();
  return true;
}

bool WifiTcpBridge::saveConfig() {
  Preferences p;
  if (!p.begin(NVS_NAMESPACE, false)) return false;
  p.putBool("en", _cfg.enabled);
  p.putString("host", _cfg.host);
  p.putUShort("port", _cfg.port);
  p.putString("path", _cfg.path);
  p.putString("tok", _cfg.token);
  p.putBytes("site", _cfg.site_id, sizeof(_cfg.site_id));
  p.putString("scope", _cfg.scope);
  p.putString("ssid", _cfg.wifi_ssid);
  p.putString("psk",  _cfg.wifi_psk);
  p.end();
  return true;
}

void WifiTcpBridge::begin() {
  loadConfig();
  _initialized = true;
  if (!_cfg.enabled) {
    enterState(IDLE);
    return;
  }
  _tls.setCACert(ISRG_ROOT_X1_PEM);
  _ws.setCACert(ISRG_ROOT_X1_PEM);
  _ws.onMessage([this](websockets::WebsocketsMessage m) { onWsMessage(m); });
  _ws.onEvent([this](websockets::WebsocketsEvent e, String d) { onWsEvent(e, d); });

  if (_cfg.wifi_ssid[0] != 0) {
    WiFi.mode(WIFI_STA);
    WiFi.begin(_cfg.wifi_ssid, _cfg.wifi_psk);
    enterState(CONNECT_W);
  } else {
    snprintf(_last_error, sizeof(_last_error), "no wifi.ssid configured");
    enterState(BACKOFF);
  }
}

void WifiTcpBridge::end() {
  _ws.close();
  WiFi.disconnect(true, false);
  enterState(IDLE);
  _initialized = false;
}

void WifiTcpBridge::loop() {
  if (!_initialized) return;
  uint32_t now = millis();

  switch (_state) {
    case IDLE:
      return;

    case CONNECT_W:
      if (WiFi.status() == WL_CONNECTED) {
        // URL bauen: wss://host:port/path
        String url = String("wss://") + _cfg.host + ":" + String(_cfg.port) + _cfg.path;
        if (_ws.connect(url)) {
          enterState(HELLO);
          sendHello();
        } else {
          snprintf(_last_error, sizeof(_last_error), "ws connect failed");
          scheduleReconnect();
        }
      } else if ((int32_t)(now - _next_attempt_ms) > 30000) {
        snprintf(_last_error, sizeof(_last_error), "wifi timeout");
        scheduleReconnect();
      }
      return;

    case CONNECT_S:
    case HELLO:
    case READY:
      _ws.poll();
      if (_state == READY && _hb_timeout_ms > 0
          && (int32_t)(now - _last_hback_ms) > (int32_t)_hb_timeout_ms) {
        snprintf(_last_error, sizeof(_last_error), "heartbeat timeout");
        _ws.close();
        scheduleReconnect();
      }
      return;

    case BACKOFF:
      if ((int32_t)(now - _next_attempt_ms) >= 0) {
        // Versuch: erst WiFi-Reconnect, dann WS.
        WiFi.reconnect();
        enterState(CONNECT_W);
        _next_attempt_ms = now;
      }
      return;
  }
}

void WifiTcpBridge::enterState(State s) {
  _state = s;
  if (s == READY) {
    _backoff_ms = BACKOFF_INITIAL_MS;
    _last_hback_ms = millis();
  }
}

void WifiTcpBridge::scheduleReconnect() {
  _reconnects++;
  uint32_t jitter = (uint32_t)random(0, _backoff_ms / 5 + 1);
  _next_attempt_ms = millis() + _backoff_ms + jitter;
  _backoff_ms = min(_backoff_ms * 2, BACKOFF_MAX_MS);
  enterState(BACKOFF);
}

void WifiTcpBridge::sendHello() {
  uint8_t buf[256];
  CborWriter w(buf, sizeof(buf));
  w.writeMap(7);  // t, site, tok, fw, proto, scope, caps
  w.kvText("t", "hello");
  w.kvBytes("site", _cfg.site_id, sizeof(_cfg.site_id));
  w.kvText("tok", _cfg.token);
  w.kvText("fw", FIRMWARE_VERSION);
  w.kvUInt("proto", PROTO_VERSION);
  w.kvText("scope", _cfg.scope);
  w.writeTextKey("caps");
  w.writeArray(2);
  w.writeText("rssi");
  w.writeText("snr");
  if (w.error()) {
    snprintf(_last_error, sizeof(_last_error), "hello encode overflow");
    _ws.close();
    scheduleReconnect();
    return;
  }
  _ws.sendBinary((const char*)w.data(), w.length());
  _last_hback_ms = millis();
}

void WifiTcpBridge::sendHeartbeatAck(uint32_t seq) {
  uint8_t buf[32];
  CborWriter w(buf, sizeof(buf));
  w.writeMap(2);
  w.kvText("t", "hback");
  w.kvUInt("seq", seq);
  if (w.error()) return;
  _ws.sendBinary((const char*)w.data(), w.length());
}

bool WifiTcpBridge::encodePktFrame(const mesh::Packet* pkt, uint8_t* out, size_t cap, size_t* out_len) {
  // Wir serialisieren das komplette on-air-Paket (Header + Path + Payload)
  // ins "raw"-Feld. Der Server tagged es mit unserer site_id und routet.
  uint8_t raw[256];
  uint8_t raw_len = pkt->writeTo(raw);  // MeshCore Packet::writeTo gibt Länge zurück
  CborWriter w(out, cap);
  w.writeMap(2);
  w.kvText("t", "pkt");
  w.kvBytes("raw", raw, raw_len);
  if (w.error()) return false;
  *out_len = w.length();
  return true;
}

void WifiTcpBridge::sendPacket(mesh::Packet* packet) {
  if (_state != READY) return;  // verloren — Mesh läuft trotzdem lokal weiter
  uint8_t buf[300];
  size_t n;
  if (!encodePktFrame(packet, buf, sizeof(buf), &n)) {
    snprintf(_last_error, sizeof(_last_error), "pkt encode overflow");
    return;
  }
  _ws.sendBinary((const char*)buf, n);
}

void WifiTcpBridge::onPacketReceived(mesh::Packet* packet) {
  // BridgeBase-Standard: hasSeen + queue
  handleReceivedPacket(packet);
}

bool WifiTcpBridge::decodeAndDispatch(const uint8_t* data, size_t len) {
  if (len > MAX_FRAME_BYTES) return false;
  CborReader r(data, len);
  uint32_t pairs;
  if (!r.readMapHeader(&pairs)) return false;

  // Ersten Pass: Frame-Typ rausholen. Wir scannen die Map; Server schickt
  // uns immer "t" zuerst (kanonisch), aber wir suchen explizit.
  // Pragmatisch: erstes Pair muss "t":<text> sein.
  const char* k; size_t kl;
  if (!r.readText(&k, &kl) || kl != 1 || k[0] != 't') return false;
  const char* v; size_t vl;
  if (!r.readText(&v, &vl)) return false;

  if (vl == 8 && memcmp(v, "helloack", 8) == 0) {
    // Restliche Felder skippen, in READY wechseln.
    for (uint32_t i = 1; i < pairs; ++i) {
      if (!r.skipItem() || !r.skipItem()) return false;
    }
    enterState(READY);
    return true;
  }
  if (vl == 2 && memcmp(v, "hb", 2) == 0) {
    // hb {seq, ts} — wir extrahieren seq und antworten mit hback.
    uint32_t seq = 0;
    for (uint32_t i = 1; i < pairs; ++i) {
      const char* fk; size_t fkl;
      if (!r.readText(&fk, &fkl)) return false;
      if (fkl == 3 && memcmp(fk, "seq", 3) == 0) {
        if (!r.readUInt(&seq)) return false;
      } else {
        if (!r.skipItem()) return false;
      }
    }
    sendHeartbeatAck(seq);
    _last_hback_ms = millis();
    return true;
  }
  if (vl == 3 && memcmp(v, "pkt", 3) == 0) {
    const uint8_t* raw = nullptr; size_t rawl = 0;
    for (uint32_t i = 1; i < pairs; ++i) {
      const char* fk; size_t fkl;
      if (!r.readText(&fk, &fkl)) return false;
      if (fkl == 3 && memcmp(fk, "raw", 3) == 0) {
        if (!r.readBytes(&raw, &rawl)) return false;
      } else {
        if (!r.skipItem()) return false;
      }
    }
    if (raw == nullptr || rawl == 0) return false;
    mesh::Packet* p = _mgr->allocNew();
    if (p == nullptr) return false;
    if (!p->readFrom(raw, (uint8_t)rawl)) {
      _mgr->free(p);
      return false;
    }
    onPacketReceived(p);
    return true;
  }
  if (vl == 4 && memcmp(v, "flow", 4) == 0) {
    // Backpressure-Hinweis — wir loggen, ignorieren aber sonst (ohne Queue).
    return true;
  }
  if (vl == 3 && memcmp(v, "bye", 3) == 0) {
    _ws.close();
    scheduleReconnect();
    return true;
  }
  // Unbekannter Frame-Typ — silent ignore.
  return true;
}

void WifiTcpBridge::onWsMessage(websockets::WebsocketsMessage msg) {
  if (!msg.isBinary()) return;
  const auto& payload = msg.data();
  decodeAndDispatch((const uint8_t*)payload.c_str(), payload.length());
}

void WifiTcpBridge::onWsEvent(websockets::WebsocketsEvent event, String data) {
  switch (event) {
    case websockets::WebsocketsEvent::ConnectionClosed:
      snprintf(_last_error, sizeof(_last_error), "ws closed");
      scheduleReconnect();
      break;
    case websockets::WebsocketsEvent::ConnectionOpened:
      // helloack-Wartephase, _state ist HELLO
      break;
    default:
      break;
  }
}

}  // namespace mcbridge
