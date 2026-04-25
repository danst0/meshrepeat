#pragma once
//
// WifiTcpBridge — BridgeBase-Subclass, die MeshCore-Pakete über eine
// WebSocket-Secure-Verbindung an den Bridge-Server (cassius) reicht und
// von dort empfangene Pakete ins lokale Mesh injiziert.
//
// Wire-Protokoll: siehe protocol/WIRE.md.
// Auth: Bearer-Token im hello-Frame, Server-Cert via ISRG Root X1 gepinnt.
// Storage: NVS-Namespace "mcbridge" (Preferences-Lib).
//
// State-Machine:
//   IDLE      — kein WiFi oder bridge.enable=0
//   CONNECT_W — WiFi.begin gestartet, warten auf STA-Connect
//   CONNECT_S — TLS+WS-Handshake läuft
//   HELLO     — hello gesendet, warten auf helloack
//   READY     — operativ; pkt-Frames hin und her, Heartbeat überwachen
//   BACKOFF   — Reconnect-Wartezeit
//
// Aufrufer (MyMesh) hängt uns wie die anderen BridgeBase-Subclasses ein:
//   - sendPacket(pkt) wird auf logTx/logRx aufgerufen (siehe MyMesh)
//   - loop() pollt den WebSocket
//   - onPacketReceived() queued ein vom Server eingegangenes Paket ins Mesh

#include <stdint.h>
#include <stddef.h>

#include "helpers/bridges/BridgeBase.h"
#include <WiFiClientSecure.h>
#include <ArduinoWebsockets.h>

namespace mcbridge {

// Persistente Konfiguration (NVS-Namespace "mcbridge").
struct BridgeConfig {
  bool     enabled        = false;
  char     host[64]       = {0};   // z.B. "meshcore.dumke.me"
  uint16_t port           = 443;
  char     path[64]       = "/api/v1/bridge";
  char     token[40]      = {0};   // 32 chars base32 + NUL + Reserve
  uint8_t  site_id[16]    = {0};   // 16 raw UUID-Bytes
  char     scope[40]      = "public";  // "public" oder "pool:<uuid>"
  char     wifi_ssid[33]  = {0};
  char     wifi_psk[64]   = {0};
};

class WifiTcpBridge : public BridgeBase {
public:
  WifiTcpBridge(NodePrefs* prefs, mesh::PacketManager* mgr, mesh::RTCClock* rtc);

  // AbstractBridge
  void begin() override;
  void end() override;
  void loop() override;
  void sendPacket(mesh::Packet* packet) override;
  void onPacketReceived(mesh::Packet* packet) override;

  // Config-API für CLI (siehe cli/BridgeCommands)
  bool loadConfig();
  bool saveConfig();
  BridgeConfig& config() { return _cfg; }

  // Status für `bridge status`-CLI
  enum State : uint8_t {
    IDLE = 0,
    CONNECT_W,
    CONNECT_S,
    HELLO,
    READY,
    BACKOFF,
  };
  State state() const { return _state; }
  uint32_t reconnectCount() const { return _reconnects; }
  const char* lastError() const { return _last_error; }

private:
  void enterState(State s);
  void scheduleReconnect();
  void onWsMessage(websockets::WebsocketsMessage msg);
  void onWsEvent(websockets::WebsocketsEvent event, String data);
  void sendHello();
  void sendHeartbeatAck(uint32_t seq);
  bool encodePktFrame(const mesh::Packet* pkt, uint8_t* out, size_t cap, size_t* out_len);
  bool decodeAndDispatch(const uint8_t* data, size_t len);

  BridgeConfig _cfg;
  State _state = IDLE;
  websockets::WebsocketsClient _ws;
  WiFiClientSecure _tls;            // wird vom WS-Client genutzt (siehe begin())
  uint32_t _next_attempt_ms = 0;
  uint32_t _backoff_ms = 1000;
  uint32_t _reconnects = 0;
  uint32_t _last_hback_ms = 0;
  uint32_t _hb_iv_ms = 15000;
  uint32_t _hb_timeout_ms = 45000;
  char _last_error[64] = {0};
};

}  // namespace mcbridge
