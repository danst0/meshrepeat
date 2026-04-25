#pragma once
//
// WifiTcpBridge — BridgeBase-Subclass, die MeshCore-Pakete über eine
// WebSocket-Secure-Verbindung an den Bridge-Server reicht und vom Server
// empfangene Pakete ins lokale Mesh injiziert.
//
// Wire-Protokoll: siehe protocol/WIRE.md.
// Auth: Bearer-Token im hello-Frame; Server-Cert via ISRG Root X1 gepinnt.
// Storage: NVS-Namespace "mcbridge" (Preferences-Lib).
// WebSocket-Stack: Links2004/arduinoWebSockets.
//

#include <stdint.h>
#include <stddef.h>

#include "helpers/bridges/BridgeBase.h"
#include <WebSocketsClient.h>

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
  uint8_t  wifi_mac[6]    = {0};  // alle 0 = default (factory MAC)
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

  // Status
  enum State : uint8_t {
    IDLE = 0,
    CONNECT_W,    // WiFi.begin gestartet
    CONNECTED,    // WS-Connect läuft / Frames-Phase
    BACKOFF,      // Reconnect-Wartezeit
  };
  State state() const { return _state; }
  uint32_t reconnectCount() const { return _reconnects; }
  const char* lastError() const { return _last_error; }
  static const char* stateName(State s);

  // Internal — called by the WebSocketsClient onEvent trampoline.
  void _dispatchWsEvent(uint8_t type, uint8_t* payload, size_t length);

private:
  void enterState(State s);
  void scheduleReconnect();
  void handleWsEvent(uint8_t type, uint8_t* payload, size_t length);
  void sendHello();
  void sendHeartbeatAck(uint32_t seq);
  bool encodePktFrame(const mesh::Packet* pkt, uint8_t* out, size_t cap, size_t* out_len);
  bool decodeAndDispatch(const uint8_t* data, size_t len);

  BridgeConfig _cfg;
  State _state = IDLE;
  WebSocketsClient _ws;
  uint32_t _next_attempt_ms = 0;
  uint32_t _backoff_ms = 1000;
  uint32_t _reconnects = 0;
  uint32_t _last_hback_ms = 0;
  uint32_t _hb_timeout_ms = 45000;
  bool _ws_connected = false;
  bool _hello_sent = false;
  char _last_error[64] = {0};
};

// Returns the most recently begun()'ed WifiTcpBridge instance, or nullptr.
WifiTcpBridge* getActive();

}  // namespace mcbridge
