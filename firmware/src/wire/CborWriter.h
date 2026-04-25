#pragma once
//
// Schlanker CBOR-Writer für unsere wenigen Wire-Frames (siehe protocol/WIRE.md).
// Wir benötigen nur einen Subset von RFC 8949: Maps mit Text-Keys, Text/Bytes,
// kleine Unsigned/Signed-Integer, kleine Arrays. Kein Major-Type 6 (Tags),
// keine Floats, keine Indefinite-Length-Items.
//
// Kanonisches CBOR (Deterministic Encoding nach RFC 8949 §4.2.1): kürzeste
// Integer-Codierung, Map-Keys nach Length+lex sortiert. Wir vereinfachen:
// die Aufrufer übergeben Keys in der gewünschten on-wire-Reihenfolge.
// Da unsere Map-Keys alle kurz und kollisionsfrei sind, reicht das.
//

#include <stdint.h>
#include <string.h>
#include <stddef.h>

namespace mcbridge {

class CborWriter {
public:
  CborWriter(uint8_t* buffer, size_t capacity)
      : _buf(buffer), _cap(capacity), _len(0), _err(false) {}

  size_t length() const { return _len; }
  bool error() const { return _err; }
  const uint8_t* data() const { return _buf; }

  void writeMap(uint8_t pairs) {
    writeTypeAndLength(0xA0, pairs);  // Major 5, indefinite if pairs >= 24 → tail
  }
  void writeArray(uint8_t items) { writeTypeAndLength(0x80, items); }

  void writeTextKey(const char* key) {
    size_t l = strlen(key);
    writeTypeAndLength(0x60, (uint32_t)l);  // Major 3
    appendBytes((const uint8_t*)key, l);
  }

  void writeText(const char* s) {
    size_t l = strlen(s);
    writeTypeAndLength(0x60, (uint32_t)l);
    appendBytes((const uint8_t*)s, l);
  }

  void writeBytes(const uint8_t* p, size_t n) {
    writeTypeAndLength(0x40, (uint32_t)n);  // Major 2
    appendBytes(p, n);
  }

  void writeUInt(uint32_t v) { writeTypeAndLength(0x00, v); }

  void writeInt(int32_t v) {
    if (v >= 0) {
      writeTypeAndLength(0x00, (uint32_t)v);
    } else {
      writeTypeAndLength(0x20, (uint32_t)(-(v + 1)));
    }
  }

  // Convenience: write a pair (key + uint).
  void kvUInt(const char* key, uint32_t v) {
    writeTextKey(key);
    writeUInt(v);
  }
  void kvInt(const char* key, int32_t v) {
    writeTextKey(key);
    writeInt(v);
  }
  void kvText(const char* key, const char* s) {
    writeTextKey(key);
    writeText(s);
  }
  void kvBytes(const char* key, const uint8_t* p, size_t n) {
    writeTextKey(key);
    writeBytes(p, n);
  }

private:
  uint8_t* _buf;
  size_t _cap;
  size_t _len;
  bool _err;

  void writeTypeAndLength(uint8_t major, uint32_t length) {
    if (length < 24) {
      put1((uint8_t)(major | length));
    } else if (length <= 0xFF) {
      put1((uint8_t)(major | 24));
      put1((uint8_t)length);
    } else if (length <= 0xFFFF) {
      put1((uint8_t)(major | 25));
      put1((uint8_t)(length >> 8));
      put1((uint8_t)length);
    } else {
      put1((uint8_t)(major | 26));
      put1((uint8_t)(length >> 24));
      put1((uint8_t)(length >> 16));
      put1((uint8_t)(length >> 8));
      put1((uint8_t)length);
    }
  }

  void put1(uint8_t b) {
    if (_len < _cap) {
      _buf[_len++] = b;
    } else {
      _err = true;
    }
  }

  void appendBytes(const uint8_t* p, size_t n) {
    if (_len + n > _cap) {
      _err = true;
      return;
    }
    memcpy(_buf + _len, p, n);
    _len += n;
  }
};

}  // namespace mcbridge
