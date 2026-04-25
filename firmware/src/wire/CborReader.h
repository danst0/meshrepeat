#pragma once
//
// Minimaler CBOR-Reader. Wir parsen die Frames vom Server: helloack, hb,
// flow, bye, pkt. Alle haben einfache Map-Strukturen ohne Tags/Floats.
// Der Reader bietet Skip- und Field-Lookup-Helfer auf Map-Ebene.
//

#include <stdint.h>
#include <string.h>
#include <stddef.h>

namespace mcbridge {

class CborReader {
public:
  CborReader(const uint8_t* data, size_t length)
      : _data(data), _end(data + length), _err(false) {}

  bool error() const { return _err; }

  // Read map header. Returns number of pairs, or sets error.
  bool readMapHeader(uint32_t* pairs_out) {
    if (atEnd()) { _err = true; return false; }
    uint8_t b = peek();
    if ((b & 0xE0) != 0xA0) { _err = true; return false; }
    uint32_t v;
    if (!readTypeAndLength(0xA0, &v)) return false;
    *pairs_out = v;
    return true;
  }

  // Read text-string. Returns view into _data with length.
  bool readText(const char** out, size_t* len_out) {
    if (atEnd()) { _err = true; return false; }
    uint8_t b = peek();
    if ((b & 0xE0) != 0x60) { _err = true; return false; }
    uint32_t l;
    if (!readTypeAndLength(0x60, &l)) return false;
    if (_data + l > _end) { _err = true; return false; }
    *out = (const char*)_data;
    *len_out = l;
    _data += l;
    return true;
  }

  bool readBytes(const uint8_t** out, size_t* len_out) {
    if (atEnd()) { _err = true; return false; }
    uint8_t b = peek();
    if ((b & 0xE0) != 0x40) { _err = true; return false; }
    uint32_t l;
    if (!readTypeAndLength(0x40, &l)) return false;
    if (_data + l > _end) { _err = true; return false; }
    *out = _data;
    *len_out = l;
    _data += l;
    return true;
  }

  bool readUInt(uint32_t* out) {
    if (atEnd()) { _err = true; return false; }
    uint8_t b = peek();
    if ((b & 0xE0) != 0x00) { _err = true; return false; }
    return readTypeAndLength(0x00, out);
  }

  bool readInt(int32_t* out) {
    if (atEnd()) { _err = true; return false; }
    uint8_t b = peek();
    if ((b & 0xE0) == 0x00) {
      uint32_t v;
      if (!readTypeAndLength(0x00, &v)) return false;
      *out = (int32_t)v;
      return true;
    }
    if ((b & 0xE0) == 0x20) {
      uint32_t v;
      if (!readTypeAndLength(0x20, &v)) return false;
      *out = -(int32_t)v - 1;
      return true;
    }
    _err = true;
    return false;
  }

  // Skip the next CBOR data item (recursively for compound types).
  bool skipItem() {
    if (atEnd()) { _err = true; return false; }
    uint8_t b = peek();
    uint8_t major = b & 0xE0;
    uint32_t v;
    switch (major) {
      case 0x00:  // unsigned
      case 0x20:  // negative
        return readTypeAndLength(major, &v);
      case 0x40:  // bytes
      case 0x60:  // text
        if (!readTypeAndLength(major, &v)) return false;
        if (_data + v > _end) { _err = true; return false; }
        _data += v;
        return true;
      case 0x80:  // array
        if (!readTypeAndLength(major, &v)) return false;
        for (uint32_t i = 0; i < v; ++i) {
          if (!skipItem()) return false;
        }
        return true;
      case 0xA0:  // map
        if (!readTypeAndLength(major, &v)) return false;
        for (uint32_t i = 0; i < v; ++i) {
          if (!skipItem()) return false;  // key
          if (!skipItem()) return false;  // value
        }
        return true;
      default:
        _err = true;
        return false;
    }
  }

private:
  const uint8_t* _data;
  const uint8_t* _end;
  bool _err;

  bool atEnd() const { return _data >= _end; }
  uint8_t peek() const { return *_data; }

  bool readTypeAndLength(uint8_t expected_major, uint32_t* out) {
    if (atEnd()) { _err = true; return false; }
    uint8_t b = *_data++;
    if ((b & 0xE0) != expected_major) {
      _err = true;
      return false;
    }
    uint8_t info = b & 0x1F;
    if (info < 24) {
      *out = info;
      return true;
    }
    auto need = [&](uint8_t n) -> bool {
      if (_data + n > _end) { _err = true; return false; }
      return true;
    };
    switch (info) {
      case 24:
        if (!need(1)) return false;
        *out = *_data++;
        return true;
      case 25:
        if (!need(2)) return false;
        *out = ((uint32_t)_data[0] << 8) | _data[1];
        _data += 2;
        return true;
      case 26:
        if (!need(4)) return false;
        *out = ((uint32_t)_data[0] << 24) | ((uint32_t)_data[1] << 16)
             | ((uint32_t)_data[2] << 8) | _data[3];
        _data += 4;
        return true;
      default:
        _err = true;
        return false;
    }
  }
};

}  // namespace mcbridge
