/*
 * nghttp2
 *
 * Copyright (c) 2026 nghttp2 contributors
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 * LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 * WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
#include "nghttp2_log.h"

#include <stdio.h>
#ifdef HAVE_UNISTD_H
#  include <unistd.h>
#endif /* defined(HAVE_UNISTD_H) */
#include <assert.h>
#include <string.h>

#include "nghttp2_str.h"
#include "nghttp2_macro.h"
#include "nghttp2_conv.h"
#include "nghttp2_unreachable.h"

void nghttp2_log_init(nghttp2_log *log, uint64_t conn_id,
                      nghttp2_log_write log_write, char *buf, nghttp2_tstamp ts,
                      void *user_data) {
  log->conn_id = conn_id;
  log->log_write = log_write;
  log->events = 0xFF;
  log->ts = log->last_ts = ts;
  log->user_data = user_data;
  log->buf = buf;
}

/*
 * # Log header
 *
 * <LEVEL><TIMESTAMP> <CONN_ID> <EVENT>
 *
 * <LEVEL>:
 *   Log level.  I=Info, W=Warning, E=Error
 *
 * <TIMESTAMP>:
 *   Timestamp relative to nghttp2_log.ts field in milliseconds
 *   resolution.
 *
 * <CONN_ID>:
 *   Connection ID in hex string.  This is not a QUIC Connection ID.
 *
 * <EVENT>:
 *   Event.  See nghttp2_log_event.
 *
 * # Frame event
 *
 * <DIR> <FRAMENAME>(<FRAMETYPE>)
 *
 * <DIR>:
 *   Flow direction.  tx=transmission, rx=reception
 *
 * <FRAMENAME>:
 *   Frame name.  (e.g., STREAM, ACK, PING)
 *
 * <FRAMETYPE>:
 *   Frame type in hex string.
 */

static const char *strerrorcode(uint64_t error_code) {
  switch (error_code) {
  case NGHTTP2_NO_ERROR:
    return "NO_ERROR";
  case NGHTTP2_PROTOCOL_ERROR:
    return "PROTOCOL_ERROR";
  case NGHTTP2_INTERNAL_ERROR:
    return "INTERNAL_ERROR";
  case NGHTTP2_FLOW_CONTROL_ERROR:
    return "FLOW_CONTROL_ERROR";
  case NGHTTP2_SETTINGS_TIMEOUT:
    return "SETTINGS_TIMEOUT";
  case NGHTTP2_STREAM_CLOSED:
    return "STREAM_CLOSED";
  case NGHTTP2_FRAME_SIZE_ERROR:
    return "FRAME_SIZE_ERROR";
  case NGHTTP2_REFUSED_STREAM:
    return "REFUSED_STREAM";
  case NGHTTP2_CANCEL:
    return "CANCEL";
  case NGHTTP2_COMPRESSION_ERROR:
    return "COMPRESSION_ERROR";
  case NGHTTP2_CONNECT_ERROR:
    return "CONNECT_ERROR";
  case NGHTTP2_ENHANCE_YOUR_CALM:
    return "ENHANCE_YOUR_CALM";
  case NGHTTP2_INADEQUATE_SECURITY:
    return "INADEQUATE_SECURITY";
  case NGHTTP2_HTTP_1_1_REQUIRED:
    return "HTTP_1_1_REQUIRED";
  default:
    return "(unknown)";
  }
}

static void log_fr_data(nghttp2_log *log, const nghttp2_frame_data *fr,
                        const char *dir) {
  nghttp2_log_infof_raw(
    log, NGHTTP2_LOG_EVENT_FRM, dir, " DATA(0x", hex(fr->hd.type),
    ") len=", fr->hd.len, " flags=0x", hex(fr->hd.flags), " id=0x",
    hex(fr->hd.stream_id), " padlen=", fr->padlen, " datalen=", fr->datalen,
    " fin=", (fr->hd.flags & NGHTTP2_DATA_FLAG_END_STREAM) != 0);
}

static void log_fr_headers(nghttp2_log *log, const nghttp2_frame_headers *fr,
                           const char *dir) {
  nghttp2_log_infof_raw(log, NGHTTP2_LOG_EVENT_FRM, dir, " HEADERS(0x",
                        hex(fr->hd.type), ") len=0x", fr->hd.len, " flags=0x",
                        hex(fr->hd.flags), " id=", hex(fr->hd.stream_id),
                        " padlen=", fr->padlen,
                        " field_blocklen=", fr->field_blocklen);
}

static void log_fr_continuation(nghttp2_log *log,
                                const nghttp2_frame_headers *fr,
                                const char *dir) {
  nghttp2_log_infof_raw(log, NGHTTP2_LOG_EVENT_FRM, dir, " CONTINUATION(0x",
                        hex(fr->hd.type), ") len=0x", fr->hd.len, " flags=0x",
                        hex(fr->hd.flags), " id=", hex(fr->hd.stream_id),
                        " field_blocklen=", fr->field_blocklen);
}

static void log_fr_rst_stream(nghttp2_log *log,
                              const nghttp2_frame_rst_stream *fr,
                              const char *dir) {
  nghttp2_log_infof_raw(log, NGHTTP2_LOG_EVENT_FRM, dir, " RST_STREAM(0x",
                        hex(fr->hd.type), ") len=", fr->hd.len, " id=0x",
                        hex(fr->hd.stream_id),
                        " error_code=", strerrorcode(fr->error_code), "(0x",
                        hex(fr->error_code), ")");
}

static void log_rx_fr_settings(nghttp2_log *log,
                               const nghttp2_frame_settings *fr) {
  const nghttp2_proto_settings *settings = fr->settings;

#define NGHTTP2_LOG_SETTINGS_HD(FR)                                            \
  "rx SETTINGS(0x", hex((FR)->hd.type), ") len=", fr->hd.len, " flags=0x",     \
    hex(fr->hd.flags)

  if (fr->hd.len == 0 || (fr->hd.flags & NGHTTP2_SETTINGS_FLAG_ACK)) {
    nghttp2_log_infof_raw(log, NGHTTP2_LOG_EVENT_FRM,
                          NGHTTP2_LOG_SETTINGS_HD(fr));

    return;
  }

  nghttp2_log_infof_raw(
    log, NGHTTP2_LOG_EVENT_FRM, NGHTTP2_LOG_SETTINGS_HD(fr),
    " SETTINGS_HEADER_TABLE_SIZE(0x1)=", settings->hpack_max_dtable_capacity);
  nghttp2_log_infof_raw(
    log, NGHTTP2_LOG_EVENT_FRM, NGHTTP2_LOG_SETTINGS_HD(fr),
    " SETTINGS_MAX_CONCURRENT_STREAMS(0x3)=", settings->max_concurrent_streams);
  nghttp2_log_infof_raw(
    log, NGHTTP2_LOG_EVENT_FRM, NGHTTP2_LOG_SETTINGS_HD(fr),
    " SETTINGS_INITIAL_WINDOW_SIZE(0x4)=", settings->initial_max_stream_data);
  nghttp2_log_infof_raw(
    log, NGHTTP2_LOG_EVENT_FRM, NGHTTP2_LOG_SETTINGS_HD(fr),
    " SETTINGS_MAX_HEADER_LIST_SIZE(0x6)=", settings->max_field_section_size);
  nghttp2_log_infof_raw(log, NGHTTP2_LOG_EVENT_FRM, NGHTTP2_LOG_SETTINGS_HD(fr),
                        " SETTINGS_ENABLE_CONNECT_PROTOCOL(0x8)=",
                        settings->enable_connect_protocol);

#undef NGHTTP2_LOG_SETTINGS_HD
}

static const char *strsettings(uint16_t id) {
  switch (id) {
  case NGHTTP2_SETTINGS_HEADER_TABLE_SIZE:
    return "SETTINGS_HEADER_TABLE_SIZE";
  case NGHTTP2_SETTINGS_ENABLE_PUSH:
    return "SETTINGS_ENABLE_PUSH";
  case NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS:
    return "SETTINGS_MAX_CONCURRENT_STREAMS";
  case NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE:
    return "SETTINGS_INITIAL_WINDOW_SIZE";
  case NGHTTP2_SETTINGS_MAX_FRAME_SIZE:
    return "SETTINGS_MAX_FRAME_SIZE";
  case NGHTTP2_SETTINGS_ENABLE_CONNECT_PROTOCOL:
    return "SETTINGS_ENABLE_CONNECT_PROTOCOL";
  case NGHTTP2_SETTINGS_NO_RFC7540_PRIORITIES:
    return "SETTINGS_NO_RFC7540_PRIORITIES";
  default:
    return "(unknown)";
  }
}

static void log_tx_fr_settings(nghttp2_log *log,
                               const nghttp2_frame_settings *fr) {
  const nghttp2_settings_entry *iv = fr->iv;
  size_t i;

#define NGHTTP2_LOG_SETTINGS_HD(FR)                                            \
  "tx SETTINGS(0x", hex((FR)->hd.type), ") len=", fr->hd.len, " flags=0x",     \
    hex(fr->hd.flags)

  if (fr->hd.len == 0 || (fr->hd.flags & NGHTTP2_SETTINGS_FLAG_ACK)) {
    nghttp2_log_infof_raw(log, NGHTTP2_LOG_EVENT_FRM,
                          NGHTTP2_LOG_SETTINGS_HD(fr));

    return;
  }

  for (i = 0; i < fr->niv; ++i) {
    nghttp2_log_infof_raw(
      log, NGHTTP2_LOG_EVENT_FRM, NGHTTP2_LOG_SETTINGS_HD(fr), " ",
      strsettings(iv[i].id), "(0x", hex(iv[i].id), ")=", iv[i].value);
  }

#undef NGHTTP2_LOG_SETTINGS_HD
}

static void log_fr_window_update(nghttp2_log *log,
                                 const nghttp2_frame_window_update *fr,
                                 const char *dir) {
  nghttp2_log_infof_raw(log, NGHTTP2_LOG_EVENT_FRM, dir, " WINDOW_UPDATE(0x",
                        hex(fr->hd.type), ") len=", fr->hd.len, " id=0x",
                        hex(fr->hd.stream_id),
                        " window_size_increment=", fr->window_size_inc);
}

void nghttp2_log_rx_data(nghttp2_log *log, const nghttp2_frame_data *fr) {
  if (!log->log_write || !(log->events & NGHTTP2_LOG_EVENT_FRM)) {
    return;
  }

  log_fr_data(log, fr, "rx");
}

void nghttp2_log_rx_headers(nghttp2_log *log, const nghttp2_frame_headers *fr) {
  if (!log->log_write || !(log->events & NGHTTP2_LOG_EVENT_FRM)) {
    return;
  }

  log_fr_headers(log, fr, "rx");
}

void nghttp2_log_rx_rst_stream(nghttp2_log *log,
                               const nghttp2_frame_rst_stream *fr) {
  if (!log->log_write || !(log->events & NGHTTP2_LOG_EVENT_FRM)) {
    return;
  }

  log_fr_rst_stream(log, fr, "rx");
}

void nghttp2_log_rx_settings(nghttp2_log *log,
                             const nghttp2_frame_settings *fr) {
  if (!log->log_write || !(log->events & NGHTTP2_LOG_EVENT_FRM)) {
    return;
  }

  log_rx_fr_settings(log, fr);
}

void nghttp2_log_rx_window_update(nghttp2_log *log,
                                  const nghttp2_frame_window_update *fr) {
  if (!log->log_write || !(log->events & NGHTTP2_LOG_EVENT_FRM)) {
    return;
  }

  log_fr_window_update(log, fr, "rx");
}

void nghttp2_log_tx_data(nghttp2_log *log, const nghttp2_frame_data *fr) {
  if (!log->log_write || !(log->events & NGHTTP2_LOG_EVENT_FRM)) {
    return;
  }

  log_fr_data(log, fr, "tx");
}

void nghttp2_log_tx_headers(nghttp2_log *log, const nghttp2_frame_headers *fr) {
  if (!log->log_write || !(log->events & NGHTTP2_LOG_EVENT_FRM)) {
    return;
  }

  log_fr_headers(log, fr, "tx");
}

void nghttp2_log_tx_continuation(nghttp2_log *log,
                                 const nghttp2_frame_headers *fr) {
  if (!log->log_write || !(log->events & NGHTTP2_LOG_EVENT_FRM)) {
    return;
  }

  log_fr_continuation(log, fr, "tx");
}

void nghttp2_log_tx_rst_stream(nghttp2_log *log,
                               const nghttp2_frame_rst_stream *fr) {
  if (!log->log_write || !(log->events & NGHTTP2_LOG_EVENT_FRM)) {
    return;
  }

  log_fr_rst_stream(log, fr, "tx");
}

void nghttp2_log_tx_settings(nghttp2_log *log,
                             const nghttp2_frame_settings *fr) {
  if (!log->log_write || !(log->events & NGHTTP2_LOG_EVENT_FRM)) {
    return;
  }

  log_tx_fr_settings(log, fr);
}

void nghttp2_log_tx_window_update(nghttp2_log *log,
                                  const nghttp2_frame_window_update *fr) {
  if (!log->log_write || !(log->events & NGHTTP2_LOG_EVENT_FRM)) {
    return;
  }

  log_fr_window_update(log, fr, "tx");
}

uint64_t nghttp2_log_timestamp(const nghttp2_log *log) {
  return (log->last_ts - log->ts) / NGHTTP2_MILLISECONDS;
}
