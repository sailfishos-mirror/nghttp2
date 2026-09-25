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
#include "nghttp2_conn_test.h"

#include <stdio.h>
#include <unistd.h>
#include <errno.h>

#include "nghttp2_conn.h"
#include "nghttp2_test_helper.h"

static const MunitTest tests[] = {
  munit_void_test(test_nghttp2_conn_read_request),
  munit_void_test(test_nghttp2_conn_submit_request),
  munit_void_test(test_nghttp2_conn_read_preface),
  munit_void_test(test_nghttp2_conn_recv_frame_hd),
  munit_void_test(test_nghttp2_conn_recv_headers),
  munit_void_test(test_nghttp2_conn_recv_continuation),
  munit_void_test(test_nghttp2_conn_recv_data),
  munit_void_test(test_nghttp2_conn_recv_rst_stream),
  munit_void_test(test_nghttp2_conn_recv_settings),
  munit_test_end(),
};

const MunitSuite conn_suite = {
  .prefix = "/conn",
  .tests = tests,
};

static const nghttp2_nv reqnva[] = {
  MAKE_NV(":method", "GET"),
  MAKE_NV(":scheme", "https"),
  MAKE_NV(":authority", "example.com"),
  MAKE_NV(":path", "/"),
  MAKE_NV("user-agent", "nghttp2 client"),
};

static const nghttp2_nv trnva[] = {
  MAKE_NV("trailer1", "foo"),
  MAKE_NV("trailer2", "bar"),
};

typedef struct conn_options {
  const nghttp2_callbacks *callbacks;
  const nghttp2_settings *settings;
  const nghttp2_mem *mem;
  void *user_data;
} conn_options;

typedef struct userdata {
  struct {
    size_t ncalled;
    nghttp2_proto_settings settings;
  } recv_settings;
  struct {
    size_t ncalled;
    int64_t stream_id;
  } begin_headers;
  struct {
    size_t ncalled;
    int64_t stream_id;
    const nghttp2_nv *expect_nva;
    size_t expect_nvlen;
    size_t expect_offset;
  } recv_header;
  struct {
    size_t ncalled;
    int64_t stream_id;
    int fin;
  } end_headers;
  struct {
    size_t ncalled;
    int64_t stream_id;
  } begin_trailers;
  struct {
    size_t ncalled;
    int64_t stream_id;
    const nghttp2_nv *expect_nva;
    size_t expect_nvlen;
    size_t expect_offset;
  } recv_trailer;
  struct {
    size_t ncalled;
    int64_t stream_id;
    int fin;
  } end_trailers;
  struct {
    size_t ncalled;
    int64_t stream_id;
    size_t datalen;
    int fin;
  } recv_data;
  struct {
    size_t ncalled;
    int64_t stream_id;
  } end_stream;
} userdata;

static void genrand(uint8_t *dest, size_t destlen) { memset(dest, 0, destlen); }

static int recv_settings(nghttp2_conn *conn,
                         const nghttp2_proto_settings *settings,
                         void *user_data) {
  userdata *ud = user_data;
  (void)conn;

  ++ud->recv_settings.ncalled;
  ud->recv_settings.settings = *settings;

  return 0;
}

static int begin_headers(nghttp2_conn *conn, int64_t stream_id,
                         void *conn_user_data, void *stream_user_data) {
  userdata *ud = conn_user_data;
  (void)conn;
  (void)stream_user_data;

  ++ud->begin_headers.ncalled;
  ud->begin_headers.stream_id = stream_id;

  return 0;
}

static int end_headers(nghttp2_conn *conn, int64_t stream_id, int fin,
                       void *conn_user_data, void *stream_user_data) {
  userdata *ud = conn_user_data;
  (void)conn;
  (void)stream_user_data;

  ++ud->end_headers.ncalled;
  ud->end_headers.stream_id = stream_id;
  ud->end_headers.fin = fin;

  return 0;
}

static int begin_trailers(nghttp2_conn *conn, int64_t stream_id,
                          void *conn_user_data, void *stream_user_data) {
  userdata *ud = conn_user_data;
  (void)conn;
  (void)stream_user_data;

  ++ud->begin_trailers.ncalled;
  ud->begin_trailers.stream_id = stream_id;

  return 0;
}

static int end_trailers(nghttp2_conn *conn, int64_t stream_id, int fin,
                        void *conn_user_data, void *stream_user_data) {
  userdata *ud = conn_user_data;
  (void)conn;
  (void)stream_user_data;

  ++ud->end_trailers.ncalled;
  ud->end_trailers.stream_id = stream_id;
  ud->end_trailers.fin = fin;

  return 0;
}

static int recv_header(nghttp2_conn *conn, int64_t stream_id, int32_t token,
                       nghttp2_rcbuf *name, nghttp2_rcbuf *value, uint8_t flags,
                       void *conn_user_data, void *stream_user_data) {
  userdata *ud = conn_user_data;
  const nghttp2_nv *nv;
  (void)conn;
  (void)token;
  (void)flags;
  (void)stream_user_data;

  ++ud->recv_header.ncalled;
  ud->recv_header.stream_id = stream_id;

  assert_size(ud->recv_header.expect_nvlen, >, ud->recv_header.expect_offset);

  nv = &ud->recv_header.expect_nva[ud->recv_header.expect_offset++];

  assert_memn_equal(nv->name, nv->namelen, name->base, name->len);
  assert_memn_equal(nv->value, nv->valuelen, value->base, value->len);

  return 0;
}

static int recv_trailer(nghttp2_conn *conn, int64_t stream_id, int32_t token,
                        nghttp2_rcbuf *name, nghttp2_rcbuf *value,
                        uint8_t flags, void *conn_user_data,
                        void *stream_user_data) {
  userdata *ud = conn_user_data;
  const nghttp2_nv *nv;
  (void)conn;
  (void)token;
  (void)flags;
  (void)stream_user_data;

  ++ud->recv_trailer.ncalled;
  ud->recv_trailer.stream_id = stream_id;

  assert_size(ud->recv_trailer.expect_nvlen, >, ud->recv_trailer.expect_offset);

  nv = &ud->recv_trailer.expect_nva[ud->recv_trailer.expect_offset++];

  assert_memn_equal(nv->name, nv->namelen, name->base, name->len);
  assert_memn_equal(nv->value, nv->valuelen, value->base, value->len);

  return 0;
}

static int recv_data(nghttp2_conn *conn, int64_t stream_id, const uint8_t *data,
                     size_t datalen, int fin, void *conn_user_data,
                     void *stream_user_data) {
  userdata *ud = conn_user_data;
  (void)conn;
  (void)data;
  (void)stream_user_data;

  ++ud->recv_data.ncalled;
  ud->recv_data.stream_id = stream_id;
  ud->recv_data.datalen += datalen;
  ud->recv_data.fin = fin;

  return 0;
}

static int end_stream(nghttp2_conn *conn, int64_t stream_id,
                      void *conn_user_data, void *stream_user_data) {
  userdata *ud = conn_user_data;
  (void)conn;
  (void)stream_user_data;

  ++ud->end_stream.ncalled;
  ud->end_stream.stream_id = stream_id;

  return 0;
}

static void log_write(void *user_data, char *msg, size_t len) {
  ssize_t nwrite;
  (void)user_data;

  msg[len++] = '\n';

  while ((nwrite = write(fileno(stderr), msg,
#ifdef WIN32
                         (unsigned int)
#endif /* WIN32 */
                           len)) == -1 &&
         errno == EINTR)
    ;

  assert_ssize((ssize_t)len, ==, nwrite);
}

static uint8_t nulldata[1 << 20];

static nghttp2_ssize read_data_nk(nghttp2_conn *conn, int64_t stream_id,
                                  nghttp2_vec *vec, size_t veccnt,
                                  uint32_t *pflags, void *conn_user_data,
                                  void *stream_user_data, size_t n) {
  (void)conn;
  (void)stream_id;
  (void)veccnt;
  (void)conn_user_data;
  (void)stream_user_data;

  vec[0] = (nghttp2_vec){
    .base = nulldata,
    .len = n,
  };

  *pflags |= NGHTTP2_READ_DATA_FLAG_EOF;

  return 1;
}

static nghttp2_ssize read_data_4k(nghttp2_conn *conn, int64_t stream_id,
                                  nghttp2_vec *vec, size_t veccnt,
                                  uint32_t *pflags, void *conn_user_data,
                                  void *stream_user_data) {
  return read_data_nk(conn, stream_id, vec, veccnt, pflags, conn_user_data,
                      stream_user_data, 1 << 12);
}

static nghttp2_ssize read_data_128k(nghttp2_conn *conn, int64_t stream_id,
                                    nghttp2_vec *vec, size_t veccnt,
                                    uint32_t *pflags, void *conn_user_data,
                                    void *stream_user_data) {
  return read_data_nk(conn, stream_id, vec, veccnt, pflags, conn_user_data,
                      stream_user_data, 1 << 17);
}

static size_t server_default_remote_settings(nghttp2_settings_entry *iv) {
  iv[0] = (nghttp2_settings_entry){
    .id = NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS,
    .value = 100,
  };

  return 1;
}

static void server_default_callbacks(nghttp2_callbacks *callbacks) {
  *callbacks = (nghttp2_callbacks){
    .rand = genrand,
  };
}

static void server_default_settings(nghttp2_settings *settings) {
  nghttp2_settings_default(settings);
  settings->max_concurrent_streams_remote = 100;
  settings->log_write = log_write;
}

static void setup_default_server_with_options(nghttp2_conn **pconn,
                                              conn_options opts) {
  nghttp2_callbacks callbacks;
  nghttp2_settings settings;
  int rv;

  if (!opts.callbacks) {
    server_default_callbacks(&callbacks);
    opts.callbacks = &callbacks;
  }

  if (!opts.settings) {
    server_default_settings(&settings);
    opts.settings = &settings;
  }

  rv = nghttp2_conn_server_new(pconn, opts.callbacks, opts.settings, opts.mem,
                               opts.user_data);

  assert_int(0, ==, rv);
}

static void setup_default_server(nghttp2_conn **pconn) {
  setup_default_server_with_options(pconn, (conn_options){0});
}

/* static size_t client_default_remote_settings(nghttp2_settings_entry *iv) { */
/*   iv[0] = (nghttp2_settings_entry){ */
/*     .id = NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, */
/*     .value = 100, */
/*   }; */

/*   return 1; */
/* } */

static void client_default_callbacks(nghttp2_callbacks *callbacks) {
  *callbacks = (nghttp2_callbacks){
    .rand = genrand,
  };
}

static void client_default_settings(nghttp2_settings *settings) {
  nghttp2_settings_default(settings);
  settings->log_write = log_write;
}

static void setup_default_client_with_options(nghttp2_conn **pconn,
                                              conn_options opts) {
  nghttp2_callbacks callbacks;
  nghttp2_settings settings;
  int rv;

  if (!opts.callbacks) {
    client_default_callbacks(&callbacks);
    opts.callbacks = &callbacks;
  }

  if (!opts.settings) {
    client_default_settings(&settings);
    opts.settings = &settings;
  }

  rv = nghttp2_conn_client_new(pconn, opts.callbacks, opts.settings, opts.mem,
                               opts.user_data);

  assert_int(0, ==, rv);
}

static void setup_default_client(nghttp2_conn **pconn) {
  setup_default_client_with_options(pconn, (conn_options){0});
}

static void read_client_preface(nghttp2_conn *conn,
                                const nghttp2_settings_entry *iv, size_t ivlen,
                                nghttp2_tstamp ts) {
  int rv;
  uint8_t rawbuf[256];
  nghttp2_buf buf;

  rv = nghttp2_conn_read(conn, (const uint8_t *)NGHTTP2_CLIENT_HTTP2_PREFACE,
                         nghttp2_strlen_lit(NGHTTP2_CLIENT_HTTP2_PREFACE), ts);

  assert_int(0, ==, rv);

  nghttp2_buf_wrap_init(&buf, rawbuf, sizeof(rawbuf));
  write_settings(&buf, iv, ivlen);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ts);

  assert_int(0, ==, rv);
}

static void read_server_preface(nghttp2_conn *conn,
                                const nghttp2_settings_entry *iv, size_t ivlen,
                                nghttp2_tstamp ts) {
  int rv;
  uint8_t rawbuf[256];
  nghttp2_buf buf;

  nghttp2_buf_wrap_init(&buf, rawbuf, sizeof(rawbuf));
  write_settings(&buf, iv, ivlen);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ts);

  assert_int(0, ==, rv);
}

void test_nghttp2_conn_read_request(void) {
  const nghttp2_mem *mem = nghttp2_mem_default();
  nghttp2_conn *conn;
  nghttp2_settings_entry iv[16];
  size_t ivlen;
  nghttp2_frame fr;
  nghttp2_hpack_encoder enc;
  uint8_t rawbuf[16384];
  nghttp2_buf buf;
  nghttp2_buf hbuf;
  nghttp2_tstamp ts = 0;
  nghttp2_stream *stream;
  userdata ud;
  nghttp2_callbacks callbacks;
  conn_options opts;
  int rv;

  nghttp2_buf_wrap_init(&buf, rawbuf, sizeof(rawbuf));

  /* Read request without data */
  server_default_callbacks(&callbacks);
  callbacks.begin_headers = begin_headers;
  callbacks.recv_header = recv_header;
  callbacks.end_headers = end_headers;
  callbacks.end_stream = end_stream;

  opts = (conn_options){
    .callbacks = &callbacks,
    .user_data = &ud,
  };

  setup_default_server_with_options(&conn, opts);
  ivlen = server_default_remote_settings(iv);
  read_client_preface(conn, iv, ivlen, ts);

  nghttp2_buf_init(&hbuf);
  nghttp2_hpack_encoder_init(&enc, NGHTTP2_HPACK_DEFAULT_MAX_BUFFER_SIZE, mem);

  nghttp2_buf_reset(&hbuf);
  rv =
    nghttp2_hpack_encoder_write(&enc, &hbuf, reqnva, nghttp2_arraylen(reqnva));

  assert_int(0, ==, rv);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags =
          NGHTTP2_HEADERS_FLAG_END_HEADERS | NGHTTP2_HEADERS_FLAG_END_STREAM,
        .stream_id = 1,
      },
    .field_block = hbuf.pos,
    .field_blocklen = nghttp2_buf_len(&hbuf),
  };

  nghttp2_buf_reset(&buf);
  write_frame(&buf, &fr);

  ud = (userdata){
    .recv_header.expect_nva = reqnva,
    .recv_header.expect_nvlen = nghttp2_arraylen(reqnva),
  };
  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH,
              ==, conn->rx.frrd.state);
  assert_size(1, ==, ud.begin_headers.ncalled);
  assert_int64(1, ==, ud.begin_headers.stream_id);
  assert_size(1, ==, ud.end_headers.ncalled);
  assert_int64(1, ==, ud.end_headers.stream_id);
  assert_true(ud.end_headers.fin);
  assert_size(nghttp2_arraylen(reqnva), ==, ud.recv_header.ncalled);
  assert_int64(1, ==, ud.recv_header.stream_id);
  assert_size(nghttp2_arraylen(reqnva), ==, ud.recv_header.expect_offset);
  assert_size(1, ==, ud.end_stream.ncalled);
  assert_int64(1, ==, ud.end_stream.stream_id);

  stream = nghttp2_conn_find_stream(conn, 1);

  assert_not_null(stream);
  assert_true(stream->flags & NGHTTP2_STREAM_FLAG_SHUT_RD);

  nghttp2_buf_free(&hbuf, mem);
  nghttp2_hpack_encoder_free(&enc);
  nghttp2_conn_del(conn);

  /* Read request with data */
  server_default_callbacks(&callbacks);
  callbacks.begin_headers = begin_headers;
  callbacks.recv_header = recv_header;
  callbacks.end_headers = end_headers;
  callbacks.end_stream = end_stream;
  callbacks.recv_data = recv_data;

  opts = (conn_options){
    .callbacks = &callbacks,
    .user_data = &ud,
  };

  setup_default_server_with_options(&conn, opts);
  ivlen = server_default_remote_settings(iv);
  read_client_preface(conn, iv, ivlen, ts);

  nghttp2_hpack_encoder_init(&enc, NGHTTP2_HPACK_DEFAULT_MAX_BUFFER_SIZE, mem);

  nghttp2_buf_init(&hbuf);
  rv =
    nghttp2_hpack_encoder_write(&enc, &hbuf, reqnva, nghttp2_arraylen(reqnva));

  assert_int(0, ==, rv);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags = NGHTTP2_HEADERS_FLAG_END_HEADERS,
        .stream_id = 1,
      },
    .field_block = hbuf.pos,
    .field_blocklen = nghttp2_buf_len(&hbuf),
  };

  nghttp2_buf_reset(&buf);
  write_frame(&buf, &fr);

  ud = (userdata){
    .recv_header.expect_nva = reqnva,
    .recv_header.expect_nvlen = nghttp2_arraylen(reqnva),
  };
  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH,
              ==, conn->rx.frrd.state);
  assert_size(1, ==, ud.begin_headers.ncalled);
  assert_int64(1, ==, ud.begin_headers.stream_id);
  assert_size(1, ==, ud.end_headers.ncalled);
  assert_int64(1, ==, ud.end_headers.stream_id);
  assert_false(ud.end_headers.fin);
  assert_size(nghttp2_arraylen(reqnva), ==, ud.recv_header.ncalled);
  assert_int64(1, ==, ud.recv_header.stream_id);
  assert_size(nghttp2_arraylen(reqnva), ==, ud.recv_header.expect_offset);
  assert_size(0, ==, ud.end_stream.ncalled);

  stream = nghttp2_conn_find_stream(conn, 1);

  assert_not_null(stream);
  assert_false(stream->flags & NGHTTP2_STREAM_FLAG_SHUT_RD);

  fr.data = (nghttp2_frame_data){
    .hd =
      {
        .type = NGHTTP2_FRAME_DATA,
        .stream_id = 1,
      },
    .datalen = 77,
  };

  nghttp2_buf_reset(&buf);
  write_frame(&buf, &fr);

  ud = (userdata){0};
  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH,
              ==, conn->rx.frrd.state);
  assert_size(1, ==, ud.recv_data.ncalled);
  assert_int64(1, ==, ud.recv_data.stream_id);
  assert_size(77, ==, ud.recv_data.datalen);
  assert_false(ud.recv_data.fin);
  assert_size(0, ==, ud.end_stream.ncalled);

  stream = nghttp2_conn_find_stream(conn, 1);

  assert_not_null(stream);
  assert_false(stream->flags & NGHTTP2_STREAM_FLAG_SHUT_RD);

  fr.data = (nghttp2_frame_data){
    .hd =
      {
        .type = NGHTTP2_FRAME_DATA,
        .flags = NGHTTP2_DATA_FLAG_END_STREAM,
        .stream_id = 1,
      },
    .datalen = 22,
  };

  nghttp2_buf_reset(&buf);
  write_frame(&buf, &fr);

  ud = (userdata){0};
  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH,
              ==, conn->rx.frrd.state);
  assert_size(1, ==, ud.recv_data.ncalled);
  assert_int64(1, ==, ud.recv_data.stream_id);
  assert_size(22, ==, ud.recv_data.datalen);
  assert_true(ud.recv_data.fin);
  assert_size(1, ==, ud.end_stream.ncalled);
  assert_int64(1, ==, ud.end_stream.stream_id);

  stream = nghttp2_conn_find_stream(conn, 1);

  assert_not_null(stream);
  assert_true(stream->flags & NGHTTP2_STREAM_FLAG_SHUT_RD);

  nghttp2_buf_free(&hbuf, mem);
  nghttp2_hpack_encoder_free(&enc);
  nghttp2_conn_del(conn);

  /* Read request with data and trailers */
  server_default_callbacks(&callbacks);
  callbacks.begin_headers = begin_headers;
  callbacks.recv_header = recv_header;
  callbacks.end_headers = end_headers;
  callbacks.begin_trailers = begin_trailers;
  callbacks.recv_trailer = recv_trailer;
  callbacks.end_trailers = end_trailers;
  callbacks.end_stream = end_stream;
  callbacks.recv_data = recv_data;

  opts = (conn_options){
    .callbacks = &callbacks,
    .user_data = &ud,
  };

  setup_default_server_with_options(&conn, opts);
  ivlen = server_default_remote_settings(iv);
  read_client_preface(conn, iv, ivlen, ts);

  nghttp2_hpack_encoder_init(&enc, NGHTTP2_HPACK_DEFAULT_MAX_BUFFER_SIZE, mem);

  nghttp2_buf_init(&hbuf);
  rv =
    nghttp2_hpack_encoder_write(&enc, &hbuf, reqnva, nghttp2_arraylen(reqnva));

  assert_int(0, ==, rv);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags = NGHTTP2_HEADERS_FLAG_END_HEADERS,
        .stream_id = 1,
      },
    .field_block = hbuf.pos,
    .field_blocklen = nghttp2_buf_len(&hbuf),
  };

  nghttp2_buf_reset(&buf);
  write_frame(&buf, &fr);

  ud = (userdata){
    .recv_header.expect_nva = reqnva,
    .recv_header.expect_nvlen = nghttp2_arraylen(reqnva),
  };
  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH,
              ==, conn->rx.frrd.state);
  assert_size(1, ==, ud.begin_headers.ncalled);
  assert_int64(1, ==, ud.begin_headers.stream_id);
  assert_size(1, ==, ud.end_headers.ncalled);
  assert_int64(1, ==, ud.end_headers.stream_id);
  assert_false(ud.end_headers.fin);
  assert_size(nghttp2_arraylen(reqnva), ==, ud.recv_header.ncalled);
  assert_int64(1, ==, ud.recv_header.stream_id);
  assert_size(nghttp2_arraylen(reqnva), ==, ud.recv_header.expect_offset);
  assert_size(0, ==, ud.end_stream.ncalled);

  stream = nghttp2_conn_find_stream(conn, 1);

  assert_not_null(stream);
  assert_false(stream->flags & NGHTTP2_STREAM_FLAG_SHUT_RD);

  fr.data = (nghttp2_frame_data){
    .hd =
      {
        .type = NGHTTP2_FRAME_DATA,
        .stream_id = 1,
      },
    .datalen = 77,
  };

  nghttp2_buf_reset(&buf);
  write_frame(&buf, &fr);

  ud = (userdata){0};
  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH,
              ==, conn->rx.frrd.state);
  assert_size(1, ==, ud.recv_data.ncalled);
  assert_int64(1, ==, ud.recv_data.stream_id);
  assert_size(77, ==, ud.recv_data.datalen);
  assert_false(ud.recv_data.fin);
  assert_size(0, ==, ud.end_stream.ncalled);

  stream = nghttp2_conn_find_stream(conn, 1);

  assert_not_null(stream);
  assert_false(stream->flags & NGHTTP2_STREAM_FLAG_SHUT_RD);

  nghttp2_buf_reset(&hbuf);
  rv = nghttp2_hpack_encoder_write(&enc, &hbuf, trnva, nghttp2_arraylen(trnva));

  assert_int(0, ==, rv);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags =
          NGHTTP2_HEADERS_FLAG_END_HEADERS | NGHTTP2_HEADERS_FLAG_END_STREAM,
        .stream_id = 1,
      },
    .field_block = hbuf.pos,
    .field_blocklen = nghttp2_buf_len(&hbuf),
  };

  nghttp2_buf_reset(&buf);
  write_frame(&buf, &fr);

  ud = (userdata){
    .recv_trailer.expect_nva = trnva,
    .recv_trailer.expect_nvlen = nghttp2_arraylen(trnva),
  };
  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH,
              ==, conn->rx.frrd.state);
  assert_size(1, ==, ud.begin_trailers.ncalled);
  assert_int64(1, ==, ud.begin_trailers.stream_id);
  assert_size(1, ==, ud.end_trailers.ncalled);
  assert_int64(1, ==, ud.end_trailers.stream_id);
  assert_true(ud.end_trailers.fin);
  assert_size(nghttp2_arraylen(trnva), ==, ud.recv_trailer.ncalled);
  assert_int64(1, ==, ud.recv_trailer.stream_id);
  assert_size(nghttp2_arraylen(trnva), ==, ud.recv_trailer.expect_offset);
  assert_size(1, ==, ud.end_stream.ncalled);
  assert_int64(1, ==, ud.end_stream.stream_id);

  stream = nghttp2_conn_find_stream(conn, 1);

  assert_not_null(stream);
  assert_true(stream->flags & NGHTTP2_STREAM_FLAG_SHUT_RD);

  nghttp2_buf_free(&hbuf, mem);
  nghttp2_hpack_encoder_free(&enc);
  nghttp2_conn_del(conn);

  /* Read request including CONTINUATION without data */
  server_default_callbacks(&callbacks);
  callbacks.begin_headers = begin_headers;
  callbacks.recv_header = recv_header;
  callbacks.end_headers = end_headers;
  callbacks.end_stream = end_stream;

  opts = (conn_options){
    .callbacks = &callbacks,
    .user_data = &ud,
  };

  setup_default_server_with_options(&conn, opts);
  ivlen = server_default_remote_settings(iv);
  read_client_preface(conn, iv, ivlen, ts);

  nghttp2_buf_init(&hbuf);
  nghttp2_hpack_encoder_init(&enc, NGHTTP2_HPACK_DEFAULT_MAX_BUFFER_SIZE, mem);

  nghttp2_buf_reset(&hbuf);
  rv =
    nghttp2_hpack_encoder_write(&enc, &hbuf, reqnva, nghttp2_arraylen(reqnva));

  assert_int(0, ==, rv);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags = NGHTTP2_HEADERS_FLAG_END_STREAM,
        .stream_id = 1,
      },
    .field_block = hbuf.pos,
    .field_blocklen = nghttp2_buf_len(&hbuf) - 1,
  };

  hbuf.pos += fr.headers.field_blocklen;
  nghttp2_buf_reset(&buf);
  write_frame(&buf, &fr);

  ud = (userdata){
    .recv_header.expect_nva = reqnva,
    .recv_header.expect_nvlen = nghttp2_arraylen(reqnva) - 1,
  };
  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state,
              NGHTTP2_FRAME_READ_STATE_CONTINUATION_FRAME_LENGTH, ==,
              conn->rx.frrd.state);
  assert_size(1, ==, ud.begin_headers.ncalled);
  assert_int64(1, ==, ud.begin_headers.stream_id);
  assert_size(0, ==, ud.end_headers.ncalled);
  assert_size(nghttp2_arraylen(reqnva) - 1, ==, ud.recv_header.ncalled);
  assert_int64(1, ==, ud.recv_header.stream_id);
  assert_size(nghttp2_arraylen(reqnva) - 1, ==, ud.recv_header.expect_offset);
  assert_size(0, ==, ud.end_stream.ncalled);

  stream = nghttp2_conn_find_stream(conn, 1);

  assert_not_null(stream);
  assert_false(stream->flags & NGHTTP2_STREAM_FLAG_SHUT_RD);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_CONTINUATION,
        .flags = NGHTTP2_HEADERS_FLAG_END_HEADERS,
        .stream_id = 1,
      },
    .field_block = hbuf.pos,
    .field_blocklen = nghttp2_buf_len(&hbuf),
  };

  nghttp2_buf_reset(&buf);
  write_frame(&buf, &fr);

  ud = (userdata){
    .recv_header.expect_nva = &reqnva[nghttp2_arraylen(reqnva) - 1],
    .recv_header.expect_nvlen = 1,
  };
  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH,
              ==, conn->rx.frrd.state);
  assert_size(0, ==, ud.begin_headers.ncalled);
  assert_size(1, ==, ud.end_headers.ncalled);
  assert_int64(1, ==, ud.end_headers.stream_id);
  assert_true(ud.end_headers.fin);
  assert_size(1, ==, ud.recv_header.ncalled);
  assert_int64(1, ==, ud.recv_header.stream_id);
  assert_size(1, ==, ud.recv_header.expect_offset);
  assert_size(1, ==, ud.end_stream.ncalled);
  assert_int64(1, ==, ud.end_stream.stream_id);

  stream = nghttp2_conn_find_stream(conn, 1);

  assert_not_null(stream);
  assert_true(stream->flags & NGHTTP2_STREAM_FLAG_SHUT_RD);

  nghttp2_buf_free(&hbuf, mem);
  nghttp2_hpack_encoder_free(&enc);
  nghttp2_conn_del(conn);
}

void test_nghttp2_conn_submit_request(void) {
  nghttp2_conn *conn;
  uint8_t rawbuf[16384];
  nghttp2_buf buf;
  int64_t stream_id;
  nghttp2_ssize nwrite;
  nghttp2_tstamp ts = 0;
  nghttp2_stream *stream;
  nghttp2_frame fr;
  nghttp2_frd frd;
  int rv;

  nghttp2_buf_wrap_init(&buf, rawbuf, sizeof(rawbuf));

  /* 4k data */
  setup_default_client(&conn);

  rv = nghttp2_conn_open_stream(conn, &stream_id, NULL);

  assert_int(0, ==, rv);
  assert_int64(1, ==, stream_id);

  rv = nghttp2_conn_submit_request(conn, stream_id, reqnva,
                                   nghttp2_arraylen(reqnva),
                                   &(nghttp2_data_reader){
                                     .read_data = read_data_4k,
                                   });

  assert_int(0, ==, rv);

  nghttp2_buf_reset(&buf);
  nwrite = nghttp2_conn_write(conn, buf.last, nghttp2_buf_left(&buf), ++ts);

  assert_ptrdiff(0, <, nwrite);

  buf.last += nwrite;

  stream = nghttp2_conn_find_stream(conn, stream_id);

  assert_not_null(stream);
  assert_true(stream->flags & NGHTTP2_STREAM_FLAG_SHUT_WR);

  check_http2_preface(&buf);

  rv = nghttp2_frd_decode_buf(&frd, &fr, &buf);

  assert_int(0, ==, rv);
  assert_uint8(NGHTTP2_FRAME_SETTINGS, ==, fr.meta.hd.type);
  assert_uint8(0x00U, ==, fr.settings.hd.flags);
  assert_int64(0, ==, fr.settings.hd.stream_id);
  assert_size(2, ==, fr.settings.niv);
  assert_uint16(NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, ==,
                fr.settings.iv[0].id);
  assert_uint32(0, ==, fr.settings.iv[0].value);
  assert_uint16(NGHTTP2_SETTINGS_NO_RFC7540_PRIORITIES, ==,
                fr.settings.iv[1].id);
  assert_uint32(1, ==, fr.settings.iv[1].value);

  rv = nghttp2_frd_decode_buf(&frd, &fr, &buf);

  assert_int(0, ==, rv);
  assert_uint8(NGHTTP2_FRAME_HEADERS, ==, fr.meta.hd.type);
  assert_uint8(NGHTTP2_HEADERS_FLAG_END_HEADERS, ==, fr.headers.hd.flags);
  assert_int64(1, ==, fr.headers.hd.stream_id);
  assert_size(0, ==, fr.headers.padlen);
  assert_size(0, <, fr.headers.field_blocklen);

  rv = nghttp2_frd_decode_buf(&frd, &fr, &buf);

  assert_int(0, ==, rv);
  assert_uint8(NGHTTP2_FRAME_DATA, ==, fr.meta.hd.type);
  assert_uint8(NGHTTP2_DATA_FLAG_END_STREAM, ==, fr.data.hd.flags);
  assert_int64(1, ==, fr.data.hd.stream_id);
  assert_size(0, ==, fr.data.padlen);
  assert_size(4096, ==, fr.data.datalen);
  assert_size(0, ==, nghttp2_buf_len(&buf));

  nghttp2_conn_del(conn);

  /* 128k data */
  setup_default_client(&conn);

  rv = nghttp2_conn_open_stream(conn, &stream_id, NULL);

  assert_int(0, ==, rv);
  assert_int64(1, ==, stream_id);

  rv = nghttp2_conn_submit_request(conn, stream_id, reqnva,
                                   nghttp2_arraylen(reqnva),
                                   &(nghttp2_data_reader){
                                     .read_data = read_data_128k,
                                   });

  assert_int(0, ==, rv);

  for (;;) {
    nghttp2_buf_reset(&buf);
    nwrite = nghttp2_conn_write(conn, buf.last, nghttp2_buf_left(&buf), ++ts);

    if (nwrite == 0) {
      break;
    }

    assert_ptrdiff(0, <, nwrite);
  }

  stream = nghttp2_conn_find_stream(conn, stream_id);

  assert_not_null(stream);
  assert_true(stream->flags & NGHTTP2_STREAM_FLAG_FC_BLOCKED);
  assert_true(stream->flags & NGHTTP2_STREAM_FLAG_SHUT_WR);
  assert_false(nghttp2_http_writer_empty(&stream->tx.hw));

  conn->tx.max_offset += 65537;
  stream->tx.max_offset += 65537;

  for (;;) {
    nghttp2_buf_reset(&buf);
    nwrite = nghttp2_conn_write(conn, buf.last, nghttp2_buf_left(&buf), ++ts);

    if (nwrite == 0) {
      break;
    }

    assert_ptrdiff(0, <, nwrite);
  }

  stream = nghttp2_conn_find_stream(conn, stream_id);

  assert_not_null(stream);
  assert_true(nghttp2_http_writer_empty(&stream->tx.hw));

  nghttp2_conn_del(conn);

  /* trailers */
  setup_default_client(&conn);

  rv = nghttp2_conn_open_stream(conn, &stream_id, NULL);

  assert_int(0, ==, rv);
  assert_int64(1, ==, stream_id);

  rv = nghttp2_conn_submit_request(conn, stream_id, reqnva,
                                   nghttp2_arraylen(reqnva),
                                   &(nghttp2_data_reader){
                                     .read_data = read_data_4k,
                                   });

  assert_int(0, ==, rv);

  rv = nghttp2_conn_submit_trailers(conn, stream_id, trnva,
                                    nghttp2_arraylen(trnva));

  assert_int(0, ==, rv);

  nghttp2_buf_reset(&buf);
  nwrite = nghttp2_conn_write(conn, buf.last, nghttp2_buf_left(&buf), ++ts);

  assert_ptrdiff(0, <, nwrite);

  buf.last += nwrite;

  stream = nghttp2_conn_find_stream(conn, stream_id);

  assert_not_null(stream);
  assert_true(stream->flags & NGHTTP2_STREAM_FLAG_SHUT_WR);

  check_http2_preface(&buf);

  rv = nghttp2_frd_decode_buf(&frd, &fr, &buf);

  assert_int(0, ==, rv);
  assert_uint8(NGHTTP2_FRAME_SETTINGS, ==, fr.meta.hd.type);
  assert_uint8(0x00U, ==, fr.settings.hd.flags);
  assert_int64(0, ==, fr.settings.hd.stream_id);
  assert_size(2, ==, fr.settings.niv);
  assert_uint16(NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, ==,
                fr.settings.iv[0].id);
  assert_uint32(0, ==, fr.settings.iv[0].value);
  assert_uint16(NGHTTP2_SETTINGS_NO_RFC7540_PRIORITIES, ==,
                fr.settings.iv[1].id);
  assert_uint32(1, ==, fr.settings.iv[1].value);

  rv = nghttp2_frd_decode_buf(&frd, &fr, &buf);

  assert_int(0, ==, rv);
  assert_uint8(NGHTTP2_FRAME_HEADERS, ==, fr.meta.hd.type);
  assert_uint8(NGHTTP2_HEADERS_FLAG_END_HEADERS, ==, fr.headers.hd.flags);
  assert_int64(1, ==, fr.headers.hd.stream_id);
  assert_size(0, ==, fr.headers.padlen);
  assert_size(0, <, fr.headers.field_blocklen);

  rv = nghttp2_frd_decode_buf(&frd, &fr, &buf);

  assert_int(0, ==, rv);
  assert_uint8(NGHTTP2_FRAME_DATA, ==, fr.meta.hd.type);
  assert_uint8(0x00U, ==, fr.data.hd.flags);
  assert_int64(1, ==, fr.data.hd.stream_id);
  assert_size(0, ==, fr.data.padlen);
  assert_size(4096, ==, fr.data.datalen);

  rv = nghttp2_frd_decode_buf(&frd, &fr, &buf);

  assert_int(0, ==, rv);
  assert_uint8(NGHTTP2_FRAME_HEADERS, ==, fr.meta.hd.type);
  assert_uint8(NGHTTP2_HEADERS_FLAG_END_HEADERS |
                 NGHTTP2_HEADERS_FLAG_END_STREAM,
               ==, fr.headers.hd.flags);
  assert_int64(1, ==, fr.headers.hd.stream_id);
  assert_size(0, ==, fr.headers.padlen);
  assert_size(0, <, fr.headers.field_blocklen);
  assert_size(0, ==, nghttp2_buf_len(&buf));

  nghttp2_conn_del(conn);
}

void test_nghttp2_conn_read_preface(void) {
  static const nghttp2_frame_settings settings = {
    .hd =
      {
        .type = NGHTTP2_FRAME_SETTINGS,
      },
  };
  static const nghttp2_frame_window_update wu = {
    .hd =
      {
        .len = 4,
        .type = NGHTTP2_FRAME_WINDOW_UPDATE,
      },
    .window_size_inc = 1000,
  };
  nghttp2_conn *conn;
  nghttp2_tstamp ts = 0;
  uint8_t rawbuf[16384];
  nghttp2_buf buf;
  size_t i;
  int rv;

  nghttp2_buf_wrap_init(&buf, rawbuf, sizeof(rawbuf));

  /* server: read client preface */
  setup_default_server(&conn);

  rv =
    nghttp2_conn_read(conn, (const uint8_t *)NGHTTP2_CLIENT_HTTP2_PREFACE,
                      nghttp2_strlen_lit(NGHTTP2_CLIENT_HTTP2_PREFACE), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH,
              ==, conn->rx.frrd.state);

  nghttp2_buf_reset(&buf);
  buf.last +=
    nghttp2_frame_encode_settings(buf.last, nghttp2_buf_left(&buf), &settings);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH,
              ==, conn->rx.frrd.state);

  nghttp2_conn_del(conn);

  /* server: read client preface one byte at a time */
  setup_default_server(&conn);

  for (i = 0; i < nghttp2_strlen_lit(NGHTTP2_CLIENT_HTTP2_PREFACE); ++i) {
    rv = nghttp2_conn_read(
      conn, (const uint8_t *)NGHTTP2_CLIENT_HTTP2_PREFACE + i, 1, ++ts);

    assert_int(0, ==, rv);
  }

  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH,
              ==, conn->rx.frrd.state);

  nghttp2_buf_reset(&buf);
  buf.last +=
    nghttp2_frame_encode_settings(buf.last, nghttp2_buf_left(&buf), &settings);

  for (i = 0; i < nghttp2_buf_len(&buf); ++i) {
    rv = nghttp2_conn_read(conn, buf.pos + i, 1, ++ts);

    assert_int(0, ==, rv);
  }

  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH,
              ==, conn->rx.frrd.state);

  nghttp2_conn_del(conn);

  /* server: receive bad HTTP/2 preface */
  setup_default_server(&conn);

  for (i = 0; i < nghttp2_strlen_lit(NGHTTP2_CLIENT_HTTP2_PREFACE) - 1; ++i) {
    rv = nghttp2_conn_read(
      conn, (const uint8_t *)NGHTTP2_CLIENT_HTTP2_PREFACE + i, 1, ++ts);

    assert_int(0, ==, rv);
  }

  rv = nghttp2_conn_read(conn, (const uint8_t *)"\0", 1, ++ts);

  assert_int(NGHTTP2_ERR_PROTO, ==, rv);

  nghttp2_conn_del(conn);

  /* server: receive a frame other than SETTINGS as the first frame */
  setup_default_server(&conn);

  rv =
    nghttp2_conn_read(conn, (const uint8_t *)NGHTTP2_CLIENT_HTTP2_PREFACE,
                      nghttp2_strlen_lit(NGHTTP2_CLIENT_HTTP2_PREFACE), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH,
              ==, conn->rx.frrd.state);

  nghttp2_buf_reset(&buf);
  buf.last +=
    nghttp2_frame_encode_window_update(buf.last, nghttp2_buf_left(&buf), &wu);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(NGHTTP2_ERR_PROTO, ==, rv);

  nghttp2_conn_del(conn);

  /* client: receive server preface */
  setup_default_client(&conn);

  nghttp2_buf_reset(&buf);
  buf.last +=
    nghttp2_frame_encode_settings(buf.last, nghttp2_buf_left(&buf), &settings);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH,
              ==, conn->rx.frrd.state);

  nghttp2_conn_del(conn);

  /* client: receive server preface one byte at a time */
  setup_default_client(&conn);

  nghttp2_buf_reset(&buf);
  buf.last +=
    nghttp2_frame_encode_settings(buf.last, nghttp2_buf_left(&buf), &settings);

  for (i = 0; i < nghttp2_buf_len(&buf); ++i) {
    rv = nghttp2_conn_read(conn, buf.pos + i, 1, ++ts);

    assert_int(0, ==, rv);
  }

  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH,
              ==, conn->rx.frrd.state);

  nghttp2_conn_del(conn);

  /* client: receive client preface */
  setup_default_client(&conn);

  /* This would lead to very large frame length */
  rv =
    nghttp2_conn_read(conn, (const uint8_t *)NGHTTP2_CLIENT_HTTP2_PREFACE,
                      nghttp2_strlen_lit(NGHTTP2_CLIENT_HTTP2_PREFACE), ++ts);

  assert_int(NGHTTP2_ERR_PROTO, ==, rv);

  nghttp2_conn_del(conn);

  /* client: receive a frame other than SETTINGS as the first frame */
  setup_default_client(&conn);

  nghttp2_buf_reset(&buf);
  buf.last +=
    nghttp2_frame_encode_window_update(buf.last, nghttp2_buf_left(&buf), &wu);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(NGHTTP2_ERR_PROTO, ==, rv);

  nghttp2_conn_del(conn);
}

void test_nghttp2_conn_recv_frame_hd(void) {
  nghttp2_conn *conn;
  nghttp2_tstamp ts = 0;
  int rv;

  /* Frame length is too large */
  setup_default_server(&conn);

  read_client_preface(conn, NULL, 0, ts);

  rv = nghttp2_conn_read(conn, (const uint8_t *)"\x00\x40\x01", 3, ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_CLOSING, ==,
              conn->rx.frrd.state);
  assert_uint32(NGHTTP2_FRAME_SIZE_ERROR, ==, conn->tx.goaway.error_code);

  nghttp2_conn_del(conn);

  /* The largest frame length */
  setup_default_server(&conn);

  read_client_preface(conn, NULL, 0, ts);

  rv = nghttp2_conn_read(conn, (const uint8_t *)"\xFF\xFF\xFF", 3, ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_CLOSING, ==,
              conn->rx.frrd.state);
  assert_uint32(NGHTTP2_FRAME_SIZE_ERROR, ==, conn->tx.goaway.error_code);

  nghttp2_conn_del(conn);
}

void test_nghttp2_conn_recv_headers(void) {
  const nghttp2_mem *mem = nghttp2_mem_default();
  nghttp2_conn *conn;
  uint8_t rawbuf[16384];
  nghttp2_buf buf, hbuf;
  nghttp2_tstamp ts = 0;
  nghttp2_frame fr;
  nghttp2_hpack_encoder enc;
  nghttp2_stream *stream;
  nghttp2_callbacks callbacks;
  userdata ud;
  conn_options opts;
  size_t i;
  int rv;

  nghttp2_buf_wrap_init(&buf, rawbuf, sizeof(rawbuf));
  nghttp2_buf_init(&hbuf);

  /* Receive HEADERS with END_HEADERS, END_STREAM, PADDED, and
     PRIORITY flags set */
  setup_default_server(&conn);
  read_client_preface(conn, NULL, 0, ts);
  nghttp2_hpack_encoder_init(&enc, NGHTTP2_HPACK_DEFAULT_MAX_BUFFER_SIZE, mem);

  nghttp2_buf_reset(&hbuf);
  rv =
    nghttp2_hpack_encoder_write(&enc, &hbuf, reqnva, nghttp2_arraylen(reqnva));

  assert_int(0, ==, rv);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags = NGHTTP2_HEADERS_FLAG_END_HEADERS |
                 NGHTTP2_HEADERS_FLAG_END_STREAM | NGHTTP2_HEADERS_FLAG_PADDED |
                 NGHTTP2_HEADERS_FLAG_PRIORITY,
        .stream_id = 0x01,
      },
    .padlen = 11,
    .field_block = hbuf.pos,
    .field_blocklen = nghttp2_buf_len(&hbuf),
  };

  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);

  nghttp2_buf_reset(&buf);
  buf.last +=
    nghttp2_frame_encode_headers(buf.last, nghttp2_buf_left(&buf), &fr.headers);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH,
              ==, conn->rx.frrd.state);

  stream = nghttp2_conn_find_stream(conn, 0x01);

  assert_not_null(stream);
  assert_true(stream->flags & NGHTTP2_STREAM_FLAG_SHUT_RD);

  nghttp2_hpack_encoder_free(&enc);
  nghttp2_conn_del(conn);

  /* Read 1 byte at a time */
  setup_default_server(&conn);
  read_client_preface(conn, NULL, 0, ts);

  for (i = 0; i < nghttp2_buf_len(&buf); ++i) {
    rv = nghttp2_conn_read(conn, buf.pos + i, 1, ++ts);

    assert_int(0, ==, rv);
  }

  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH,
              ==, conn->rx.frrd.state);

  stream = nghttp2_conn_find_stream(conn, 0x01);

  assert_not_null(stream);
  assert_true(stream->flags & NGHTTP2_STREAM_FLAG_SHUT_RD);

  nghttp2_conn_del(conn);

  /* Receive HEADERS with END_HEADERS, END_STREAM, and PADDED flags
     set */
  setup_default_server(&conn);
  read_client_preface(conn, NULL, 0, ts);
  nghttp2_hpack_encoder_init(&enc, NGHTTP2_HPACK_DEFAULT_MAX_BUFFER_SIZE, mem);

  nghttp2_buf_reset(&hbuf);
  rv =
    nghttp2_hpack_encoder_write(&enc, &hbuf, reqnva, nghttp2_arraylen(reqnva));

  assert_int(0, ==, rv);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags = NGHTTP2_HEADERS_FLAG_END_HEADERS |
                 NGHTTP2_HEADERS_FLAG_END_STREAM | NGHTTP2_HEADERS_FLAG_PADDED,
        .stream_id = 0x01,
      },
    .padlen = 11,
    .field_block = hbuf.pos,
    .field_blocklen = nghttp2_buf_len(&hbuf),
  };

  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);

  nghttp2_buf_reset(&buf);
  buf.last +=
    nghttp2_frame_encode_headers(buf.last, nghttp2_buf_left(&buf), &fr.headers);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH,
              ==, conn->rx.frrd.state);

  nghttp2_hpack_encoder_free(&enc);
  nghttp2_conn_del(conn);

  /* Receive HEADERS with END_HEADERS, END_STREAM, and PRIORITY flags
     set */
  setup_default_server(&conn);
  read_client_preface(conn, NULL, 0, ts);
  nghttp2_hpack_encoder_init(&enc, NGHTTP2_HPACK_DEFAULT_MAX_BUFFER_SIZE, mem);

  nghttp2_buf_reset(&hbuf);
  rv =
    nghttp2_hpack_encoder_write(&enc, &hbuf, reqnva, nghttp2_arraylen(reqnva));

  assert_int(0, ==, rv);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags = NGHTTP2_HEADERS_FLAG_END_HEADERS |
                 NGHTTP2_HEADERS_FLAG_END_STREAM |
                 NGHTTP2_HEADERS_FLAG_PRIORITY,
        .stream_id = 0x01,
      },
    .field_block = hbuf.pos,
    .field_blocklen = nghttp2_buf_len(&hbuf),
  };

  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);

  nghttp2_buf_reset(&buf);
  buf.last +=
    nghttp2_frame_encode_headers(buf.last, nghttp2_buf_left(&buf), &fr.headers);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH,
              ==, conn->rx.frrd.state);

  nghttp2_hpack_encoder_free(&enc);
  nghttp2_conn_del(conn);

  /* Receive HEADERS with END_HEADERS and END_STREAM flags set */
  setup_default_server(&conn);
  read_client_preface(conn, NULL, 0, ts);
  nghttp2_hpack_encoder_init(&enc, NGHTTP2_HPACK_DEFAULT_MAX_BUFFER_SIZE, mem);

  nghttp2_buf_reset(&hbuf);
  rv =
    nghttp2_hpack_encoder_write(&enc, &hbuf, reqnva, nghttp2_arraylen(reqnva));

  assert_int(0, ==, rv);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags =
          NGHTTP2_HEADERS_FLAG_END_HEADERS | NGHTTP2_HEADERS_FLAG_END_STREAM,
        .stream_id = 0x01,
      },
    .field_block = hbuf.pos,
    .field_blocklen = nghttp2_buf_len(&hbuf),
  };

  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);

  nghttp2_buf_reset(&buf);
  buf.last +=
    nghttp2_frame_encode_headers(buf.last, nghttp2_buf_left(&buf), &fr.headers);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH,
              ==, conn->rx.frrd.state);

  nghttp2_hpack_encoder_free(&enc);
  nghttp2_conn_del(conn);

  /* Receive HEADERS with END_HEADERS flags set */
  setup_default_server(&conn);
  read_client_preface(conn, NULL, 0, ts);
  nghttp2_hpack_encoder_init(&enc, NGHTTP2_HPACK_DEFAULT_MAX_BUFFER_SIZE, mem);

  nghttp2_buf_reset(&hbuf);
  rv =
    nghttp2_hpack_encoder_write(&enc, &hbuf, reqnva, nghttp2_arraylen(reqnva));

  assert_int(0, ==, rv);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags = NGHTTP2_HEADERS_FLAG_END_HEADERS,
        .stream_id = 0x01,
      },
    .field_block = hbuf.pos,
    .field_blocklen = nghttp2_buf_len(&hbuf),
  };

  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);

  nghttp2_buf_reset(&buf);
  buf.last +=
    nghttp2_frame_encode_headers(buf.last, nghttp2_buf_left(&buf), &fr.headers);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH,
              ==, conn->rx.frrd.state);

  stream = nghttp2_conn_find_stream(conn, 0x01);

  assert_not_null(stream);
  assert_false(stream->flags & NGHTTP2_STREAM_FLAG_SHUT_RD);

  nghttp2_hpack_encoder_free(&enc);
  nghttp2_conn_del(conn);

  /* Receive HEADERS with no flags set */
  setup_default_server(&conn);
  read_client_preface(conn, NULL, 0, ts);
  nghttp2_hpack_encoder_init(&enc, NGHTTP2_HPACK_DEFAULT_MAX_BUFFER_SIZE, mem);

  nghttp2_buf_reset(&hbuf);
  rv =
    nghttp2_hpack_encoder_write(&enc, &hbuf, reqnva, nghttp2_arraylen(reqnva));

  assert_int(0, ==, rv);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .stream_id = 0x01,
      },
    .field_block = hbuf.pos,
    .field_blocklen = nghttp2_buf_len(&hbuf),
  };

  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);

  nghttp2_buf_reset(&buf);
  buf.last +=
    nghttp2_frame_encode_headers(buf.last, nghttp2_buf_left(&buf), &fr.headers);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state,
              NGHTTP2_FRAME_READ_STATE_CONTINUATION_FRAME_LENGTH, ==,
              conn->rx.frrd.state);

  stream = nghttp2_conn_find_stream(conn, 0x01);

  assert_not_null(stream);
  assert_false(stream->flags & NGHTTP2_STREAM_FLAG_SHUT_RD);

  nghttp2_hpack_encoder_free(&enc);
  nghttp2_conn_del(conn);

  /* Receive HEADERS with END_HEADERS, END_STREAM, and PADDED flags
     set, and the length of padding is 0 */
  setup_default_server(&conn);
  read_client_preface(conn, NULL, 0, ts);
  nghttp2_hpack_encoder_init(&enc, NGHTTP2_HPACK_DEFAULT_MAX_BUFFER_SIZE, mem);

  nghttp2_buf_reset(&hbuf);
  rv =
    nghttp2_hpack_encoder_write(&enc, &hbuf, reqnva, nghttp2_arraylen(reqnva));

  assert_int(0, ==, rv);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags = NGHTTP2_HEADERS_FLAG_END_HEADERS |
                 NGHTTP2_HEADERS_FLAG_END_STREAM | NGHTTP2_HEADERS_FLAG_PADDED,
        .stream_id = 0x01,
      },
    .field_block = hbuf.pos,
    .field_blocklen = nghttp2_buf_len(&hbuf),
  };

  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);

  nghttp2_buf_reset(&buf);
  buf.last +=
    nghttp2_frame_encode_headers(buf.last, nghttp2_buf_left(&buf), &fr.headers);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH,
              ==, conn->rx.frrd.state);

  nghttp2_hpack_encoder_free(&enc);
  nghttp2_conn_del(conn);

  /* Receive HEADERS with PADDED flags set */
  setup_default_server(&conn);
  read_client_preface(conn, NULL, 0, ts);
  nghttp2_hpack_encoder_init(&enc, NGHTTP2_HPACK_DEFAULT_MAX_BUFFER_SIZE, mem);

  nghttp2_buf_reset(&hbuf);
  rv =
    nghttp2_hpack_encoder_write(&enc, &hbuf, reqnva, nghttp2_arraylen(reqnva));

  assert_int(0, ==, rv);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags = NGHTTP2_HEADERS_FLAG_PADDED,
        .stream_id = 0x01,
      },
    .padlen = 1,
    .field_block = hbuf.pos,
    .field_blocklen = nghttp2_buf_len(&hbuf),
  };

  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);

  nghttp2_buf_reset(&buf);
  buf.last +=
    nghttp2_frame_encode_headers(buf.last, nghttp2_buf_left(&buf), &fr.headers);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state,
              NGHTTP2_FRAME_READ_STATE_CONTINUATION_FRAME_LENGTH, ==,
              conn->rx.frrd.state);

  stream = nghttp2_conn_find_stream(conn, 0x01);

  assert_not_null(stream);
  assert_false(stream->flags & NGHTTP2_STREAM_FLAG_SHUT_RD);

  nghttp2_hpack_encoder_free(&enc);
  nghttp2_conn_del(conn);

  /* Receive HEADERS with stream ID == 0 */
  setup_default_server(&conn);
  read_client_preface(conn, NULL, 0, ts);
  nghttp2_hpack_encoder_init(&enc, NGHTTP2_HPACK_DEFAULT_MAX_BUFFER_SIZE, mem);

  nghttp2_buf_reset(&hbuf);
  rv =
    nghttp2_hpack_encoder_write(&enc, &hbuf, reqnva, nghttp2_arraylen(reqnva));

  assert_int(0, ==, rv);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags =
          NGHTTP2_HEADERS_FLAG_END_HEADERS | NGHTTP2_HEADERS_FLAG_END_STREAM,
      },
    .field_block = hbuf.pos,
    .field_blocklen = nghttp2_buf_len(&hbuf),
  };

  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);

  nghttp2_buf_reset(&buf);
  buf.last +=
    nghttp2_frame_encode_headers(buf.last, nghttp2_buf_left(&buf), &fr.headers);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_CLOSING, ==,
              conn->rx.frrd.state);
  assert_uint32(NGHTTP2_PROTOCOL_ERROR, ==, conn->tx.goaway.error_code);

  nghttp2_hpack_encoder_free(&enc);
  nghttp2_conn_del(conn);

  /* Receive HEADERS with stream ID == 2 */
  setup_default_server(&conn);
  read_client_preface(conn, NULL, 0, ts);
  nghttp2_hpack_encoder_init(&enc, NGHTTP2_HPACK_DEFAULT_MAX_BUFFER_SIZE, mem);

  nghttp2_buf_reset(&hbuf);
  rv =
    nghttp2_hpack_encoder_write(&enc, &hbuf, reqnva, nghttp2_arraylen(reqnva));

  assert_int(0, ==, rv);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags =
          NGHTTP2_HEADERS_FLAG_END_HEADERS | NGHTTP2_HEADERS_FLAG_END_STREAM,
        .stream_id = 0x02,
      },
    .field_block = hbuf.pos,
    .field_blocklen = nghttp2_buf_len(&hbuf),
  };

  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);

  nghttp2_buf_reset(&buf);
  buf.last +=
    nghttp2_frame_encode_headers(buf.last, nghttp2_buf_left(&buf), &fr.headers);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_CLOSING, ==,
              conn->rx.frrd.state);
  assert_uint32(NGHTTP2_PROTOCOL_ERROR, ==, conn->tx.goaway.error_code);

  nghttp2_hpack_encoder_free(&enc);
  nghttp2_conn_del(conn);

  /* Receive HEADERS with PADDED flag set and the length is too
     short */
  setup_default_server(&conn);
  read_client_preface(conn, NULL, 0, ts);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags = NGHTTP2_HEADERS_FLAG_PADDED,
        .stream_id = 0x01,
      },
  };

  nghttp2_buf_reset(&buf);
  buf.last +=
    nghttp2_frame_encode_headers(buf.last, nghttp2_buf_left(&buf), &fr.headers);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_CLOSING, ==,
              conn->rx.frrd.state);
  assert_uint32(NGHTTP2_PROTOCOL_ERROR, ==, conn->tx.goaway.error_code);

  nghttp2_conn_del(conn);

  /* Receive HEADERS with PADDED flag set and the length is too
     short */
  setup_default_server(&conn);
  read_client_preface(conn, NULL, 0, ts);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags = NGHTTP2_HEADERS_FLAG_PADDED,
        .stream_id = 0x01,
      },
    .padlen = 10,
  };

  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers) - 1;

  nghttp2_buf_reset(&buf);
  buf.last +=
    nghttp2_frame_encode_headers(buf.last, nghttp2_buf_left(&buf), &fr.headers);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_CLOSING, ==,
              conn->rx.frrd.state);
  assert_uint32(NGHTTP2_PROTOCOL_ERROR, ==, conn->tx.goaway.error_code);

  nghttp2_conn_del(conn);

  /* Receive HEADERS with PRIORITY flag set and the length is too
     short */
  setup_default_server(&conn);
  read_client_preface(conn, NULL, 0, ts);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .len = 4,
        .type = NGHTTP2_FRAME_HEADERS,
        .flags = NGHTTP2_HEADERS_FLAG_PRIORITY,
        .stream_id = 0x01,
      },
  };

  nghttp2_buf_reset(&buf);
  buf.last +=
    nghttp2_frame_encode_headers(buf.last, nghttp2_buf_left(&buf), &fr.headers);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_CLOSING, ==,
              conn->rx.frrd.state);
  assert_uint32(NGHTTP2_PROTOCOL_ERROR, ==, conn->tx.goaway.error_code);

  nghttp2_conn_del(conn);

  /* Receive HEADERS with PADDED and PRIORITY flags set and the length
     is too short */
  setup_default_server(&conn);
  read_client_preface(conn, NULL, 0, ts);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .len = 5,
        .type = NGHTTP2_FRAME_HEADERS,
        .flags = NGHTTP2_HEADERS_FLAG_PADDED | NGHTTP2_HEADERS_FLAG_PRIORITY,
        .stream_id = 0x01,
      },
  };

  nghttp2_buf_reset(&buf);
  buf.last +=
    nghttp2_frame_encode_headers(buf.last, nghttp2_buf_left(&buf), &fr.headers);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_CLOSING, ==,
              conn->rx.frrd.state);
  assert_uint32(NGHTTP2_PROTOCOL_ERROR, ==, conn->tx.goaway.error_code);

  nghttp2_conn_del(conn);

  /* Receive HEADERS with PADDED flag set and the length is too
     short */
  setup_default_server(&conn);
  read_client_preface(conn, NULL, 0, ts);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags = NGHTTP2_HEADERS_FLAG_PADDED | NGHTTP2_HEADERS_FLAG_PRIORITY,
        .stream_id = 0x01,
      },
    .padlen = 10,
  };

  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers) - 1;

  nghttp2_buf_reset(&buf);
  buf.last +=
    nghttp2_frame_encode_headers(buf.last, nghttp2_buf_left(&buf), &fr.headers);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_CLOSING, ==,
              conn->rx.frrd.state);
  assert_uint32(NGHTTP2_PROTOCOL_ERROR, ==, conn->tx.goaway.error_code);

  nghttp2_conn_del(conn);

  /* Receive HEADERS with END_HEADERS flag set and it is 0 length */
  setup_default_server(&conn);
  read_client_preface(conn, NULL, 0, ts);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags = NGHTTP2_HEADERS_FLAG_END_HEADERS,
        .stream_id = 0x01,
      },
  };

  nghttp2_buf_reset(&buf);
  buf.last +=
    nghttp2_frame_encode_headers(buf.last, nghttp2_buf_left(&buf), &fr.headers);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_CLOSING, ==,
              conn->rx.frrd.state);
  assert_uint32(NGHTTP2_PROTOCOL_ERROR, ==, conn->tx.goaway.error_code);

  nghttp2_conn_del(conn);

  /* Receive HEADERS without END_HEADERS flag set and it is 0 length */
  setup_default_server(&conn);
  read_client_preface(conn, NULL, 0, ts);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .stream_id = 0x01,
      },
  };

  nghttp2_buf_reset(&buf);
  buf.last +=
    nghttp2_frame_encode_headers(buf.last, nghttp2_buf_left(&buf), &fr.headers);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state,
              NGHTTP2_FRAME_READ_STATE_CONTINUATION_FRAME_LENGTH, ==,
              conn->rx.frrd.state);

  nghttp2_conn_del(conn);

  /* Receive HEADERS with END_STREAMS flag set and it is 0 length */
  setup_default_server(&conn);
  read_client_preface(conn, NULL, 0, ts);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags = NGHTTP2_HEADERS_FLAG_END_STREAM,
        .stream_id = 0x01,
      },
  };

  nghttp2_buf_reset(&buf);
  buf.last +=
    nghttp2_frame_encode_headers(buf.last, nghttp2_buf_left(&buf), &fr.headers);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state,
              NGHTTP2_FRAME_READ_STATE_CONTINUATION_FRAME_LENGTH, ==,
              conn->rx.frrd.state);

  nghttp2_conn_del(conn);

  /* Receive HEADERS with just 1 byte padding */
  setup_default_server(&conn);
  read_client_preface(conn, NULL, 0, ts);

  assert_int(0, ==, rv);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags = NGHTTP2_HEADERS_FLAG_PADDED,
        .stream_id = 0x01,
      },
  };

  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);

  nghttp2_buf_reset(&buf);
  buf.last +=
    nghttp2_frame_encode_headers(buf.last, nghttp2_buf_left(&buf), &fr.headers);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state,
              NGHTTP2_FRAME_READ_STATE_CONTINUATION_FRAME_LENGTH, ==,
              conn->rx.frrd.state);

  nghttp2_conn_del(conn);

  /* Receive HEADERS with just 2 byte padding and no field block */
  setup_default_server(&conn);
  read_client_preface(conn, NULL, 0, ts);

  assert_int(0, ==, rv);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags = NGHTTP2_HEADERS_FLAG_END_HEADERS | NGHTTP2_HEADERS_FLAG_PADDED,
        .stream_id = 0x01,
      },
    .padlen = 1,
  };

  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);

  nghttp2_buf_reset(&buf);
  buf.last +=
    nghttp2_frame_encode_headers(buf.last, nghttp2_buf_left(&buf), &fr.headers);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_CLOSING, ==,
              conn->rx.frrd.state);

  nghttp2_conn_del(conn);

  /* Receive HEADERS with just priority */
  setup_default_server(&conn);
  read_client_preface(conn, NULL, 0, ts);

  assert_int(0, ==, rv);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags = NGHTTP2_HEADERS_FLAG_PRIORITY,
        .stream_id = 0x01,
      },
  };

  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);

  nghttp2_buf_reset(&buf);
  buf.last +=
    nghttp2_frame_encode_headers(buf.last, nghttp2_buf_left(&buf), &fr.headers);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state,
              NGHTTP2_FRAME_READ_STATE_CONTINUATION_FRAME_LENGTH, ==,
              conn->rx.frrd.state);

  nghttp2_conn_del(conn);

  /* Receive trailer HEADERS with END_HEADERS and 0 length field
     block */
  setup_default_server(&conn);
  read_client_preface(conn, NULL, 0, ts);
  nghttp2_hpack_encoder_init(&enc, NGHTTP2_HPACK_DEFAULT_MAX_BUFFER_SIZE, mem);

  nghttp2_buf_reset(&hbuf);
  rv =
    nghttp2_hpack_encoder_write(&enc, &hbuf, reqnva, nghttp2_arraylen(reqnva));

  assert_int(0, ==, rv);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags = NGHTTP2_HEADERS_FLAG_END_HEADERS,
        .stream_id = 0x01,
      },
    .field_block = hbuf.pos,
    .field_blocklen = nghttp2_buf_len(&hbuf),
  };

  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);

  nghttp2_buf_reset(&buf);
  buf.last +=
    nghttp2_frame_encode_headers(buf.last, nghttp2_buf_left(&buf), &fr.headers);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH,
              ==, conn->rx.frrd.state);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags =
          NGHTTP2_HEADERS_FLAG_END_HEADERS | NGHTTP2_HEADERS_FLAG_END_STREAM,
        .stream_id = 0x01,
      },
  };

  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);

  nghttp2_buf_reset(&buf);
  buf.last +=
    nghttp2_frame_encode_headers(buf.last, nghttp2_buf_left(&buf), &fr.headers);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH,
              ==, conn->rx.frrd.state);

  nghttp2_hpack_encoder_free(&enc);
  nghttp2_conn_del(conn);

  /* Receive trailer HEADERS without END_STREAM */
  setup_default_server(&conn);
  read_client_preface(conn, NULL, 0, ts);
  nghttp2_hpack_encoder_init(&enc, NGHTTP2_HPACK_DEFAULT_MAX_BUFFER_SIZE, mem);

  nghttp2_buf_reset(&hbuf);
  rv =
    nghttp2_hpack_encoder_write(&enc, &hbuf, reqnva, nghttp2_arraylen(reqnva));

  assert_int(0, ==, rv);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags = NGHTTP2_HEADERS_FLAG_END_HEADERS,
        .stream_id = 0x01,
      },
    .field_block = hbuf.pos,
    .field_blocklen = nghttp2_buf_len(&hbuf),
  };

  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);

  nghttp2_buf_reset(&buf);
  buf.last +=
    nghttp2_frame_encode_headers(buf.last, nghttp2_buf_left(&buf), &fr.headers);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH,
              ==, conn->rx.frrd.state);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags = NGHTTP2_HEADERS_FLAG_END_HEADERS,
        .stream_id = 0x01,
      },
  };

  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);

  nghttp2_buf_reset(&buf);
  buf.last +=
    nghttp2_frame_encode_headers(buf.last, nghttp2_buf_left(&buf), &fr.headers);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_CLOSING, ==,
              conn->rx.frrd.state);
  assert_uint32(NGHTTP2_PROTOCOL_ERROR, ==, conn->tx.goaway.error_code);

  nghttp2_hpack_encoder_free(&enc);
  nghttp2_conn_del(conn);

  /* Receive trailer HEADERS with END_HEADERS and PADDED, and 1 padded byte
     and 0 length field block */
  setup_default_server(&conn);
  read_client_preface(conn, NULL, 0, ts);
  nghttp2_hpack_encoder_init(&enc, NGHTTP2_HPACK_DEFAULT_MAX_BUFFER_SIZE, mem);

  nghttp2_buf_reset(&hbuf);
  rv =
    nghttp2_hpack_encoder_write(&enc, &hbuf, reqnva, nghttp2_arraylen(reqnva));

  assert_int(0, ==, rv);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags = NGHTTP2_HEADERS_FLAG_END_HEADERS,
        .stream_id = 0x01,
      },
    .field_block = hbuf.pos,
    .field_blocklen = nghttp2_buf_len(&hbuf),
  };

  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);

  nghttp2_buf_reset(&buf);
  buf.last +=
    nghttp2_frame_encode_headers(buf.last, nghttp2_buf_left(&buf), &fr.headers);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH,
              ==, conn->rx.frrd.state);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags = NGHTTP2_HEADERS_FLAG_END_HEADERS |
                 NGHTTP2_HEADERS_FLAG_END_STREAM | NGHTTP2_HEADERS_FLAG_PADDED,
        .stream_id = 0x01,
      },
  };

  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);

  nghttp2_buf_reset(&buf);
  buf.last +=
    nghttp2_frame_encode_headers(buf.last, nghttp2_buf_left(&buf), &fr.headers);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH,
              ==, conn->rx.frrd.state);

  nghttp2_hpack_encoder_free(&enc);
  nghttp2_conn_del(conn);

  /* Receive trailer HEADERS with END_HEADERS and PRIORITY, and 0
     length field block */
  setup_default_server(&conn);
  read_client_preface(conn, NULL, 0, ts);
  nghttp2_hpack_encoder_init(&enc, NGHTTP2_HPACK_DEFAULT_MAX_BUFFER_SIZE, mem);

  nghttp2_buf_reset(&hbuf);
  rv =
    nghttp2_hpack_encoder_write(&enc, &hbuf, reqnva, nghttp2_arraylen(reqnva));

  assert_int(0, ==, rv);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags = NGHTTP2_HEADERS_FLAG_END_HEADERS,
        .stream_id = 0x01,
      },
    .field_block = hbuf.pos,
    .field_blocklen = nghttp2_buf_len(&hbuf),
  };

  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);

  nghttp2_buf_reset(&buf);
  buf.last +=
    nghttp2_frame_encode_headers(buf.last, nghttp2_buf_left(&buf), &fr.headers);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH,
              ==, conn->rx.frrd.state);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags = NGHTTP2_HEADERS_FLAG_END_HEADERS |
                 NGHTTP2_HEADERS_FLAG_END_STREAM |
                 NGHTTP2_HEADERS_FLAG_PRIORITY,
        .stream_id = 0x01,
      },
  };

  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);

  nghttp2_buf_reset(&buf);
  buf.last +=
    nghttp2_frame_encode_headers(buf.last, nghttp2_buf_left(&buf), &fr.headers);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH,
              ==, conn->rx.frrd.state);

  nghttp2_hpack_encoder_free(&enc);
  nghttp2_conn_del(conn);

  /* Receive HEADERS for the closed stream */
  server_default_callbacks(&callbacks);

  callbacks.begin_headers = begin_headers;
  callbacks.recv_header = recv_header;
  callbacks.end_headers = end_headers;
  callbacks.end_stream = end_stream;

  opts = (conn_options){
    .callbacks = &callbacks,
    .user_data = &ud,
  };

  setup_default_server_with_options(&conn, opts);
  read_client_preface(conn, NULL, 0, ts);
  nghttp2_hpack_encoder_init(&enc, NGHTTP2_HPACK_DEFAULT_MAX_BUFFER_SIZE, mem);

  nghttp2_buf_reset(&hbuf);
  rv =
    nghttp2_hpack_encoder_write(&enc, &hbuf, reqnva, nghttp2_arraylen(reqnva));

  assert_int(0, ==, rv);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags =
          NGHTTP2_HEADERS_FLAG_END_HEADERS | NGHTTP2_HEADERS_FLAG_END_STREAM,
        .stream_id = 0x03,
      },
    .field_block = hbuf.pos,
    .field_blocklen = nghttp2_buf_len(&hbuf),
  };

  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);

  nghttp2_buf_reset(&buf);
  buf.last +=
    nghttp2_frame_encode_headers(buf.last, nghttp2_buf_left(&buf), &fr.headers);

  ud = (userdata){0};
  ud.recv_header.expect_nva = reqnva;
  ud.recv_header.expect_nvlen = nghttp2_arraylen(reqnva);
  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH,
              ==, conn->rx.frrd.state);
  assert_size(1, ==, ud.begin_headers.ncalled);
  assert_size(5, ==, ud.recv_header.ncalled);
  assert_size(1, ==, ud.end_headers.ncalled);
  assert_size(1, ==, ud.end_stream.ncalled);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags =
          NGHTTP2_HEADERS_FLAG_END_HEADERS | NGHTTP2_HEADERS_FLAG_END_STREAM,
        .stream_id = 0x01,
      },
  };

  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);

  nghttp2_buf_reset(&buf);
  buf.last +=
    nghttp2_frame_encode_headers(buf.last, nghttp2_buf_left(&buf), &fr.headers);

  ud = (userdata){0};
  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH,
              ==, conn->rx.frrd.state);
  assert_size(0, ==, ud.begin_headers.ncalled);
  assert_size(0, ==, ud.recv_header.ncalled);
  assert_size(0, ==, ud.end_headers.ncalled);
  assert_size(0, ==, ud.end_stream.ncalled);

  stream = nghttp2_conn_find_stream(conn, 0x01);

  assert_null(stream);

  nghttp2_hpack_encoder_free(&enc);
  nghttp2_conn_del(conn);

  nghttp2_buf_free(&hbuf, mem);
}

void test_nghttp2_conn_recv_continuation(void) {
  const nghttp2_mem *mem = nghttp2_mem_default();
  nghttp2_conn *conn;
  uint8_t rawbuf[16384];
  nghttp2_buf buf, hbuf;
  nghttp2_tstamp ts = 0;
  nghttp2_frame fr;
  nghttp2_hpack_encoder enc;
  nghttp2_stream *stream;
  nghttp2_callbacks callbacks;
  userdata ud;
  conn_options opts;
  size_t i;
  int rv;

  nghttp2_buf_wrap_init(&buf, rawbuf, sizeof(rawbuf));
  nghttp2_buf_init(&hbuf);

  /* Receive HEADERS with END_STREAM and CONTINUATION. */
  setup_default_server(&conn);
  read_client_preface(conn, NULL, 0, ts);
  nghttp2_hpack_encoder_init(&enc, NGHTTP2_HPACK_DEFAULT_MAX_BUFFER_SIZE, mem);

  nghttp2_buf_reset(&hbuf);
  rv =
    nghttp2_hpack_encoder_write(&enc, &hbuf, reqnva, nghttp2_arraylen(reqnva));

  assert_int(0, ==, rv);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags = NGHTTP2_HEADERS_FLAG_END_STREAM,
        .stream_id = 0x01,
      },
    .field_block = hbuf.pos,
    .field_blocklen = nghttp2_buf_len(&hbuf) / 2,
  };

  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);

  nghttp2_buf_reset(&buf);
  buf.last +=
    nghttp2_frame_encode_headers(buf.last, nghttp2_buf_left(&buf), &fr.headers);

  hbuf.pos += nghttp2_buf_len(&hbuf) / 2;

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_CONTINUATION,
        .flags = NGHTTP2_HEADERS_FLAG_END_HEADERS,
        .stream_id = 0x01,
      },
    .field_block = hbuf.pos,
    .field_blocklen = nghttp2_buf_len(&hbuf),
  };

  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);

  buf.last +=
    nghttp2_frame_encode_headers(buf.last, nghttp2_buf_left(&buf), &fr.headers);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH,
              ==, conn->rx.frrd.state);

  stream = nghttp2_conn_find_stream(conn, 0x01);

  assert_not_null(stream);
  assert_true(stream->flags & NGHTTP2_STREAM_FLAG_SHUT_RD);

  nghttp2_hpack_encoder_free(&enc);
  nghttp2_conn_del(conn);

  /* 2 CONTINUATION frames */
  server_default_callbacks(&callbacks);

  callbacks.begin_headers = begin_headers;
  callbacks.recv_header = recv_header;
  callbacks.end_headers = end_headers;
  callbacks.end_stream = end_stream;

  opts = (conn_options){
    .callbacks = &callbacks,
    .user_data = &ud,
  };

  setup_default_server_with_options(&conn, opts);
  read_client_preface(conn, NULL, 0, ts);
  nghttp2_hpack_encoder_init(&enc, NGHTTP2_HPACK_DEFAULT_MAX_BUFFER_SIZE, mem);

  nghttp2_buf_reset(&hbuf);
  rv =
    nghttp2_hpack_encoder_write(&enc, &hbuf, reqnva, nghttp2_arraylen(reqnva));

  assert_int(0, ==, rv);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags = NGHTTP2_HEADERS_FLAG_END_STREAM,
        .stream_id = 0x01,
      },
    .field_block = hbuf.pos,
    .field_blocklen = nghttp2_buf_len(&hbuf) / 2,
  };

  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);

  nghttp2_buf_reset(&buf);
  buf.last +=
    nghttp2_frame_encode_headers(buf.last, nghttp2_buf_left(&buf), &fr.headers);

  hbuf.pos += nghttp2_buf_len(&hbuf) / 2;

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_CONTINUATION,
        .stream_id = 0x01,
      },
    .field_block = hbuf.pos,
    .field_blocklen = nghttp2_buf_len(&hbuf) / 2,
  };

  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);

  buf.last +=
    nghttp2_frame_encode_headers(buf.last, nghttp2_buf_left(&buf), &fr.headers);

  hbuf.pos += nghttp2_buf_len(&hbuf) / 2;

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_CONTINUATION,
        .flags = NGHTTP2_HEADERS_FLAG_END_HEADERS,
        .stream_id = 0x01,
      },
    .field_block = hbuf.pos,
    .field_blocklen = nghttp2_buf_len(&hbuf),
  };

  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);

  buf.last +=
    nghttp2_frame_encode_headers(buf.last, nghttp2_buf_left(&buf), &fr.headers);

  ud = (userdata){0};
  ud.recv_header.expect_nva = reqnva;
  ud.recv_header.expect_nvlen = nghttp2_arraylen(reqnva);
  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH,
              ==, conn->rx.frrd.state);
  assert_size(1, ==, ud.begin_headers.ncalled);
  assert_size(5, ==, ud.recv_header.ncalled);
  assert_size(1, ==, ud.end_headers.ncalled);
  assert_size(1, ==, ud.end_stream.ncalled);

  stream = nghttp2_conn_find_stream(conn, 0x01);

  assert_not_null(stream);
  assert_true(stream->flags & NGHTTP2_STREAM_FLAG_SHUT_RD);

  nghttp2_hpack_encoder_free(&enc);
  nghttp2_conn_del(conn);

  /* Read 1 byte at a time */
  server_default_callbacks(&callbacks);

  callbacks.begin_headers = begin_headers;
  callbacks.recv_header = recv_header;
  callbacks.end_headers = end_headers;
  callbacks.end_stream = end_stream;

  opts = (conn_options){
    .callbacks = &callbacks,
    .user_data = &ud,
  };

  setup_default_server_with_options(&conn, opts);
  read_client_preface(conn, NULL, 0, ts);

  ud = (userdata){0};
  ud.recv_header.expect_nva = reqnva;
  ud.recv_header.expect_nvlen = nghttp2_arraylen(reqnva);

  for (i = 0; i < nghttp2_buf_len(&buf); ++i) {
    rv = nghttp2_conn_read(conn, buf.pos + i, 1, ++ts);

    assert_int(0, ==, rv);
  }

  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH,
              ==, conn->rx.frrd.state);
  assert_size(1, ==, ud.begin_headers.ncalled);
  assert_size(5, ==, ud.recv_header.ncalled);
  assert_size(1, ==, ud.end_headers.ncalled);
  assert_size(1, ==, ud.end_stream.ncalled);

  stream = nghttp2_conn_find_stream(conn, 0x01);

  assert_not_null(stream);
  assert_true(stream->flags & NGHTTP2_STREAM_FLAG_SHUT_RD);

  nghttp2_conn_del(conn);

  /* Receive CONTINUATION and its length is too large */
  setup_default_server(&conn);
  read_client_preface(conn, NULL, 0, ts);
  nghttp2_hpack_encoder_init(&enc, NGHTTP2_HPACK_DEFAULT_MAX_BUFFER_SIZE, mem);

  nghttp2_buf_reset(&hbuf);
  rv =
    nghttp2_hpack_encoder_write(&enc, &hbuf, reqnva, nghttp2_arraylen(reqnva));

  assert_int(0, ==, rv);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags = NGHTTP2_HEADERS_FLAG_END_STREAM,
        .stream_id = 0x01,
      },
    .field_block = hbuf.pos,
    .field_blocklen = nghttp2_buf_len(&hbuf),
  };

  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);

  nghttp2_buf_reset(&buf);
  buf.last +=
    nghttp2_frame_encode_headers(buf.last, nghttp2_buf_left(&buf), &fr.headers);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .len = NGHTTP2_DEFAULT_MAX_FRAME_SIZE + 1,
        .type = NGHTTP2_FRAME_CONTINUATION,
        .flags = NGHTTP2_HEADERS_FLAG_END_HEADERS,
        .stream_id = 0x01,
      },
  };

  buf.last = nghttp2_frame_encode_hd(buf.last, &fr.headers.hd);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_CLOSING, ==,
              conn->rx.frrd.state);
  assert_uint32(NGHTTP2_FRAME_SIZE_ERROR, ==, conn->tx.goaway.error_code);

  nghttp2_hpack_encoder_free(&enc);
  nghttp2_conn_del(conn);

  /* Receive HEADERS when CONTINUATION is expected */
  setup_default_server(&conn);
  read_client_preface(conn, NULL, 0, ts);
  nghttp2_hpack_encoder_init(&enc, NGHTTP2_HPACK_DEFAULT_MAX_BUFFER_SIZE, mem);

  nghttp2_buf_reset(&hbuf);
  rv =
    nghttp2_hpack_encoder_write(&enc, &hbuf, reqnva, nghttp2_arraylen(reqnva));

  assert_int(0, ==, rv);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags = NGHTTP2_HEADERS_FLAG_END_STREAM,
        .stream_id = 0x01,
      },
    .field_block = hbuf.pos,
    .field_blocklen = nghttp2_buf_len(&hbuf),
  };

  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);

  nghttp2_buf_reset(&buf);
  buf.last +=
    nghttp2_frame_encode_headers(buf.last, nghttp2_buf_left(&buf), &fr.headers);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .len = 1,
        .type = NGHTTP2_FRAME_HEADERS,
        .flags = NGHTTP2_HEADERS_FLAG_END_HEADERS,
        .stream_id = 0x01,
      },
  };

  buf.last = nghttp2_frame_encode_hd(buf.last, &fr.headers.hd);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_CLOSING, ==,
              conn->rx.frrd.state);
  assert_uint32(NGHTTP2_PROTOCOL_ERROR, ==, conn->tx.goaway.error_code);

  nghttp2_hpack_encoder_free(&enc);
  nghttp2_conn_del(conn);

  /* Receive CONTINUATION with the wrong stream ID */
  setup_default_server(&conn);
  read_client_preface(conn, NULL, 0, ts);
  nghttp2_hpack_encoder_init(&enc, NGHTTP2_HPACK_DEFAULT_MAX_BUFFER_SIZE, mem);

  nghttp2_buf_reset(&hbuf);
  rv =
    nghttp2_hpack_encoder_write(&enc, &hbuf, reqnva, nghttp2_arraylen(reqnva));

  assert_int(0, ==, rv);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags = NGHTTP2_HEADERS_FLAG_END_STREAM,
        .stream_id = 0x03,
      },
    .field_block = hbuf.pos,
    .field_blocklen = nghttp2_buf_len(&hbuf),
  };

  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);

  nghttp2_buf_reset(&buf);
  buf.last +=
    nghttp2_frame_encode_headers(buf.last, nghttp2_buf_left(&buf), &fr.headers);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .len = 1,
        .type = NGHTTP2_FRAME_CONTINUATION,
        .flags = NGHTTP2_HEADERS_FLAG_END_HEADERS,
        .stream_id = 0x01,
      },
  };

  buf.last = nghttp2_frame_encode_hd(buf.last, &fr.headers.hd);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_CLOSING, ==,
              conn->rx.frrd.state);
  assert_uint32(NGHTTP2_PROTOCOL_ERROR, ==, conn->tx.goaway.error_code);

  nghttp2_hpack_encoder_free(&enc);
  nghttp2_conn_del(conn);

  nghttp2_buf_free(&hbuf, mem);
}

void test_nghttp2_conn_recv_data(void) {
  const nghttp2_mem *mem = nghttp2_mem_default();
  nghttp2_conn *conn;
  uint8_t rawbuf[16384];
  nghttp2_buf buf, hbuf;
  nghttp2_tstamp ts = 0;
  nghttp2_frame fr;
  nghttp2_hpack_encoder enc;
  nghttp2_stream *stream;
  nghttp2_callbacks callbacks;
  userdata ud;
  conn_options opts;
  size_t i;
  int rv;

  nghttp2_buf_wrap_init(&buf, rawbuf, sizeof(rawbuf));
  nghttp2_buf_init(&hbuf);

  /* Receive DATA with PADDED and END_STREAM set */
  server_default_callbacks(&callbacks);
  callbacks.recv_data = recv_data;

  opts = (conn_options){
    .callbacks = &callbacks,
    .user_data = &ud,
  };

  setup_default_server_with_options(&conn, opts);
  read_client_preface(conn, NULL, 0, ts);
  nghttp2_hpack_encoder_init(&enc, NGHTTP2_HPACK_DEFAULT_MAX_BUFFER_SIZE, mem);

  nghttp2_buf_reset(&hbuf);
  rv =
    nghttp2_hpack_encoder_write(&enc, &hbuf, reqnva, nghttp2_arraylen(reqnva));

  assert_int(0, ==, rv);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags = NGHTTP2_HEADERS_FLAG_END_HEADERS,
        .stream_id = 0x01,
      },
    .field_block = hbuf.pos,
    .field_blocklen = nghttp2_buf_len(&hbuf),
  };

  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);

  nghttp2_buf_reset(&buf);
  buf.last +=
    nghttp2_frame_encode_headers(buf.last, nghttp2_buf_left(&buf), &fr.headers);

  fr.data = (nghttp2_frame_data){
    .hd =
      {
        .type = NGHTTP2_FRAME_DATA,
        .flags = NGHTTP2_DATA_FLAG_END_STREAM | NGHTTP2_DATA_FLAG_PADDED,
        .stream_id = 0x01,
      },
    .padlen = 11,
    .data = nulldata,
    .datalen = 111,
  };

  fr.data.hd.len = (uint32_t)nghttp2_frame_encode_data_payloadlen(&fr.data);

  buf.last +=
    nghttp2_frame_encode_data(buf.last, nghttp2_buf_left(&buf), &fr.data);

  ud = (userdata){0};
  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH,
              ==, conn->rx.frrd.state);
  assert_size(1, ==, ud.recv_data.ncalled);
  assert_int64(0x01, ==, ud.recv_data.stream_id);
  assert_size(111, ==, ud.recv_data.datalen);
  assert_true(ud.recv_data.fin);

  stream = nghttp2_conn_find_stream(conn, 0x01);

  assert_not_null(stream);
  assert_true(stream->flags & NGHTTP2_STREAM_FLAG_SHUT_RD);

  nghttp2_hpack_encoder_free(&enc);
  nghttp2_conn_del(conn);

  /* Receive 1 byte at a time */
  server_default_callbacks(&callbacks);
  callbacks.recv_data = recv_data;

  opts = (conn_options){
    .callbacks = &callbacks,
    .user_data = &ud,
  };

  setup_default_server_with_options(&conn, opts);
  read_client_preface(conn, NULL, 0, ts);

  ud = (userdata){0};

  for (i = 0; i < nghttp2_buf_len(&buf) - 12; ++i) {
    rv = nghttp2_conn_read(conn, buf.pos + i, 1, ++ts);

    assert_int(0, ==, rv);
  }

  assert_size(110, ==, ud.recv_data.ncalled);
  assert_int64(0x01, ==, ud.recv_data.stream_id);
  assert_size(110, ==, ud.recv_data.datalen);
  assert_false(ud.recv_data.fin);

  for (i = nghttp2_buf_len(&buf) - 12; i < nghttp2_buf_len(&buf); ++i) {
    rv = nghttp2_conn_read(conn, buf.pos + i, 1, ++ts);

    assert_int(0, ==, rv);
  }

  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH,
              ==, conn->rx.frrd.state);
  assert_size(111, ==, ud.recv_data.ncalled);
  assert_int64(0x01, ==, ud.recv_data.stream_id);
  assert_size(111, ==, ud.recv_data.datalen);
  assert_true(ud.recv_data.fin);

  stream = nghttp2_conn_find_stream(conn, 0x01);

  assert_not_null(stream);
  assert_true(stream->flags & NGHTTP2_STREAM_FLAG_SHUT_RD);

  nghttp2_conn_del(conn);

  /* Receive DATA with PADDED and no END_STREAM set */
  server_default_callbacks(&callbacks);
  callbacks.recv_data = recv_data;

  opts = (conn_options){
    .callbacks = &callbacks,
    .user_data = &ud,
  };

  setup_default_server_with_options(&conn, opts);
  read_client_preface(conn, NULL, 0, ts);
  nghttp2_hpack_encoder_init(&enc, NGHTTP2_HPACK_DEFAULT_MAX_BUFFER_SIZE, mem);

  nghttp2_buf_reset(&hbuf);
  rv =
    nghttp2_hpack_encoder_write(&enc, &hbuf, reqnva, nghttp2_arraylen(reqnva));

  assert_int(0, ==, rv);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags = NGHTTP2_HEADERS_FLAG_END_HEADERS,
        .stream_id = 0x01,
      },
    .field_block = hbuf.pos,
    .field_blocklen = nghttp2_buf_len(&hbuf),
  };

  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);

  nghttp2_buf_reset(&buf);
  buf.last +=
    nghttp2_frame_encode_headers(buf.last, nghttp2_buf_left(&buf), &fr.headers);

  fr.data = (nghttp2_frame_data){
    .hd =
      {
        .type = NGHTTP2_FRAME_DATA,
        .flags = NGHTTP2_DATA_FLAG_PADDED,
        .stream_id = 0x01,
      },
    .padlen = 11,
    .data = nulldata,
    .datalen = 111,
  };

  fr.data.hd.len = (uint32_t)nghttp2_frame_encode_data_payloadlen(&fr.data);

  buf.last +=
    nghttp2_frame_encode_data(buf.last, nghttp2_buf_left(&buf), &fr.data);

  ud = (userdata){0};
  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH,
              ==, conn->rx.frrd.state);
  assert_size(1, ==, ud.recv_data.ncalled);
  assert_int64(0x01, ==, ud.recv_data.stream_id);
  assert_size(111, ==, ud.recv_data.datalen);
  assert_false(ud.recv_data.fin);

  stream = nghttp2_conn_find_stream(conn, 0x01);

  assert_not_null(stream);
  assert_false(stream->flags & NGHTTP2_STREAM_FLAG_SHUT_RD);

  nghttp2_hpack_encoder_free(&enc);
  nghttp2_conn_del(conn);

  /* Receive DATA without PADDED flag set */
  server_default_callbacks(&callbacks);
  callbacks.recv_data = recv_data;

  opts = (conn_options){
    .callbacks = &callbacks,
    .user_data = &ud,
  };

  setup_default_server_with_options(&conn, opts);
  read_client_preface(conn, NULL, 0, ts);
  nghttp2_hpack_encoder_init(&enc, NGHTTP2_HPACK_DEFAULT_MAX_BUFFER_SIZE, mem);

  nghttp2_buf_reset(&hbuf);
  rv =
    nghttp2_hpack_encoder_write(&enc, &hbuf, reqnva, nghttp2_arraylen(reqnva));

  assert_int(0, ==, rv);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags = NGHTTP2_HEADERS_FLAG_END_HEADERS,
        .stream_id = 0x01,
      },
    .field_block = hbuf.pos,
    .field_blocklen = nghttp2_buf_len(&hbuf),
  };

  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);

  nghttp2_buf_reset(&buf);
  buf.last +=
    nghttp2_frame_encode_headers(buf.last, nghttp2_buf_left(&buf), &fr.headers);

  fr.data = (nghttp2_frame_data){
    .hd =
      {
        .type = NGHTTP2_FRAME_DATA,
        .flags = NGHTTP2_DATA_FLAG_END_STREAM,
        .stream_id = 0x01,
      },
    .data = nulldata,
    .datalen = 111,
  };

  fr.data.hd.len = (uint32_t)nghttp2_frame_encode_data_payloadlen(&fr.data);

  buf.last +=
    nghttp2_frame_encode_data(buf.last, nghttp2_buf_left(&buf), &fr.data);

  ud = (userdata){0};
  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH,
              ==, conn->rx.frrd.state);
  assert_size(1, ==, ud.recv_data.ncalled);
  assert_int64(0x01, ==, ud.recv_data.stream_id);
  assert_size(111, ==, ud.recv_data.datalen);
  assert_true(ud.recv_data.fin);

  stream = nghttp2_conn_find_stream(conn, 0x01);

  assert_not_null(stream);
  assert_true(stream->flags & NGHTTP2_STREAM_FLAG_SHUT_RD);

  nghttp2_hpack_encoder_free(&enc);
  nghttp2_conn_del(conn);

  /* Receive DATA with PADDED flag set and the length is too short */
  setup_default_server(&conn);
  read_client_preface(conn, NULL, 0, ts);
  nghttp2_hpack_encoder_init(&enc, NGHTTP2_HPACK_DEFAULT_MAX_BUFFER_SIZE, mem);

  nghttp2_buf_reset(&hbuf);
  rv =
    nghttp2_hpack_encoder_write(&enc, &hbuf, reqnva, nghttp2_arraylen(reqnva));

  assert_int(0, ==, rv);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags = NGHTTP2_HEADERS_FLAG_END_HEADERS,
        .stream_id = 0x01,
      },
    .field_block = hbuf.pos,
    .field_blocklen = nghttp2_buf_len(&hbuf),
  };

  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);

  nghttp2_buf_reset(&buf);
  buf.last +=
    nghttp2_frame_encode_headers(buf.last, nghttp2_buf_left(&buf), &fr.headers);

  fr.data = (nghttp2_frame_data){
    .hd =
      {
        .type = NGHTTP2_FRAME_DATA,
        .flags = NGHTTP2_DATA_FLAG_PADDED,
        .stream_id = 0x01,
      },
  };

  buf.last +=
    nghttp2_frame_encode_data(buf.last, nghttp2_buf_left(&buf), &fr.data);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_CLOSING, ==,
              conn->rx.frrd.state);
  assert_uint32(NGHTTP2_PROTOCOL_ERROR, ==, conn->tx.goaway.error_code);

  nghttp2_hpack_encoder_free(&enc);
  nghttp2_conn_del(conn);

  /* Receive DATA with PADDED flag set and the length is too short */
  setup_default_server(&conn);
  read_client_preface(conn, NULL, 0, ts);
  nghttp2_hpack_encoder_init(&enc, NGHTTP2_HPACK_DEFAULT_MAX_BUFFER_SIZE, mem);

  nghttp2_buf_reset(&hbuf);
  rv =
    nghttp2_hpack_encoder_write(&enc, &hbuf, reqnva, nghttp2_arraylen(reqnva));

  assert_int(0, ==, rv);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags = NGHTTP2_HEADERS_FLAG_END_HEADERS,
        .stream_id = 0x01,
      },
    .field_block = hbuf.pos,
    .field_blocklen = nghttp2_buf_len(&hbuf),
  };

  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);

  nghttp2_buf_reset(&buf);
  buf.last +=
    nghttp2_frame_encode_headers(buf.last, nghttp2_buf_left(&buf), &fr.headers);

  fr.data = (nghttp2_frame_data){
    .hd =
      {
        .len = 1,
        .type = NGHTTP2_FRAME_DATA,
        .flags = NGHTTP2_DATA_FLAG_PADDED,
        .stream_id = 0x01,
      },
    .padlen = 1,
  };

  buf.last +=
    nghttp2_frame_encode_data(buf.last, nghttp2_buf_left(&buf), &fr.data);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_CLOSING, ==,
              conn->rx.frrd.state);
  assert_uint32(NGHTTP2_PROTOCOL_ERROR, ==, conn->tx.goaway.error_code);

  nghttp2_hpack_encoder_free(&enc);
  nghttp2_conn_del(conn);

  /* Receive 0 length DATA */
  server_default_callbacks(&callbacks);
  callbacks.recv_data = recv_data;

  opts = (conn_options){
    .callbacks = &callbacks,
    .user_data = &ud,
  };

  setup_default_server_with_options(&conn, opts);
  read_client_preface(conn, NULL, 0, ts);
  nghttp2_hpack_encoder_init(&enc, NGHTTP2_HPACK_DEFAULT_MAX_BUFFER_SIZE, mem);

  nghttp2_buf_reset(&hbuf);
  rv =
    nghttp2_hpack_encoder_write(&enc, &hbuf, reqnva, nghttp2_arraylen(reqnva));

  assert_int(0, ==, rv);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags = NGHTTP2_HEADERS_FLAG_END_HEADERS,
        .stream_id = 0x01,
      },
    .field_block = hbuf.pos,
    .field_blocklen = nghttp2_buf_len(&hbuf),
  };

  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);

  nghttp2_buf_reset(&buf);
  buf.last +=
    nghttp2_frame_encode_headers(buf.last, nghttp2_buf_left(&buf), &fr.headers);

  fr.data = (nghttp2_frame_data){
    .hd =
      {
        .type = NGHTTP2_FRAME_DATA,
        .flags = NGHTTP2_DATA_FLAG_END_STREAM,
        .stream_id = 0x01,
      },
  };

  buf.last +=
    nghttp2_frame_encode_data(buf.last, nghttp2_buf_left(&buf), &fr.data);

  ud = (userdata){0};
  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH,
              ==, conn->rx.frrd.state);
  assert_size(1, ==, ud.recv_data.ncalled);
  assert_int64(0x01, ==, ud.recv_data.stream_id);
  assert_size(0, ==, ud.recv_data.datalen);
  assert_true(ud.recv_data.fin);

  nghttp2_hpack_encoder_free(&enc);
  nghttp2_conn_del(conn);

  /* Receive 0 length DATA with 1 byte padding */
  setup_default_server(&conn);
  read_client_preface(conn, NULL, 0, ts);
  nghttp2_hpack_encoder_init(&enc, NGHTTP2_HPACK_DEFAULT_MAX_BUFFER_SIZE, mem);

  nghttp2_buf_reset(&hbuf);
  rv =
    nghttp2_hpack_encoder_write(&enc, &hbuf, reqnva, nghttp2_arraylen(reqnva));

  assert_int(0, ==, rv);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags = NGHTTP2_HEADERS_FLAG_END_HEADERS,
        .stream_id = 0x01,
      },
    .field_block = hbuf.pos,
    .field_blocklen = nghttp2_buf_len(&hbuf),
  };

  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);

  nghttp2_buf_reset(&buf);
  buf.last +=
    nghttp2_frame_encode_headers(buf.last, nghttp2_buf_left(&buf), &fr.headers);

  fr.data = (nghttp2_frame_data){
    .hd =
      {
        .type = NGHTTP2_FRAME_DATA,
        .flags = NGHTTP2_DATA_FLAG_END_STREAM | NGHTTP2_DATA_FLAG_PADDED,
        .stream_id = 0x01,
      },
  };

  fr.data.hd.len = (uint32_t)nghttp2_frame_encode_data_payloadlen(&fr.data);

  buf.last +=
    nghttp2_frame_encode_data(buf.last, nghttp2_buf_left(&buf), &fr.data);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH,
              ==, conn->rx.frrd.state);

  stream = nghttp2_conn_find_stream(conn, 0x01);

  assert_not_null(stream);
  assert_true(stream->flags & NGHTTP2_STREAM_FLAG_SHUT_RD);

  nghttp2_hpack_encoder_free(&enc);
  nghttp2_conn_del(conn);

  /* Receive DATA on the closed stream  */
  server_default_callbacks(&callbacks);
  callbacks.recv_data = recv_data;

  opts = (conn_options){
    .callbacks = &callbacks,
    .user_data = &ud,
  };

  setup_default_server_with_options(&conn, opts);
  read_client_preface(conn, NULL, 0, ts);
  nghttp2_hpack_encoder_init(&enc, NGHTTP2_HPACK_DEFAULT_MAX_BUFFER_SIZE, mem);

  nghttp2_buf_reset(&hbuf);
  rv =
    nghttp2_hpack_encoder_write(&enc, &hbuf, reqnva, nghttp2_arraylen(reqnva));

  assert_int(0, ==, rv);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags = NGHTTP2_HEADERS_FLAG_END_HEADERS,
        .stream_id = 0x03,
      },
    .field_block = hbuf.pos,
    .field_blocklen = nghttp2_buf_len(&hbuf),
  };

  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);

  nghttp2_buf_reset(&buf);
  buf.last +=
    nghttp2_frame_encode_headers(buf.last, nghttp2_buf_left(&buf), &fr.headers);

  fr.data = (nghttp2_frame_data){
    .hd =
      {
        .type = NGHTTP2_FRAME_DATA,
        .flags = NGHTTP2_DATA_FLAG_END_STREAM,
        .stream_id = 0x01,
      },
    .data = nulldata,
    .datalen = 99,
  };

  fr.data.hd.len = (uint32_t)nghttp2_frame_encode_data_payloadlen(&fr.data);

  buf.last +=
    nghttp2_frame_encode_data(buf.last, nghttp2_buf_left(&buf), &fr.data);

  ud = (userdata){0};
  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH,
              ==, conn->rx.frrd.state);
  assert_size(0, ==, ud.recv_data.ncalled);

  stream = nghttp2_conn_find_stream(conn, 0x01);

  assert_null(stream);

  nghttp2_hpack_encoder_free(&enc);
  nghttp2_conn_del(conn);

  nghttp2_buf_free(&hbuf, mem);
}

void test_nghttp2_conn_recv_rst_stream(void) {
  const nghttp2_mem *mem = nghttp2_mem_default();
  nghttp2_conn *conn;
  uint8_t rawbuf[16384];
  nghttp2_buf buf, hbuf;
  nghttp2_tstamp ts = 0;
  nghttp2_frame fr;
  nghttp2_hpack_encoder enc;
  nghttp2_stream *stream;
  size_t i;
  int rv;

  nghttp2_buf_wrap_init(&buf, rawbuf, sizeof(rawbuf));
  nghttp2_buf_init(&hbuf);

  /* Receive RST_STREAM */
  setup_default_server(&conn);
  read_client_preface(conn, NULL, 0, ts);
  nghttp2_hpack_encoder_init(&enc, NGHTTP2_HPACK_DEFAULT_MAX_BUFFER_SIZE, mem);

  nghttp2_buf_reset(&hbuf);
  rv =
    nghttp2_hpack_encoder_write(&enc, &hbuf, reqnva, nghttp2_arraylen(reqnva));

  assert_int(0, ==, rv);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags = NGHTTP2_HEADERS_FLAG_END_HEADERS,
        .stream_id = 0x01,
      },
    .field_block = hbuf.pos,
    .field_blocklen = nghttp2_buf_len(&hbuf),
  };

  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);

  nghttp2_buf_reset(&buf);
  buf.last +=
    nghttp2_frame_encode_headers(buf.last, nghttp2_buf_left(&buf), &fr.headers);

  fr.rst_stream = (nghttp2_frame_rst_stream){
    .hd =
      {
        .len = 4,
        .type = NGHTTP2_FRAME_RST_STREAM,
        .stream_id = 0x01,
      },
    .error_code = NGHTTP2_PROTOCOL_ERROR,
  };

  buf.last += nghttp2_frame_encode_rst_stream(buf.last, nghttp2_buf_left(&buf),
                                              &fr.rst_stream);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH,
              ==, conn->rx.frrd.state);

  stream = nghttp2_conn_find_stream(conn, 0x01);

  assert_null(stream);

  nghttp2_hpack_encoder_free(&enc);
  nghttp2_conn_del(conn);

  /* Receive 1 byte at a time */
  setup_default_server(&conn);
  read_client_preface(conn, NULL, 0, ts);

  for (i = 0; i < nghttp2_buf_len(&buf); ++i) {
    rv = nghttp2_conn_read(conn, buf.pos + i, 1, ++ts);

    assert_int(0, ==, rv);
  }

  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH,
              ==, conn->rx.frrd.state);

  stream = nghttp2_conn_find_stream(conn, 0x01);

  assert_null(stream);

  nghttp2_conn_del(conn);

  /* Receive RST_STREAM with stream ID == 0 */
  setup_default_server(&conn);
  read_client_preface(conn, NULL, 0, ts);

  fr.rst_stream = (nghttp2_frame_rst_stream){
    .hd =
      {
        .len = 4,
        .type = NGHTTP2_FRAME_RST_STREAM,
      },
    .error_code = NGHTTP2_PROTOCOL_ERROR,
  };

  nghttp2_buf_reset(&buf);
  buf.last += nghttp2_frame_encode_rst_stream(buf.last, nghttp2_buf_left(&buf),
                                              &fr.rst_stream);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_CLOSING, ==,
              conn->rx.frrd.state);
  assert_uint32(NGHTTP2_PROTOCOL_ERROR, ==, conn->tx.goaway.error_code);

  nghttp2_conn_del(conn);

  /* Receive RST_STREAM with frame length != 4 */
  setup_default_server(&conn);
  read_client_preface(conn, NULL, 0, ts);

  fr.rst_stream = (nghttp2_frame_rst_stream){
    .hd =
      {
        .len = 8,
        .type = NGHTTP2_FRAME_RST_STREAM,
        .stream_id = 0x01,
      },
    .error_code = NGHTTP2_PROTOCOL_ERROR,
  };

  nghttp2_buf_reset(&buf);
  buf.last += nghttp2_frame_encode_rst_stream(buf.last, nghttp2_buf_left(&buf),
                                              &fr.rst_stream);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_CLOSING, ==,
              conn->rx.frrd.state);
  assert_uint32(NGHTTP2_PROTOCOL_ERROR, ==, conn->tx.goaway.error_code);

  nghttp2_conn_del(conn);

  /* Receive RST_STREAM against the idle stream */
  setup_default_server(&conn);
  read_client_preface(conn, NULL, 0, ts);

  fr.rst_stream = (nghttp2_frame_rst_stream){
    .hd =
      {
        .len = 4,
        .type = NGHTTP2_FRAME_RST_STREAM,
        .stream_id = 0x01,
      },
    .error_code = NGHTTP2_PROTOCOL_ERROR,
  };

  nghttp2_buf_reset(&buf);
  buf.last += nghttp2_frame_encode_rst_stream(buf.last, nghttp2_buf_left(&buf),
                                              &fr.rst_stream);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_CLOSING, ==,
              conn->rx.frrd.state);
  assert_uint32(NGHTTP2_PROTOCOL_ERROR, ==, conn->tx.goaway.error_code);

  nghttp2_conn_del(conn);

  /* Receive RST_STREAM on the closed stream */
  setup_default_server(&conn);
  read_client_preface(conn, NULL, 0, ts);
  nghttp2_hpack_encoder_init(&enc, NGHTTP2_HPACK_DEFAULT_MAX_BUFFER_SIZE, mem);

  nghttp2_buf_reset(&hbuf);
  rv =
    nghttp2_hpack_encoder_write(&enc, &hbuf, reqnva, nghttp2_arraylen(reqnva));

  assert_int(0, ==, rv);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags = NGHTTP2_HEADERS_FLAG_END_HEADERS,
        .stream_id = 0x03,
      },
    .field_block = hbuf.pos,
    .field_blocklen = nghttp2_buf_len(&hbuf),
  };

  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);

  nghttp2_buf_reset(&buf);
  buf.last +=
    nghttp2_frame_encode_headers(buf.last, nghttp2_buf_left(&buf), &fr.headers);

  fr.rst_stream = (nghttp2_frame_rst_stream){
    .hd =
      {
        .len = 4,
        .type = NGHTTP2_FRAME_RST_STREAM,
        .stream_id = 0x01,
      },
    .error_code = NGHTTP2_PROTOCOL_ERROR,
  };

  buf.last += nghttp2_frame_encode_rst_stream(buf.last, nghttp2_buf_left(&buf),
                                              &fr.rst_stream);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH,
              ==, conn->rx.frrd.state);

  stream = nghttp2_conn_find_stream(conn, 0x03);

  assert_not_null(stream);

  nghttp2_hpack_encoder_free(&enc);
  nghttp2_conn_del(conn);

  nghttp2_buf_free(&hbuf, mem);
}

void test_nghttp2_conn_recv_settings(void) {
  const nghttp2_mem *mem = nghttp2_mem_default();
  nghttp2_conn *conn;
  nghttp2_frame fr;
  nghttp2_settings_entry iv[16];
  uint8_t rawbuf[16384];
  nghttp2_buf buf, hbuf;
  nghttp2_tstamp ts = 0;
  nghttp2_hpack_encoder enc;
  nghttp2_stream *stream;
  userdata ud;
  nghttp2_callbacks callbacks;
  conn_options opts;
  size_t i;
  int rv;

  nghttp2_buf_wrap_init(&buf, rawbuf, sizeof(rawbuf));
  nghttp2_buf_init(&hbuf);

  /* Receive empty SETTINGS */
  server_default_callbacks(&callbacks);
  callbacks.recv_settings = recv_settings;

  opts = (conn_options){
    .callbacks = &callbacks,
    .user_data = &ud,
  };

  setup_default_server_with_options(&conn, opts);
  read_client_preface(conn, NULL, 0, ts);

  fr.settings = (nghttp2_frame_settings){
    .hd =
      {
        .type = NGHTTP2_FRAME_SETTINGS,
      },
  };

  nghttp2_buf_reset(&buf);
  buf.last += nghttp2_frame_encode_settings(buf.last, nghttp2_buf_left(&buf),
                                            &fr.settings);

  ud = (userdata){0};
  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_size(1, ==, ud.recv_settings.ncalled);
  assert_size(NGHTTP2_HPACK_DEFAULT_MAX_BUFFER_SIZE, ==,
              ud.recv_settings.settings.hpack_max_dtable_capacity);
  assert_uint32(0, ==, ud.recv_settings.settings.max_concurrent_streams);
  assert_uint32(NGHTTP2_INITIAL_WINDOW_SIZE, ==,
                ud.recv_settings.settings.initial_max_stream_data);
  assert_uint32(0, ==, ud.recv_settings.settings.max_field_section_size);
  assert_uint32(0, ==, ud.recv_settings.settings.enable_connect_protocol);

  nghttp2_conn_del(conn);

  /* Receive non-empty SETTINGS */
  server_default_callbacks(&callbacks);
  callbacks.recv_settings = recv_settings;

  opts = (conn_options){
    .callbacks = &callbacks,
    .user_data = &ud,
  };

  setup_default_server_with_options(&conn, opts);
  read_client_preface(conn, NULL, 0, ts);

  iv[0] = (nghttp2_settings_entry){
    .id = NGHTTP2_SETTINGS_HEADER_TABLE_SIZE,
    .value = 1024,
  };
  iv[1] = (nghttp2_settings_entry){
    .id = NGHTTP2_SETTINGS_HEADER_TABLE_SIZE,
    .value = 2048,
  };
  iv[2] = (nghttp2_settings_entry){
    .id = NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS,
    .value = 111,
  };
  iv[3] = (nghttp2_settings_entry){
    .id = NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE,
    .value = INT32_MAX,
  };
  iv[4] = (nghttp2_settings_entry){
    .id = NGHTTP2_SETTINGS_MAX_HEADER_LIST_SIZE,
    .value = UINT32_MAX,
  };
  iv[5] = (nghttp2_settings_entry){
    .id = NGHTTP2_SETTINGS_ENABLE_CONNECT_PROTOCOL,
    .value = 1,
  };
  iv[6] = (nghttp2_settings_entry){
    .id = NGHTTP2_SETTINGS_ENABLE_PUSH,
    .value = 1,
  };
  iv[7] = (nghttp2_settings_entry){
    .id = NGHTTP2_SETTINGS_MAX_FRAME_SIZE,
    .value = 1 << 20,
  };
  iv[8] = (nghttp2_settings_entry){
    .id = UINT16_MAX,
    .value = UINT32_MAX,
  };

  fr.settings = (nghttp2_frame_settings){
    .hd =
      {
        .type = NGHTTP2_FRAME_SETTINGS,
      },
    .iv = iv,
    .niv = 9,
  };

  fr.settings.hd.len =
    (uint32_t)nghttp2_frame_encode_settings_payloadlen(&fr.settings);

  nghttp2_buf_reset(&buf);
  buf.last += nghttp2_frame_encode_settings(buf.last, nghttp2_buf_left(&buf),
                                            &fr.settings);

  ud = (userdata){0};
  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_size(1, ==, ud.recv_settings.ncalled);
  assert_size(2048, ==, ud.recv_settings.settings.hpack_max_dtable_capacity);
  assert_uint32(0, ==, ud.recv_settings.settings.max_concurrent_streams);
  assert_uint32(INT32_MAX, ==,
                ud.recv_settings.settings.initial_max_stream_data);
  assert_uint32(UINT32_MAX, ==,
                ud.recv_settings.settings.max_field_section_size);
  assert_uint32(1, ==, ud.recv_settings.settings.enable_connect_protocol);

  nghttp2_conn_del(conn);

  /* Read 1 byte at a time */
  server_default_callbacks(&callbacks);
  callbacks.recv_settings = recv_settings;

  opts = (conn_options){
    .callbacks = &callbacks,
    .user_data = &ud,
  };

  setup_default_server_with_options(&conn, opts);
  read_client_preface(conn, NULL, 0, ts);

  ud = (userdata){0};

  for (i = 0; i < nghttp2_buf_len(&buf); ++i) {
    rv = nghttp2_conn_read(conn, buf.pos + i, 1, ++ts);

    assert_int(0, ==, rv);
  }

  assert_size(1, ==, ud.recv_settings.ncalled);
  assert_size(2048, ==, ud.recv_settings.settings.hpack_max_dtable_capacity);
  assert_uint32(0, ==, ud.recv_settings.settings.max_concurrent_streams);
  assert_uint32(INT32_MAX, ==,
                ud.recv_settings.settings.initial_max_stream_data);
  assert_uint32(UINT32_MAX, ==,
                ud.recv_settings.settings.max_field_section_size);
  assert_uint32(1, ==, ud.recv_settings.settings.enable_connect_protocol);

  nghttp2_conn_del(conn);

  /* Receive SETTINGS_ENABLE_PUSH other than 0 or 1 */
  setup_default_server(&conn);
  read_client_preface(conn, NULL, 0, ts);

  iv[0] = (nghttp2_settings_entry){
    .id = NGHTTP2_SETTINGS_ENABLE_PUSH,
    .value = 2,
  };

  fr.settings = (nghttp2_frame_settings){
    .hd =
      {
        .type = NGHTTP2_FRAME_SETTINGS,
      },
    .iv = iv,
    .niv = 1,
  };

  fr.settings.hd.len =
    (uint32_t)nghttp2_frame_encode_settings_payloadlen(&fr.settings);

  nghttp2_buf_reset(&buf);
  buf.last += nghttp2_frame_encode_settings(buf.last, nghttp2_buf_left(&buf),
                                            &fr.settings);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_CLOSING, ==,
              conn->rx.frrd.state);
  assert_uint32(NGHTTP2_PROTOCOL_ERROR, ==, conn->tx.goaway.error_code);

  nghttp2_conn_del(conn);

  /* Receive SETTINGS_ENABLE_CONNECT_PROTOCOL turned on then turned
     off */
  setup_default_server(&conn);
  read_client_preface(conn, NULL, 0, ts);

  iv[0] = (nghttp2_settings_entry){
    .id = NGHTTP2_SETTINGS_ENABLE_CONNECT_PROTOCOL,
    .value = 1,
  };
  iv[1] = (nghttp2_settings_entry){
    .id = NGHTTP2_SETTINGS_ENABLE_CONNECT_PROTOCOL,
  };

  fr.settings = (nghttp2_frame_settings){
    .hd =
      {
        .type = NGHTTP2_FRAME_SETTINGS,
      },
    .iv = iv,
    .niv = 2,
  };

  fr.settings.hd.len =
    (uint32_t)nghttp2_frame_encode_settings_payloadlen(&fr.settings);

  nghttp2_buf_reset(&buf);
  buf.last += nghttp2_frame_encode_settings(buf.last, nghttp2_buf_left(&buf),
                                            &fr.settings);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_CLOSING, ==,
              conn->rx.frrd.state);
  assert_uint32(NGHTTP2_PROTOCOL_ERROR, ==, conn->tx.goaway.error_code);

  nghttp2_conn_del(conn);

  /* Receive SETTINGS_INITIAL_WINDOW_SIZE that exceeds the maximum
     value */
  setup_default_server(&conn);
  read_client_preface(conn, NULL, 0, ts);

  iv[0] = (nghttp2_settings_entry){
    .id = NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE,
    .value = NGHTTP2_MAX_WINDOW_SIZE + 1U,
  };
  iv[1] = (nghttp2_settings_entry){
    .id = NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE,
    .value = NGHTTP2_MAX_WINDOW_SIZE,
  };

  fr.settings = (nghttp2_frame_settings){
    .hd =
      {
        .type = NGHTTP2_FRAME_SETTINGS,
      },
    .iv = iv,
    .niv = 2,
  };

  fr.settings.hd.len =
    (uint32_t)nghttp2_frame_encode_settings_payloadlen(&fr.settings);

  nghttp2_buf_reset(&buf);
  buf.last += nghttp2_frame_encode_settings(buf.last, nghttp2_buf_left(&buf),
                                            &fr.settings);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_CLOSING, ==,
              conn->rx.frrd.state);
  assert_uint32(NGHTTP2_PROTOCOL_ERROR, ==, conn->tx.goaway.error_code);

  nghttp2_conn_del(conn);

  /* Receive SETTINGS_MAX_FRAME_SIZE that is less than the minimum
     value. */
  setup_default_server(&conn);
  read_client_preface(conn, NULL, 0, ts);

  iv[0] = (nghttp2_settings_entry){
    .id = NGHTTP2_SETTINGS_MAX_FRAME_SIZE,
    .value = NGHTTP2_DEFAULT_MAX_FRAME_SIZE - 1U,
  };

  fr.settings = (nghttp2_frame_settings){
    .hd =
      {
        .type = NGHTTP2_FRAME_SETTINGS,
      },
    .iv = iv,
    .niv = 1,
  };

  fr.settings.hd.len =
    (uint32_t)nghttp2_frame_encode_settings_payloadlen(&fr.settings);

  nghttp2_buf_reset(&buf);
  buf.last += nghttp2_frame_encode_settings(buf.last, nghttp2_buf_left(&buf),
                                            &fr.settings);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_CLOSING, ==,
              conn->rx.frrd.state);
  assert_uint32(NGHTTP2_PROTOCOL_ERROR, ==, conn->tx.goaway.error_code);

  nghttp2_conn_del(conn);

  /* Receive SETTINGS_MAX_FRAME_SIZE that exceeds the maximum
     value. */
  setup_default_server(&conn);
  read_client_preface(conn, NULL, 0, ts);

  iv[0] = (nghttp2_settings_entry){
    .id = NGHTTP2_SETTINGS_MAX_FRAME_SIZE,
    .value = NGHTTP2_HARD_MAX_FRAME_SIZE + 1U,
  };

  fr.settings = (nghttp2_frame_settings){
    .hd =
      {
        .type = NGHTTP2_FRAME_SETTINGS,
      },
    .iv = iv,
    .niv = 1,
  };

  fr.settings.hd.len =
    (uint32_t)nghttp2_frame_encode_settings_payloadlen(&fr.settings);

  nghttp2_buf_reset(&buf);
  buf.last += nghttp2_frame_encode_settings(buf.last, nghttp2_buf_left(&buf),
                                            &fr.settings);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_CLOSING, ==,
              conn->rx.frrd.state);
  assert_uint32(NGHTTP2_PROTOCOL_ERROR, ==, conn->tx.goaway.error_code);

  nghttp2_conn_del(conn);

  /* Receive SETTINGS with stream_id != 0 */
  setup_default_server(&conn);
  read_client_preface(conn, NULL, 0, ts);

  fr.settings = (nghttp2_frame_settings){
    .hd =
      {
        .type = NGHTTP2_FRAME_SETTINGS,
        .stream_id = 0x01,
      },
  };

  nghttp2_buf_reset(&buf);
  buf.last += nghttp2_frame_encode_settings(buf.last, nghttp2_buf_left(&buf),
                                            &fr.settings);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_CLOSING, ==,
              conn->rx.frrd.state);
  assert_uint32(NGHTTP2_PROTOCOL_ERROR, ==, conn->tx.goaway.error_code);

  nghttp2_conn_del(conn);

  /* Receive SETTINGS with ACK flag set which is unexpected */
  setup_default_server(&conn);
  read_client_preface(conn, NULL, 0, ts);

  fr.settings = (nghttp2_frame_settings){
    .hd =
      {
        .type = NGHTTP2_FRAME_SETTINGS,
        .flags = NGHTTP2_SETTINGS_FLAG_ACK,
      },
  };

  nghttp2_buf_reset(&buf);
  buf.last += nghttp2_frame_encode_settings(buf.last, nghttp2_buf_left(&buf),
                                            &fr.settings);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_CLOSING, ==,
              conn->rx.frrd.state);
  assert_uint32(NGHTTP2_PROTOCOL_ERROR, ==, conn->tx.goaway.error_code);

  nghttp2_conn_del(conn);

  /* Receive SETTINGS with ACK flag */
  setup_default_server(&conn);
  read_client_preface(conn, NULL, 0, ts);

  conn->flags |= NGHTTP2_CONN_FLAG_EXPECT_SETTINGS_ACK;

  fr.settings = (nghttp2_frame_settings){
    .hd =
      {
        .type = NGHTTP2_FRAME_SETTINGS,
        .flags = NGHTTP2_SETTINGS_FLAG_ACK,
      },
  };

  nghttp2_buf_reset(&buf);
  buf.last += nghttp2_frame_encode_settings(buf.last, nghttp2_buf_left(&buf),
                                            &fr.settings);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH,
              ==, conn->rx.frrd.state);
  assert_uint32(100, ==, conn->rx.max_concurrent_streams);

  nghttp2_conn_del(conn);

  /* Receive SETTINGS with ACK flag with non-zero payload*/
  setup_default_server(&conn);
  read_client_preface(conn, NULL, 0, ts);

  conn->flags |= NGHTTP2_CONN_FLAG_EXPECT_SETTINGS_ACK;

  fr.settings = (nghttp2_frame_settings){
    .hd =
      {
        .len = 6,
        .type = NGHTTP2_FRAME_SETTINGS,
        .flags = NGHTTP2_SETTINGS_FLAG_ACK,
      },
  };

  nghttp2_buf_reset(&buf);
  buf.last += nghttp2_frame_encode_settings(buf.last, nghttp2_buf_left(&buf),
                                            &fr.settings);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_CLOSING, ==,
              conn->rx.frrd.state);
  assert_uint32(NGHTTP2_PROTOCOL_ERROR, ==, conn->tx.goaway.error_code);

  nghttp2_conn_del(conn);

  /* Receive SETTINGS with length is not multiple of 6 */
  setup_default_server(&conn);
  read_client_preface(conn, NULL, 0, ts);

  fr.settings = (nghttp2_frame_settings){
    .hd =
      {
        .len = 17,
        .type = NGHTTP2_FRAME_SETTINGS,
      },
  };

  nghttp2_buf_reset(&buf);
  buf.last += nghttp2_frame_encode_settings(buf.last, nghttp2_buf_left(&buf),
                                            &fr.settings);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_CLOSING, ==,
              conn->rx.frrd.state);
  assert_uint32(NGHTTP2_PROTOCOL_ERROR, ==, conn->tx.goaway.error_code);

  nghttp2_conn_del(conn);

  /* Receive SETTINGS with SETTINGS_ENABLE_PUSH = 1 from server */
  setup_default_client(&conn);
  read_server_preface(conn, NULL, 0, ts);

  iv[0] = (nghttp2_settings_entry){
    .id = NGHTTP2_SETTINGS_ENABLE_PUSH,
    .value = 1,
  };

  fr.settings = (nghttp2_frame_settings){
    .hd =
      {
        .type = NGHTTP2_FRAME_SETTINGS,
      },
    .iv = iv,
    .niv = 1,
  };

  fr.settings.hd.len =
    (uint32_t)nghttp2_frame_encode_settings_payloadlen(&fr.settings);

  nghttp2_buf_reset(&buf);
  buf.last += nghttp2_frame_encode_settings(buf.last, nghttp2_buf_left(&buf),
                                            &fr.settings);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_CLOSING, ==,
              conn->rx.frrd.state);
  assert_uint32(NGHTTP2_PROTOCOL_ERROR, ==, conn->tx.goaway.error_code);

  nghttp2_conn_del(conn);

  /* Receive SETTINGS with SETTINGS_ENABLE_PUSH = 0 from server */
  setup_default_client(&conn);
  read_server_preface(conn, NULL, 0, ts);

  iv[0] = (nghttp2_settings_entry){
    .id = NGHTTP2_SETTINGS_ENABLE_PUSH,
  };

  fr.settings = (nghttp2_frame_settings){
    .hd =
      {
        .type = NGHTTP2_FRAME_SETTINGS,
      },
    .iv = iv,
    .niv = 1,
  };

  fr.settings.hd.len =
    (uint32_t)nghttp2_frame_encode_settings_payloadlen(&fr.settings);

  nghttp2_buf_reset(&buf);
  buf.last += nghttp2_frame_encode_settings(buf.last, nghttp2_buf_left(&buf),
                                            &fr.settings);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH,
              ==, conn->rx.frrd.state);

  nghttp2_conn_del(conn);

  /* Value is split into 2 */
  setup_default_client(&conn);
  read_server_preface(conn, NULL, 0, ts);

  iv[0] = (nghttp2_settings_entry){
    .id = NGHTTP2_SETTINGS_ENABLE_PUSH,
  };

  fr.settings = (nghttp2_frame_settings){
    .hd =
      {
        .type = NGHTTP2_FRAME_SETTINGS,
      },
    .iv = iv,
    .niv = 1,
  };

  fr.settings.hd.len =
    (uint32_t)nghttp2_frame_encode_settings_payloadlen(&fr.settings);

  nghttp2_buf_reset(&buf);
  buf.last += nghttp2_frame_encode_settings(buf.last, nghttp2_buf_left(&buf),
                                            &fr.settings);

  rv = nghttp2_conn_read(conn, buf.pos, NGHTTP2_FRAME_HDLEN + 3, ++ts);

  assert_int(0, ==, rv);

  buf.pos += NGHTTP2_FRAME_HDLEN + 3;

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);

  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH,
              ==, conn->rx.frrd.state);

  nghttp2_conn_del(conn);

  /* Apply new remote limits */
  setup_default_server(&conn);
  read_client_preface(conn, NULL, 0, ts);
  nghttp2_hpack_encoder_init(&enc, NGHTTP2_HPACK_DEFAULT_MAX_BUFFER_SIZE, mem);

  nghttp2_buf_reset(&hbuf);
  rv =
    nghttp2_hpack_encoder_write(&enc, &hbuf, reqnva, nghttp2_arraylen(reqnva));

  assert_int(0, ==, rv);

  fr.headers = (nghttp2_frame_headers){
    .hd =
      {
        .type = NGHTTP2_FRAME_HEADERS,
        .flags = NGHTTP2_HEADERS_FLAG_END_HEADERS,
        .stream_id = 0x01,
      },
    .field_block = hbuf.pos,
    .field_blocklen = nghttp2_buf_len(&hbuf),
  };

  fr.headers.hd.len =
    (uint32_t)nghttp2_frame_encode_headers_payloadlen(&fr.headers);

  nghttp2_buf_reset(&buf);
  buf.last +=
    nghttp2_frame_encode_headers(buf.last, nghttp2_buf_left(&buf), &fr.headers);

  iv[0] = (nghttp2_settings_entry){
    .id = NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE,
    .value = 32768,
  };
  iv[1] = (nghttp2_settings_entry){
    .id = NGHTTP2_SETTINGS_HEADER_TABLE_SIZE,
  };
  iv[2] = (nghttp2_settings_entry){
    .id = NGHTTP2_SETTINGS_HEADER_TABLE_SIZE,
    .value = 8192,
  };

  fr.settings = (nghttp2_frame_settings){
    .hd =
      {
        .type = NGHTTP2_FRAME_SETTINGS,
      },
    .iv = iv,
    .niv = 3,
  };

  fr.settings.hd.len =
    (uint32_t)nghttp2_frame_encode_settings_payloadlen(&fr.settings);

  buf.last += nghttp2_frame_encode_settings(buf.last, nghttp2_buf_left(&buf),
                                            &fr.settings);

  rv = nghttp2_conn_read(conn, buf.pos, nghttp2_buf_len(&buf), ++ts);

  assert_int(0, ==, rv);
  assert_enum(nghttp2_frame_read_state, NGHTTP2_FRAME_READ_STATE_FRAME_LENGTH,
              ==, conn->rx.frrd.state);

  stream = nghttp2_conn_find_stream(conn, 0x01);

  assert_not_null(stream);
  assert_uint64(32768, ==, stream->tx.max_offset);
  assert_uint64(NGHTTP2_INITIAL_WINDOW_SIZE, ==, conn->tx.max_offset);

  nghttp2_hpack_encoder_free(&enc);
  nghttp2_conn_del(conn);

  nghttp2_buf_free(&hbuf, mem);
}
