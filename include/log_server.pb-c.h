/* Generated by the protocol buffer compiler.  DO NOT EDIT! */
/* Generated from: log_server.proto */

#ifndef PROTOBUF_C_log_5fserver_2eproto__INCLUDED
#define PROTOBUF_C_log_5fserver_2eproto__INCLUDED

#include <protobuf-c/protobuf-c.h>

PROTOBUF_C__BEGIN_DECLS

#if PROTOBUF_C_VERSION_NUMBER < 1003000
# error This file was generated by a newer version of protoc-c which is incompatible with your libprotobuf-c headers. Please update your headers.
#elif 1003002 < PROTOBUF_C_MIN_COMPILER_VERSION
# error This file was generated by an older version of protoc-c which is incompatible with your libprotobuf-c headers. Please regenerate this file with a newer version of protoc-c.
#endif


typedef struct _ClientMessage ClientMessage;
typedef struct _TimeSpec TimeSpec;
typedef struct _IoBuffer IoBuffer;
typedef struct _InfoMessage InfoMessage;
typedef struct _InfoMessage__StringList InfoMessage__StringList;
typedef struct _InfoMessage__NumberList InfoMessage__NumberList;
typedef struct _AcceptMessage AcceptMessage;
typedef struct _RejectMessage RejectMessage;
typedef struct _ExitMessage ExitMessage;
typedef struct _AlertMessage AlertMessage;
typedef struct _RestartMessage RestartMessage;
typedef struct _ChangeWindowSize ChangeWindowSize;
typedef struct _CommandSuspend CommandSuspend;
typedef struct _ServerMessage ServerMessage;
typedef struct _ServerHello ServerHello;


/* --- enums --- */


/* --- messages --- */

typedef enum {
  CLIENT_MESSAGE__TYPE__NOT_SET = 0,
  CLIENT_MESSAGE__TYPE_ACCEPT_MSG = 1,
  CLIENT_MESSAGE__TYPE_REJECT_MSG = 2,
  CLIENT_MESSAGE__TYPE_EXIT_MSG = 3,
  CLIENT_MESSAGE__TYPE_RESTART_MSG = 4,
  CLIENT_MESSAGE__TYPE_ALERT_MSG = 5,
  CLIENT_MESSAGE__TYPE_TTYIN_BUF = 6,
  CLIENT_MESSAGE__TYPE_TTYOUT_BUF = 7,
  CLIENT_MESSAGE__TYPE_STDIN_BUF = 8,
  CLIENT_MESSAGE__TYPE_STDOUT_BUF = 9,
  CLIENT_MESSAGE__TYPE_STDERR_BUF = 10,
  CLIENT_MESSAGE__TYPE_WINSIZE_EVENT = 11,
  CLIENT_MESSAGE__TYPE_SUSPEND_EVENT = 12
    PROTOBUF_C__FORCE_ENUM_TO_BE_INT_SIZE(CLIENT_MESSAGE__TYPE)
} ClientMessage__TypeCase;

/*
 * Client message to the server.  Messages on the wire are
 * prefixed with a 32-bit size in network byte order.
 */
struct  _ClientMessage
{
  ProtobufCMessage base;
  ClientMessage__TypeCase type_case;
  union {
    AcceptMessage *accept_msg;
    RejectMessage *reject_msg;
    ExitMessage *exit_msg;
    RestartMessage *restart_msg;
    AlertMessage *alert_msg;
    IoBuffer *ttyin_buf;
    IoBuffer *ttyout_buf;
    IoBuffer *stdin_buf;
    IoBuffer *stdout_buf;
    IoBuffer *stderr_buf;
    ChangeWindowSize *winsize_event;
    CommandSuspend *suspend_event;
  };
};
#define CLIENT_MESSAGE__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&client_message__descriptor) \
    , CLIENT_MESSAGE__TYPE__NOT_SET, {0} }


/*
 * Equivalent of POSIX struct timespec 
 */
struct  _TimeSpec
{
  ProtobufCMessage base;
  /*
   * seconds 
   */
  int64_t tv_sec;
  /*
   * nanoseconds 
   */
  int32_t tv_nsec;
};
#define TIME_SPEC__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&time_spec__descriptor) \
    , 0, 0 }


/*
 * I/O buffer with keystroke data 
 */
struct  _IoBuffer
{
  ProtobufCMessage base;
  /*
   * elapsed time since last record 
   */
  TimeSpec *delay;
  /*
   * keystroke data 
   */
  ProtobufCBinaryData data;
};
#define IO_BUFFER__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&io_buffer__descriptor) \
    , NULL, {0,NULL} }


struct  _InfoMessage__StringList
{
  ProtobufCMessage base;
  size_t n_strings;
  char **strings;
};
#define INFO_MESSAGE__STRING_LIST__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&info_message__string_list__descriptor) \
    , 0,NULL }


struct  _InfoMessage__NumberList
{
  ProtobufCMessage base;
  size_t n_numbers;
  int64_t *numbers;
};
#define INFO_MESSAGE__NUMBER_LIST__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&info_message__number_list__descriptor) \
    , 0,NULL }


typedef enum {
  INFO_MESSAGE__VALUE__NOT_SET = 0,
  INFO_MESSAGE__VALUE_NUMVAL = 2,
  INFO_MESSAGE__VALUE_STRVAL = 3,
  INFO_MESSAGE__VALUE_STRLISTVAL = 4,
  INFO_MESSAGE__VALUE_NUMLISTVAL = 5
    PROTOBUF_C__FORCE_ENUM_TO_BE_INT_SIZE(INFO_MESSAGE__VALUE)
} InfoMessage__ValueCase;

/*
 * Key/value pairs, like Privilege Manager struct info.
 * The value may be a number, a string, or a list of strings.
 */
struct  _InfoMessage
{
  ProtobufCMessage base;
  char *key;
  InfoMessage__ValueCase value_case;
  union {
    int64_t numval;
    char *strval;
    InfoMessage__StringList *strlistval;
    InfoMessage__NumberList *numlistval;
  };
};
#define INFO_MESSAGE__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&info_message__descriptor) \
    , (char *)protobuf_c_empty_string, INFO_MESSAGE__VALUE__NOT_SET, {0} }


/*
 * Event log data for command accepted by the policy.
 */
struct  _AcceptMessage
{
  ProtobufCMessage base;
  /*
   * when command was submitted 
   */
  TimeSpec *submit_time;
  /*
   * key,value event log data 
   */
  size_t n_info_msgs;
  InfoMessage **info_msgs;
  /*
   * true if I/O logging enabled 
   */
  protobuf_c_boolean expect_iobufs;
};
#define ACCEPT_MESSAGE__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&accept_message__descriptor) \
    , NULL, 0,NULL, 0 }


/*
 * Event log data for command rejected by the policy.
 */
struct  _RejectMessage
{
  ProtobufCMessage base;
  /*
   * when command was submitted 
   */
  TimeSpec *submit_time;
  /*
   * reason command was rejected 
   */
  char *reason;
  /*
   * key,value event log data 
   */
  size_t n_info_msgs;
  InfoMessage **info_msgs;
};
#define REJECT_MESSAGE__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&reject_message__descriptor) \
    , NULL, (char *)protobuf_c_empty_string, 0,NULL }


/*
 * Might revisit runtime and use end_time instead 
 */
struct  _ExitMessage
{
  ProtobufCMessage base;
  /*
   * total elapsed run time 
   */
  TimeSpec *run_time;
  /*
   * 0-255 
   */
  int32_t exit_value;
  /*
   * true if command dumped core 
   */
  protobuf_c_boolean dumped_core;
  /*
   * signal name if killed by signal 
   */
  char *signal;
  /*
   * if killed due to other error 
   */
  char *error;
};
#define EXIT_MESSAGE__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&exit_message__descriptor) \
    , NULL, 0, 0, (char *)protobuf_c_empty_string, (char *)protobuf_c_empty_string }


/*
 * Alert message, policy module-specific. 
 */
struct  _AlertMessage
{
  ProtobufCMessage base;
  /*
   * time alert message occurred 
   */
  TimeSpec *alert_time;
  /*
   * description of policy violation 
   */
  char *reason;
};
#define ALERT_MESSAGE__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&alert_message__descriptor) \
    , NULL, (char *)protobuf_c_empty_string }


/*
 * Used to restart an existing I/O log on the server. 
 */
struct  _RestartMessage
{
  ProtobufCMessage base;
  /*
   * ID of log being restarted 
   */
  char *log_id;
  /*
   * resume point (elapsed time) 
   */
  TimeSpec *resume_point;
};
#define RESTART_MESSAGE__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&restart_message__descriptor) \
    , (char *)protobuf_c_empty_string, NULL }


/*
 * Window size change event. 
 */
struct  _ChangeWindowSize
{
  ProtobufCMessage base;
  /*
   * elapsed time since last record 
   */
  TimeSpec *delay;
  /*
   * new number of rows 
   */
  int32_t rows;
  /*
   * new number of columns 
   */
  int32_t cols;
};
#define CHANGE_WINDOW_SIZE__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&change_window_size__descriptor) \
    , NULL, 0, 0 }


/*
 * Command suspend/resume event. 
 */
struct  _CommandSuspend
{
  ProtobufCMessage base;
  /*
   * elapsed time since last record 
   */
  TimeSpec *delay;
  /*
   * signal that caused suspend/resume 
   */
  char *signal;
};
#define COMMAND_SUSPEND__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&command_suspend__descriptor) \
    , NULL, (char *)protobuf_c_empty_string }


typedef enum {
  SERVER_MESSAGE__TYPE__NOT_SET = 0,
  SERVER_MESSAGE__TYPE_HELLO = 1,
  SERVER_MESSAGE__TYPE_COMMIT_POINT = 2,
  SERVER_MESSAGE__TYPE_LOG_ID = 3,
  SERVER_MESSAGE__TYPE_ERROR = 4,
  SERVER_MESSAGE__TYPE_ABORT = 5
    PROTOBUF_C__FORCE_ENUM_TO_BE_INT_SIZE(SERVER_MESSAGE__TYPE)
} ServerMessage__TypeCase;

/*
 * Server messages to the client.  Messages on the wire are
 * prefixed with a 32-bit size in network byte order.
 */
struct  _ServerMessage
{
  ProtobufCMessage base;
  ServerMessage__TypeCase type_case;
  union {
    /*
     * server hello message 
     */
    ServerHello *hello;
    /*
     * cumulative time of records stored 
     */
    TimeSpec *commit_point;
    /*
     * ID of server-side I/O log 
     */
    char *log_id;
    /*
     * error message from server 
     */
    char *error;
    /*
     * abort message, kill command 
     */
    char *abort;
  };
};
#define SERVER_MESSAGE__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&server_message__descriptor) \
    , SERVER_MESSAGE__TYPE__NOT_SET, {0} }


/*
 * Hello message from server when client connects. 
 */
struct  _ServerHello
{
  ProtobufCMessage base;
  /*
   * free-form server description 
   */
  char *server_id;
  /*
   * optional redirect if busy 
   */
  char *redirect;
  /*
   * optional list of known servers 
   */
  size_t n_servers;
  char **servers;
};
#define SERVER_HELLO__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&server_hello__descriptor) \
    , (char *)protobuf_c_empty_string, (char *)protobuf_c_empty_string, 0,NULL }


/* ClientMessage methods */
void   client_message__init
                     (ClientMessage         *message);
size_t client_message__get_packed_size
                     (const ClientMessage   *message);
size_t client_message__pack
                     (const ClientMessage   *message,
                      uint8_t             *out);
size_t client_message__pack_to_buffer
                     (const ClientMessage   *message,
                      ProtobufCBuffer     *buffer);
ClientMessage *
       client_message__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   client_message__free_unpacked
                     (ClientMessage *message,
                      ProtobufCAllocator *allocator);
/* TimeSpec methods */
void   time_spec__init
                     (TimeSpec         *message);
size_t time_spec__get_packed_size
                     (const TimeSpec   *message);
size_t time_spec__pack
                     (const TimeSpec   *message,
                      uint8_t             *out);
size_t time_spec__pack_to_buffer
                     (const TimeSpec   *message,
                      ProtobufCBuffer     *buffer);
TimeSpec *
       time_spec__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   time_spec__free_unpacked
                     (TimeSpec *message,
                      ProtobufCAllocator *allocator);
/* IoBuffer methods */
void   io_buffer__init
                     (IoBuffer         *message);
size_t io_buffer__get_packed_size
                     (const IoBuffer   *message);
size_t io_buffer__pack
                     (const IoBuffer   *message,
                      uint8_t             *out);
size_t io_buffer__pack_to_buffer
                     (const IoBuffer   *message,
                      ProtobufCBuffer     *buffer);
IoBuffer *
       io_buffer__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   io_buffer__free_unpacked
                     (IoBuffer *message,
                      ProtobufCAllocator *allocator);
/* InfoMessage__StringList methods */
void   info_message__string_list__init
                     (InfoMessage__StringList         *message);
/* InfoMessage__NumberList methods */
void   info_message__number_list__init
                     (InfoMessage__NumberList         *message);
/* InfoMessage methods */
void   info_message__init
                     (InfoMessage         *message);
size_t info_message__get_packed_size
                     (const InfoMessage   *message);
size_t info_message__pack
                     (const InfoMessage   *message,
                      uint8_t             *out);
size_t info_message__pack_to_buffer
                     (const InfoMessage   *message,
                      ProtobufCBuffer     *buffer);
InfoMessage *
       info_message__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   info_message__free_unpacked
                     (InfoMessage *message,
                      ProtobufCAllocator *allocator);
/* AcceptMessage methods */
void   accept_message__init
                     (AcceptMessage         *message);
size_t accept_message__get_packed_size
                     (const AcceptMessage   *message);
size_t accept_message__pack
                     (const AcceptMessage   *message,
                      uint8_t             *out);
size_t accept_message__pack_to_buffer
                     (const AcceptMessage   *message,
                      ProtobufCBuffer     *buffer);
AcceptMessage *
       accept_message__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   accept_message__free_unpacked
                     (AcceptMessage *message,
                      ProtobufCAllocator *allocator);
/* RejectMessage methods */
void   reject_message__init
                     (RejectMessage         *message);
size_t reject_message__get_packed_size
                     (const RejectMessage   *message);
size_t reject_message__pack
                     (const RejectMessage   *message,
                      uint8_t             *out);
size_t reject_message__pack_to_buffer
                     (const RejectMessage   *message,
                      ProtobufCBuffer     *buffer);
RejectMessage *
       reject_message__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   reject_message__free_unpacked
                     (RejectMessage *message,
                      ProtobufCAllocator *allocator);
/* ExitMessage methods */
void   exit_message__init
                     (ExitMessage         *message);
size_t exit_message__get_packed_size
                     (const ExitMessage   *message);
size_t exit_message__pack
                     (const ExitMessage   *message,
                      uint8_t             *out);
size_t exit_message__pack_to_buffer
                     (const ExitMessage   *message,
                      ProtobufCBuffer     *buffer);
ExitMessage *
       exit_message__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   exit_message__free_unpacked
                     (ExitMessage *message,
                      ProtobufCAllocator *allocator);
/* AlertMessage methods */
void   alert_message__init
                     (AlertMessage         *message);
size_t alert_message__get_packed_size
                     (const AlertMessage   *message);
size_t alert_message__pack
                     (const AlertMessage   *message,
                      uint8_t             *out);
size_t alert_message__pack_to_buffer
                     (const AlertMessage   *message,
                      ProtobufCBuffer     *buffer);
AlertMessage *
       alert_message__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   alert_message__free_unpacked
                     (AlertMessage *message,
                      ProtobufCAllocator *allocator);
/* RestartMessage methods */
void   restart_message__init
                     (RestartMessage         *message);
size_t restart_message__get_packed_size
                     (const RestartMessage   *message);
size_t restart_message__pack
                     (const RestartMessage   *message,
                      uint8_t             *out);
size_t restart_message__pack_to_buffer
                     (const RestartMessage   *message,
                      ProtobufCBuffer     *buffer);
RestartMessage *
       restart_message__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   restart_message__free_unpacked
                     (RestartMessage *message,
                      ProtobufCAllocator *allocator);
/* ChangeWindowSize methods */
void   change_window_size__init
                     (ChangeWindowSize         *message);
size_t change_window_size__get_packed_size
                     (const ChangeWindowSize   *message);
size_t change_window_size__pack
                     (const ChangeWindowSize   *message,
                      uint8_t             *out);
size_t change_window_size__pack_to_buffer
                     (const ChangeWindowSize   *message,
                      ProtobufCBuffer     *buffer);
ChangeWindowSize *
       change_window_size__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   change_window_size__free_unpacked
                     (ChangeWindowSize *message,
                      ProtobufCAllocator *allocator);
/* CommandSuspend methods */
void   command_suspend__init
                     (CommandSuspend         *message);
size_t command_suspend__get_packed_size
                     (const CommandSuspend   *message);
size_t command_suspend__pack
                     (const CommandSuspend   *message,
                      uint8_t             *out);
size_t command_suspend__pack_to_buffer
                     (const CommandSuspend   *message,
                      ProtobufCBuffer     *buffer);
CommandSuspend *
       command_suspend__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   command_suspend__free_unpacked
                     (CommandSuspend *message,
                      ProtobufCAllocator *allocator);
/* ServerMessage methods */
void   server_message__init
                     (ServerMessage         *message);
size_t server_message__get_packed_size
                     (const ServerMessage   *message);
size_t server_message__pack
                     (const ServerMessage   *message,
                      uint8_t             *out);
size_t server_message__pack_to_buffer
                     (const ServerMessage   *message,
                      ProtobufCBuffer     *buffer);
ServerMessage *
       server_message__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   server_message__free_unpacked
                     (ServerMessage *message,
                      ProtobufCAllocator *allocator);
/* ServerHello methods */
void   server_hello__init
                     (ServerHello         *message);
size_t server_hello__get_packed_size
                     (const ServerHello   *message);
size_t server_hello__pack
                     (const ServerHello   *message,
                      uint8_t             *out);
size_t server_hello__pack_to_buffer
                     (const ServerHello   *message,
                      ProtobufCBuffer     *buffer);
ServerHello *
       server_hello__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   server_hello__free_unpacked
                     (ServerHello *message,
                      ProtobufCAllocator *allocator);
/* --- per-message closures --- */

typedef void (*ClientMessage_Closure)
                 (const ClientMessage *message,
                  void *closure_data);
typedef void (*TimeSpec_Closure)
                 (const TimeSpec *message,
                  void *closure_data);
typedef void (*IoBuffer_Closure)
                 (const IoBuffer *message,
                  void *closure_data);
typedef void (*InfoMessage__StringList_Closure)
                 (const InfoMessage__StringList *message,
                  void *closure_data);
typedef void (*InfoMessage__NumberList_Closure)
                 (const InfoMessage__NumberList *message,
                  void *closure_data);
typedef void (*InfoMessage_Closure)
                 (const InfoMessage *message,
                  void *closure_data);
typedef void (*AcceptMessage_Closure)
                 (const AcceptMessage *message,
                  void *closure_data);
typedef void (*RejectMessage_Closure)
                 (const RejectMessage *message,
                  void *closure_data);
typedef void (*ExitMessage_Closure)
                 (const ExitMessage *message,
                  void *closure_data);
typedef void (*AlertMessage_Closure)
                 (const AlertMessage *message,
                  void *closure_data);
typedef void (*RestartMessage_Closure)
                 (const RestartMessage *message,
                  void *closure_data);
typedef void (*ChangeWindowSize_Closure)
                 (const ChangeWindowSize *message,
                  void *closure_data);
typedef void (*CommandSuspend_Closure)
                 (const CommandSuspend *message,
                  void *closure_data);
typedef void (*ServerMessage_Closure)
                 (const ServerMessage *message,
                  void *closure_data);
typedef void (*ServerHello_Closure)
                 (const ServerHello *message,
                  void *closure_data);

/* --- services --- */


/* --- descriptors --- */

extern const ProtobufCMessageDescriptor client_message__descriptor;
extern const ProtobufCMessageDescriptor time_spec__descriptor;
extern const ProtobufCMessageDescriptor io_buffer__descriptor;
extern const ProtobufCMessageDescriptor info_message__descriptor;
extern const ProtobufCMessageDescriptor info_message__string_list__descriptor;
extern const ProtobufCMessageDescriptor info_message__number_list__descriptor;
extern const ProtobufCMessageDescriptor accept_message__descriptor;
extern const ProtobufCMessageDescriptor reject_message__descriptor;
extern const ProtobufCMessageDescriptor exit_message__descriptor;
extern const ProtobufCMessageDescriptor alert_message__descriptor;
extern const ProtobufCMessageDescriptor restart_message__descriptor;
extern const ProtobufCMessageDescriptor change_window_size__descriptor;
extern const ProtobufCMessageDescriptor command_suspend__descriptor;
extern const ProtobufCMessageDescriptor server_message__descriptor;
extern const ProtobufCMessageDescriptor server_hello__descriptor;

PROTOBUF_C__END_DECLS


#endif  /* PROTOBUF_C_log_5fserver_2eproto__INCLUDED */
