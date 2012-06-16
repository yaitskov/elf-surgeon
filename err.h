#ifndef __ERR_H_
#define __ERR_H_

#define notz(expr, msg, ...)                    \
  if (!(expr)) {  \
    fprintf(stderr, "file '%s'; func '%s'; line %d:\ncode: %s\nmessage: ", \
              __FILE__, __func__, __LINE__, #expr); \
    fprintf(stderr, msg, ##__VA_ARGS__);             \
       exit(1); }

#define ntz(expr, msg)      \
  if (!(expr)) {  \
       fprintf(stderr, "file '%s'; func '%s'; line %d:\ncode: %s\nmessage: %s\n", \
              __FILE__, __func__, __LINE__, #expr, msg); \
       exit(1); }

#define nz(expr) \
  if (!(expr)) {  \
       fprintf(stderr, "file '%s'; func '%s'; line %d:\ncode: %s\n", \
              __FILE__, __func__, __LINE__, #expr); \
       exit(1); }

#define oops(expect, expr, msg, ...)                \
  { \
     int __got = (expr); \
     if ((expect) != __got) { \
       fprintf(stderr, "file '%s'; func '%s'; line %d: expected %d but got %d\ncode: %s\nmessage: ", \
              __FILE__, __func__, __LINE__, expect, __got, #expr); \
       fprintf(stderr, msg, ##__VA_ARGS__);                                    \
       exit(1); } }

#define ops(expect, expr, msg) \
  { \
     int __got = (expr); \
     if ((expect) != __got) { \
       fprintf(stderr, "file '%s'; func '%s'; line %d: expected %d but got %d\ncode: %s\nmessage: %s\n", \
              __FILE__, __func__, __LINE__, expect, __got, #expr, msg);  \
       exit(1); } }

#define check_input(expr, msg, ...)              \
  if (!(expr)) {                                 \
     fprintf(stderr, msg, ##__VA_ARGS__);        \
     exit(1);                                    \
  }

#define info_user(expr, msg, ...) \
  if (!(expr)) {                                 \
     fprintf(stderr, msg, ##__VA_ARGS__);        \
  }

#endif


