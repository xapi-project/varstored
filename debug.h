#ifndef  _DEBUG_H
#define  _DEBUG_H

enum log_level {
    LOG_LVL_ERROR,
    LOG_LVL_WARN,
    LOG_LVL_INFO,
    LOG_LVL_DEBUG,
};

extern enum log_level log_level;

#define ERR(...)                                \
    do {                                        \
        if (log_level >= LOG_LVL_ERROR) {       \
            fprintf(stderr, "%s: ", __func__);  \
            fprintf(stderr, __VA_ARGS__);       \
            fflush(stderr);                     \
        }                                       \
    } while (0)

#define WARN(...)                               \
    do {                                        \
        if (log_level >= LOG_LVL_WARN) {        \
            fprintf(stderr, "%s: ", __func__);  \
            fprintf(stderr, __VA_ARGS__);       \
            fflush(stderr);                     \
        }                                       \
    } while (0)

#define INFO(...)                               \
    do {                                        \
        if (log_level >= LOG_LVL_INFO) {        \
            printf("%s: ", __func__);           \
            printf(__VA_ARGS__);                \
            fflush(stdout);                     \
        }                                       \
    } while (0)

#define DBG(...)                                \
    do {                                        \
        if (log_level >= LOG_LVL_DEBUG) {       \
            printf("%s: ", __func__);           \
            printf(__VA_ARGS__);                \
            fflush(stdout);                     \
        }                                       \
    } while (0)

#endif  /* _DEBUG_H */

