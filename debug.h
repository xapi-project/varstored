#ifndef  _DEBUG_H
#define  _DEBUG_H

#define DBG(...)                            \
    do {                                    \
        fprintf(stderr, "%s: ", __func__);  \
        fprintf(stderr, __VA_ARGS__);       \
        fflush(stderr);                     \
    } while (0)

#endif  /* _DEBUG_H */

