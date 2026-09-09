#ifndef ELS_TRACE_H
#define ELS_TRACE_H
#include <stdint.h>
void els_trace_rec(char op, const char *name, uint32_t val);
void els_trace_arm(int on);
void els_trace_mark(const char *label);
void els_trace_dump(void);
#endif
