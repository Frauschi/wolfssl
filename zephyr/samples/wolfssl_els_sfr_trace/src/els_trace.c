/* Records ELS register accesses into RAM and prints them afterwards. Nothing
 * is printed while crypto is running: the UART is far slower than the engine
 * and would change the timing being observed. */
#include <zephyr/kernel.h>
#include <stdint.h>
#include <stdio.h>

#include "els_trace.h"

#define TRACE_MAX 16384

struct rec {
    const char *name;
    uint32_t val;
    char op;
};

static struct rec recs[TRACE_MAX];
static uint32_t nrec;
static int armed;

void els_trace_rec(char op, const char *name, uint32_t val)
{
    if (!armed || nrec >= TRACE_MAX) {
        return;
    }
    recs[nrec].op = op;
    recs[nrec].name = name;
    recs[nrec].val = val;
    nrec++;
}

void els_trace_arm(int on)
{
    armed = on;
}

void els_trace_mark(const char *label)
{
    els_trace_rec('M', label, 0);
}

void els_trace_dump(void)
{
    uint32_t i;

    printk("TRACE-BEGIN %u\n", (unsigned)nrec);
    for (i = 0; i < nrec; ++i) {
        if (recs[i].op == 'M') {
            printk("M %s\n", recs[i].name);
        }
        else {
            printk("%c %s %08x\n", recs[i].op, recs[i].name,
                   (unsigned)recs[i].val);
        }
    }
    printk("TRACE-END\n");
}
