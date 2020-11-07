// SPDX-License-Identifier: GPL-1.0+
/*
 * tty_status.c --- implements VSTATUS and TIOCSTAT from BSD4.3/4.4
 *
 */
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/tty.h>
#include <linux/sched/cputime.h>
#include <linux/sched/loadavg.h>
#include <linux/pid.h>
#include <linux/slab.h>
#include <linux/math64.h>

inline unsigned long getRSS(struct mm_struct *mm)
{
	if (mm == NULL) {
		return 0;
	}
	return get_mm_rss(mm);
}

struct task_struct *compare(struct task_struct *new, struct task_struct *prior)
{
	if (new == NULL && prior == NULL) {
		BUG();
	}

	if (new == NULL) {
		return prior;
	}

	if (prior == NULL) {
		return new;
	}

	/* Skip exiting threads */
	if (new->exit_state == EXIT_ZOMBIE) {
		return prior;
	}

	/* Is only one runnable? */
	if (new->state & TASK_RUNNING)
		return new;
	else if (prior->state & TASK_RUNNING)
		return prior;
	
	/* Is one of them a kernel thread? */
	if (!(new->flags & PF_KTHREAD))
		return new;
	else if (!(prior->flags & PF_KTHREAD))
		return prior;

	/* Is one of them actually on a cpu now-ish? */
	if (task_curr(new))
		return new;
	else if (task_curr(prior))
		return prior;

	/* Break the tie. */
	if (new->start_time > prior->start_time) {
		return new;
	}

	return prior;
}
		
struct task_struct *pick_process(struct pid *pgrp)
{
	struct task_struct *p, *winner = NULL;

	do_each_pid_task(pgrp, PIDTYPE_PGID, p) {
		winner = compare(p, winner);
	} while_each_pid_task(pgrp, PIDTYPE_PGID, p);

	return winner;
}

/*
 * Fixup the timespecs tv_nsec field so it's ready to print out.
 */
inline long nstoms(long l)
{
	l /= NSEC_PER_MSEC;
	if (l > 99)
		l /= 10;
	return l;
}

int tty_status(struct tty_struct *tty)
{

#define MSGLEN 80
#define REMAINING ((MSGLEN) - (c - (char *) &msg) - 3)

	char msg[MSGLEN], tname[TASK_COMM_LEN], *c;
	unsigned long loadavg[3];
	uint64_t pcpu, wallclock;
	struct task_struct *p;
	struct rusage rusage;
	struct timespec64 utime, stime, rtime;

	if (tty == NULL) 
		return -ENOTTY;

	c = (char *) &msg;

	get_avenrun(loadavg, FIXED_1/200, 0);
	c += scnprintf(c, REMAINING, "load: %lu.%02lu ", 
		       LOAD_INT(loadavg[0]), LOAD_FRAC(loadavg[0]));

	if (tty->session == NULL) {
		c += scnprintf(c, REMAINING, "not a controlling terminal"); 
		goto print;
	}

	if (tty->pgrp == NULL) {
		c += scnprintf(c, REMAINING, "no foreground process group"); 
		goto print;
	}

	p = pick_process(tty->pgrp);
	if (p == NULL) {
		c += scnprintf(c, REMAINING, "empty foreground process group");
		goto print;
	}

	get_task_comm(tname, p);
	c += scnprintf(c, REMAINING, " cmd: %s %d [%s] ", tname, task_pid_vnr(p),
		       (char *)get_task_state_name(p));

	getrusage(p, RUSAGE_BOTH, &rusage);
	/* Convert kernel_old_timeval to timespec64. */
	utime.tv_sec = rusage.ru_utime.tv_sec;
	utime.tv_nsec = rusage.ru_utime.tv_usec * NSEC_PER_USEC;
	stime.tv_sec = rusage.ru_stime.tv_sec;
	stime.tv_nsec = rusage.ru_stime.tv_usec * NSEC_PER_USEC;

	wallclock = ktime_get_ns() - p->start_time;
	rtime = ns_to_timespec64(wallclock);

	/* Estimate %CPU */
	pcpu = div64_u64((timespec64_to_ns(&utime) + timespec64_to_ns(&stime)) * 100,
			 wallclock);
	
	/* rtime, utime, stime, %cpu, rss */
	c += scnprintf(c, REMAINING, 
		       "%llu.%02lur %llu.%02luu %llu.%02lus %llu%% %luk",
		       rtime.tv_sec, nstoms(rtime.tv_nsec),
		       utime.tv_sec, nstoms(utime.tv_nsec),
		       stime.tv_sec, nstoms(stime.tv_nsec),
		       pcpu, getRSS(p->mm));
print:
	c += scnprintf(c, REMAINING, "\r\n");
	*c = 0;
	tty_write_message(tty, msg);
	return 0;
}

