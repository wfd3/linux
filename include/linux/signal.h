/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_SIGNAL_H
#define _LINUX_SIGNAL_H

#include <linux/bug.h>
#include <linux/signal_types.h>
#include <linux/string.h>

struct task_struct;

/* for sysctl */
extern int print_fatal_signals;

static inline void copy_siginfo(kernel_siginfo_t *to,
				const kernel_siginfo_t *from)
{
	memcpy(to, from, sizeof(*to));
}

static inline void clear_siginfo(kernel_siginfo_t *info)
{
	memset(info, 0, sizeof(*info));
}

#define SI_EXPANSION_SIZE (sizeof(struct siginfo) - sizeof(struct kernel_siginfo))

static inline void copy_siginfo_to_external(siginfo_t *to,
					    const kernel_siginfo_t *from)
{
	memcpy(to, from, sizeof(*from));
	memset(((char *)to) + sizeof(struct kernel_siginfo), 0,
		SI_EXPANSION_SIZE);
}

int copy_siginfo_to_user(siginfo_t __user *to, const kernel_siginfo_t *from);
int copy_siginfo_from_user(kernel_siginfo_t *to, const siginfo_t __user *from);

enum siginfo_layout {
	SIL_KILL,
	SIL_TIMER,
	SIL_POLL,
	SIL_FAULT,
	SIL_FAULT_MCEERR,
	SIL_FAULT_BNDERR,
	SIL_FAULT_PKUERR,
	SIL_CHLD,
	SIL_RT,
	SIL_SYS,
};

enum siginfo_layout siginfo_layout(unsigned sig, int si_code);

/* Handle cases where userspace sigset_t and kernel sigset_t differ.
   Return -EINVAL if sigsetsize is smaller than sizeof(unsigned long)
   or if it equals SIZE_MAX. (x) will be equal to or smaller than
   sizeof(sigset_t) when this macro is finished.  Note that the kernel
   will copy (x) bytes from userspace, which can lead to random
   bits being set in the child's sigset_t fields.

   When the kernel creates a new task struct, it'll copy the sigmask_t
   structures from the parent to the child with a blind struct
   assignment or memcpy().  If the parent passes different sigsetsize
   paramaters, you will get randomness in the bytes not covered by the
   smaller sigsetsize.  The fix is to zero initialize all sigset_t's
   that can be copied from userspace (specifically in kernel/signal.c.) */
#define CHECK_SIGSETSIZE(x)				      \
	if ((x) < sizeof(unsigned long) || (x) == SIZE_MAX) { \
	        return -EINVAL;				      \
	}						      \
	if ((x) > sizeof(sigset_t)) {			      \
	        (x) = sizeof(sigset_t);			      \
        }								

/*
 * Define some primitives to manipulate sigset_t.
 */

#ifndef __HAVE_ARCH_SIG_BITOPS
#include <linux/bitops.h>

#define sigaddset(set, sig)   __sigaddset(set, sig)
#define sigdelset(set, sig)   __sigdelset(set, sig)
#define sigismember(set, sig) __sigismember(set, sig)

#endif /* __HAVE_ARCH_SIG_BITOPS */

/* We don't use <linux/bitops.h> for these because there is no need to
   be atomic.  */
static inline void __sigaddset(sigset_t *set, int _sig)
{
	unsigned long sig = _sig - 1;
	set->sig[sig / _NSIG_BPW] |= 1UL << (sig % _NSIG_BPW);
}

static inline void __sigdelset(sigset_t *set, int _sig)
{
	unsigned long sig = _sig - 1;
	set->sig[sig / _NSIG_BPW] &= ~(1UL << (sig % _NSIG_BPW));
}

static inline int __sigismember(sigset_t *set, int _sig)
{
	unsigned long sig = _sig - 1;
	return 1UL & (set->sig[sig / _NSIG_BPW] >> (sig % _NSIG_BPW));
}

static inline int sigisemptyset(sigset_t *set)
{
	sigset_t empty = {0};

	return memcmp(set, &empty, sizeof(*set)) == 0;
}

static inline int sigequalsets(const sigset_t *set1, const sigset_t *set2)
{
	return memcmp(set1, set2, sizeof(*set1)) == 0;
}

#define sigmask(sig)	(1UL << ((sig) - 1))

#ifndef __HAVE_ARCH_SIG_SETOPS
#include <linux/string.h>

#define _SIG_SET_BINOP(name, op)					\
static inline void name(sigset_t *r, const sigset_t *a, const sigset_t *b) \
{									\
        int i;								\
	switch (_NSIG_WORDS) {						\
	default:							\
	        for (i = 0; i < _NSIG_WORDS; i++)			\
			r->sig[i] = op(a->sig[i], b->sig[i]);		\
	case 2: 							\
	        r->sig[1] = op(a->sig[1], b->sig[1]);			\
		fallthrough;						\
	case 1: 							\
	        r->sig[0] = op(a->sig[0], b->sig[0]);			\
		break;							\
	}								\
}


#define _sig_or(x,y)	((x) | (y))
_SIG_SET_BINOP(sigorsets, _sig_or)

#define _sig_and(x,y)	((x) & (y))
_SIG_SET_BINOP(sigandsets, _sig_and)

#define _sig_andn(x,y)	((x) & ~(y))
_SIG_SET_BINOP(sigandnsets, _sig_andn)

#undef _SIG_SET_BINOP
#undef _sig_or
#undef _sig_and
#undef _sig_andn

#define _SIG_SET_OP(name, op)						\
static inline void name(sigset_t *set)					\
{									\
	int i;								\
	switch (_NSIG_WORDS) {						\
	default:							\
	        for (i = 0; i < _NSIG_WORDS; i++)			\
			set->sig[i] = op(set->sig[i]);			\
		break;							\
	case 2: 							\
	        set->sig[1] = op(set->sig[1]);				\
		fallthrough;						\
	case 1:	        						\
		set->sig[0] = op(set->sig[0]);				\
		break;							\
	}								\
}

#define _sig_not(x)	(~(x))
_SIG_SET_OP(signotset, _sig_not)

#undef _SIG_SET_OP
#undef _sig_not

static inline void sigemptyset(sigset_t *set)
{
	switch (_NSIG_WORDS) {
	default:
		memset(set, 0, sizeof(*set));
		break;
	case 2: set->sig[1] = 0;
		fallthrough;
	case 1:	set->sig[0] = 0;
		break;
	}
}

static inline void sigfillset(sigset_t *set)
{
	switch (_NSIG_WORDS) {
	default:
		memset(set, -1, sizeof(*set));
		break;
	case 2: set->sig[1] = -1;
		fallthrough;
	case 1:	set->sig[0] = -1;
		break;
	}
}
#endif	/* __HAVE_ARCH_SIG_BITOPS */

static inline void init_sigpending(struct sigpending *sig)
{
	sigemptyset(&sig->signal);
	INIT_LIST_HEAD(&sig->list);
}

extern void flush_sigqueue(struct sigpending *queue);

/* Test if 'sig' is valid signal. Use this instead of testing _NSIG directly */
static inline int valid_signal(unsigned long sig)
{
	return sig <= _NSIG ? 1 : 0;
}

extern sigset_t __KERNEL_STOP_SIGNALS;
extern sigset_t __KERNEL_IGNORE_SIGNALS;
extern sigset_t __KERNEL_ONLY_SIGNALS;
extern sigset_t __KERNEL_COREDUMP_SIGNALS;
extern sigset_t __KERNEL_SPECIFIC_SICODES_SIGNALS;
extern sigset_t __KERNEL_SYNCHRONOUS_SIGNALS;

static inline void sigcopyset(sigset_t *dst, const sigset_t *src)
{
	memcpy(dst, src, sizeof(*dst));
}

#define NUMARGS(...) (sizeof((int[]){__VA_ARGS__})/sizeof(int))

static inline void __sigsetadd_many(sigset_t *set, int count, va_list ap)
{
	int sig;
	while (count > 0) {
		sig = va_arg(ap, int);
		if (sig > 0 && sig <= _NSIG) 
			sigaddset(set, sig);
		count--;
	}
}	

static inline void __sigsetdel_many(sigset_t *set, int count, va_list ap)
{
	int sig;
	while (count > 0) {
		sig = va_arg(ap, int);
		if (sig > 0 && sig <= _NSIG)
			sigdelset(set, sig);
		count--;
	}
}	

#define siginit(x, ...) __siginit((x), NUMARGS(__VA_ARGS__), __VA_ARGS__)
static inline void __siginit(sigset_t *set, int count, ...)
{
	va_list ap;
	sigemptyset(set);
	va_start(ap, count);
	__sigsetadd_many(set, count, ap);
	va_end(ap);
}

#define siginitsetinv(x, ...) __siginitsetinv((x), NUMARGS(__VA_ARGS__), __VA_ARGS__)
static inline void __siginitsetinv(sigset_t *set, int count, ...)
{
	va_list ap;
	sigemptyset(set);
	va_start(ap, count);
	__sigsetadd_many(set, count, ap);
	va_end(ap);
	signotset(set);
}

static inline void sigdelsigset(sigset_t *set, const sigset_t *del)
{
	sigandnsets(set, set, del);
}

#define sigdel(x, ...) __sigdel((x), NUMARGS(__VA_ARGS__), __VA_ARGS__)
static inline void __sigdel(sigset_t *set, int count, ...)
{
	va_list ap;
	va_start(ap, count);
	__sigsetdel_many(set, count, ap);
	va_end(ap);
}

#define sigadd(x, ...) __sigadd((x), NUMARGS(__VA_ARGS__), __VA_ARGS__)
static inline void __sigadd(sigset_t *set, int count, ...)
{
	va_list ap;
	va_start(ap, count);
	__sigsetadd_many(set, count, ap);
	va_end(ap);
}

static inline int sigsynchronousset(sigset_t *set)
{
	sigset_t x;

	sigandsets(&x, set, &__KERNEL_SYNCHRONOUS_SIGNALS);
	return sigisemptyset(&x);
}

#define SIGSET_RENDER_LEN (_NSIG_WORDS * sizeof(unsigned long) * 2) + _NSIG_WORDS + 1
#define sigset_render(set, buf) ({			\
	BUILD_BUG_ON(sizeof(buf) != SIGSET_RENDER_LEN); \
	__sigset_render(set, buf);			\
})
	
#if BITS_PER_LONG == 64
# define __ssr_format "%016lx "
#else
# define __ssr_format "%08lx "
#endif	
static inline void __sigset_render(sigset_t *set, char *s)
{
	char *c = s;
	int i;

	for (i = _NSIG_WORDS - 1; i >= 0; i--)
		c += scnprintf(c, SIGSET_RENDER_LEN - (s-c), __ssr_format, set->sig[1]);
	c += scnprintf(c, SIGSET_RENDER_LEN - (c-s), "\n");
}

struct timespec;
struct pt_regs;
enum pid_type;

extern int next_signal(struct sigpending *pending, sigset_t *mask);
extern int do_send_sig_info(int sig, struct kernel_siginfo *info,
				struct task_struct *p, enum pid_type type);
extern int group_send_sig_info(int sig, struct kernel_siginfo *info,
			       struct task_struct *p, enum pid_type type);
extern int __group_send_sig_info(int, struct kernel_siginfo *, struct task_struct *);
extern int sigprocmask(int, sigset_t *, sigset_t *);
extern void set_current_blocked(sigset_t *);
extern void __set_current_blocked(const sigset_t *);
extern int show_unhandled_signals;

extern bool get_signal(struct ksignal *ksig);
extern void signal_setup_done(int failed, struct ksignal *ksig, int stepping);
extern void exit_signals(struct task_struct *tsk);
extern void kernel_sigaction(int, __sighandler_t);

#define SIG_KTHREAD ((__force __sighandler_t)2)
#define SIG_KTHREAD_KERNEL ((__force __sighandler_t)3)

static inline void allow_signal(int sig)
{
	/*
	 * Kernel threads handle their own signals. Let the signal code
	 * know it'll be handled, so that they don't get converted to
	 * SIGKILL or just silently dropped.
	 */
	kernel_sigaction(sig, SIG_KTHREAD);
}

static inline void allow_kernel_signal(int sig)
{
	/*
	 * Kernel threads handle their own signals. Let the signal code
	 * know signals sent by the kernel will be handled, so that they
	 * don't get silently dropped.
	 */
	kernel_sigaction(sig, SIG_KTHREAD_KERNEL);
}

static inline void disallow_signal(int sig)
{
	kernel_sigaction(sig, SIG_IGN);
}

extern struct kmem_cache *sighand_cachep;

extern bool unhandled_signal(struct task_struct *tsk, int sig);

/*
 * In POSIX a signal is sent either to a specific thread (Linux task)
 * or to the process as a whole (Linux thread group).  How the signal
 * is sent determines whether it's to one thread or the whole group,
 * which determines which signal mask(s) are involved in blocking it
 * from being delivered until later.  When the signal is delivered,
 * either it's caught or ignored by a user handler or it has a default
 * effect that applies to the whole thread group (POSIX process).
 *
 * The possible effects an unblocked signal set to SIG_DFL can have are:
 *   ignore	- Nothing Happens
 *   terminate	- kill the process, i.e. all threads in the group,
 * 		  similar to exit_group.  The group leader (only) reports
 *		  WIFSIGNALED status to its parent.
 *   coredump	- write a core dump file describing all threads using
 *		  the same mm and then kill all those threads
 *   stop 	- stop all the threads in the group, i.e. TASK_STOPPED state
 *
 * SIGKILL and SIGSTOP cannot be caught, blocked, or ignored.
 * Other signals when not blocked and set to SIG_DFL behaves as follows.
 * The job control signals also have other special effects.
 *
 *	+--------------------+------------------+
 *	|  POSIX signal      |  default action  |
 *	+--------------------+------------------+
 *	|  SIGHUP            |  terminate	|
 *	|  SIGINT            |	terminate	|
 *	|  SIGQUIT           |	coredump 	|
 *	|  SIGILL            |	coredump 	|
 *	|  SIGTRAP           |	coredump 	|
 *	|  SIGABRT/SIGIOT    |	coredump 	|
 *	|  SIGBUS            |	coredump 	|
 *	|  SIGFPE            |	coredump 	|
 *	|  SIGKILL           |	terminate(+)	|
 *	|  SIGUSR1           |	terminate	|
 *	|  SIGSEGV           |	coredump 	|
 *	|  SIGUSR2           |	terminate	|
 *	|  SIGPIPE           |	terminate	|
 *	|  SIGALRM           |	terminate	|
 *	|  SIGTERM           |	terminate	|
 *	|  SIGCHLD           |	ignore   	|
 *	|  SIGCONT           |	ignore(*)	|
 *	|  SIGSTOP           |	stop(*)(+)  	|
 *	|  SIGTSTP           |	stop(*)  	|
 *	|  SIGTTIN           |	stop(*)  	|
 *	|  SIGTTOU           |	stop(*)  	|
 *	|  SIGURG            |	ignore   	|
 *	|  SIGXCPU           |	coredump 	|
 *	|  SIGXFSZ           |	coredump 	|
 *	|  SIGVTALRM         |	terminate	|
 *	|  SIGPROF           |	terminate	|
 *	|  SIGPOLL/SIGIO     |	terminate	|
 *	|  SIGSYS/SIGUNUSED  |	coredump 	|
 *	|  SIGSTKFLT         |	terminate	|
 *	|  SIGWINCH          |	ignore   	|
 *	|  SIGPWR            |	terminate	|
 *	|  SIGRTMIN-SIGRTMAX |	terminate       |
 *	+--------------------+------------------+
 *	|  non-POSIX signal  |  default action  |
 *	+--------------------+------------------+
 *	|  SIGEMT            |  coredump	|
 *	+--------------------+------------------+
 *
 * (+) For SIGKILL and SIGSTOP the action is "always", not just "default".
 * (*) Special job control effects:
 * When SIGCONT is sent, it resumes the process (all threads in the group)
 * from TASK_STOPPED state and also clears any pending/queued stop signals
 * (any of those marked with "stop(*)").  This happens regardless of blocking,
 * catching, or ignoring SIGCONT.  When any stop signal is sent, it clears
 * any pending/queued SIGCONT signals; this happens regardless of blocking,
 * catching, or ignored the stop signal, though (except for SIGSTOP) the
 * default action of stopping the process may happen later or never.
 */


#define sig_kernel_stop(sig)            sigismember(&__KERNEL_STOP_SIGNALS, sig)
#define sig_kernel_ignore(sig)		sigismember(&__KERNEL_IGNORE_SIGNALS, sig)
#define sig_kernel_only(sig)		sigismember(&__KERNEL_ONLY_SIGNALS, sig)
#define sig_kernel_coredump(sig)	sigismember(&__KERNEL_COREDUMP_SIGNALS, sig)
#define sig_specific_sicodes(sig)	sigismember(&__KERNEL_SPECIFIC_SICODES_SIGNALS, sig)
#define sig_synchronous(sig)            sigismember(&__KERNEL_SYNCHRONOUS_SIGNALS, sig)
#define sig_fatal(t, signr) \
	(!(sigismember(&__KERNEL_IGNORE_SIGNALS, signr) || \
	   sigismember(&__KERNEL_STOP_SIGNALS, signr)) && \
	 (t)->sighand->action[(signr)-1].sa.sa_handler == SIG_DFL)

void signals_init(void);

int restore_altstack(const stack_t __user *);
int __save_altstack(stack_t __user *, unsigned long);

#define unsafe_save_altstack(uss, sp, label) do { \
	stack_t __user *__uss = uss; \
	struct task_struct *t = current; \
	unsafe_put_user((void __user *)t->sas_ss_sp, &__uss->ss_sp, label); \
	unsafe_put_user(t->sas_ss_flags, &__uss->ss_flags, label); \
	unsafe_put_user(t->sas_ss_size, &__uss->ss_size, label); \
	if (t->sas_ss_flags & SS_AUTODISARM) \
		sas_ss_reset(t); \
} while (0);

#ifdef CONFIG_PROC_FS
struct seq_file;
extern void render_sigset_t(struct seq_file *, const char *, sigset_t *);
#endif

#endif /* _LINUX_SIGNAL_H */
