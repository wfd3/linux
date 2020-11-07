/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_X86_SIGNAL_H
#define _ASM_X86_SIGNAL_H

#ifndef __ASSEMBLY__
#include <linux/linkage.h>

/* Most things should be clean enough to redefine this at will, if care
   is taken to make libc match.  */

#define _NSIG		64

#ifdef __i386__
# define _NSIG_BPW	32
#else
# define _NSIG_BPW	64
#endif

/* Round up when needed */
#define _NSIG_WORDS	((_NSIG + _NSIG_BPW - 1) / _NSIG_BPW)

typedef unsigned long old_sigset_t;		/* at least 32 bits */

typedef struct {
	unsigned long sig[_NSIG_WORDS];
} sigset_t;

/* non-uapi in-kernel SA_FLAGS for those indicates ABI for a signal frame */
#define SA_IA32_ABI	0x02000000u
#define SA_X32_ABI	0x01000000u

#ifndef CONFIG_COMPAT
typedef sigset_t compat_sigset_t;
#endif

#endif /* __ASSEMBLY__ */
#include <uapi/asm/signal.h>
#ifndef __ASSEMBLY__

#define __ARCH_HAS_SA_RESTORER

#include <asm/asm.h>
#include <uapi/asm/sigcontext.h>

#define __HAVE_ARCH_SIG_BITOPS

#define sigaddset(set,sig)		    \
	(__builtin_constant_p(sig)	    \
	 ? __sigaddset((set), (sig))  \
	 : __gen_sigaddset((set), (sig)))

static inline void __gen_sigaddset(sigset_t *set, int _sig)
{
	asm("btsl %1,%0" : "+m"(*set) : "Ir"(_sig - 1) : "cc");
}

#define sigdelset(set, sig)		    \
	(__builtin_constant_p(sig)	    \
	 ? __sigdelset((set), (sig))	    \
	 : __gen_sigdelset((set), (sig)))

static inline void __gen_sigdelset(sigset_t *set, int _sig)
{
	asm("btrl %1,%0" : "+m"(*set) : "Ir"(_sig - 1) : "cc");
}

static inline int __gen_sigismember(sigset_t *set, int _sig)
{
	bool ret;
	asm("btl %2,%1" CC_SET(c)
	    : CC_OUT(c) (ret) : "m"(*set), "Ir"(_sig-1));
	return ret;
}

#define sigismember(set, sig)			\
	(__builtin_constant_p(sig)		\
	 ? __sigismember((set), (sig))		\
	 : __gen_sigismember((set), (sig)))

struct pt_regs;

#endif /* __ASSEMBLY__ */
#endif /* _ASM_X86_SIGNAL_H */
