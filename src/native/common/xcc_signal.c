// Copyright (c) 2019-present, iQIYI, Inc. All rights reserved.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//

// Created by caikelun on 2019-03-07.

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <inttypes.h>
#include <errno.h>
#include <signal.h>
#include <sys/syscall.h>
#include <android/log.h>
#include "xcc_signal.h"
#include "xcc_errno.h"
#include "xcc_libc_support.h"

#define XCC_SIGNAL_CRASH_STACK_SIZE (1024 * 128)

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wpadded"
typedef struct {
    int signum; // 信号字
    struct sigaction oldact;
} xcc_signal_crash_info_t;
#pragma clang diagnostic pop

/**
 * - 技术原理
 * 要想拦截 Native Crash，根本上是拦截C/C++层的Crash Signal(与Crash有关的信号字)
 * Naive崩溃捕获需要注册这些信号的处理函数(signal handler)，然后在信号处理函数中收集数据
 * 因为信号是以“中断”的方式出现的，可能中断任何CPU指令序列的执行，所以在信号处理函数中，只能调用“异步信号安全(
 * async-signal-safe)”的函数。例如malloc()、calloc()、free()、snprintf()、gettimeofday() 等等都是不能
 * 使用的，C++ STL / boost 也是不能使用的。所以，在信号处理函数中我们只能不分配堆内存，需要使用堆内存只能在初
 * 始化时预分配。如果要使用不在异步信号安全白名单中的libc/bionic函数，只能直接调用 system call 或者自己实现。
 *
 * 进程崩溃前的极端情况：
 * 当崩溃捕获逻辑开始运行时，会面对很多糟糕的情况，比如：栈溢出、堆内存不可用、虚拟内存地址耗尽、FD 耗尽、Flash
 * 空间耗尽等。有时，这些极端情况的出现，本身就是导致进程崩溃的间接原因。
 * 1、栈溢出
 * 我们需要预先用 sigaltstack() 为 signal handler 分配专门的栈内存空间，否则当遇到栈溢出时，signal handler
 * 将无法正常运行。
 * 2、虚拟内存地址耗尽
 * 内存泄露很容易导致虚拟内存地址耗尽(特别是在32位环境中)，这意味着在signal handler中也不能使用类似mmap()的调用。
 3、FD 耗尽
 * FD泄露是常见的导致进程崩溃的间接原因。这意味着在signal handler中无法正常的使用依赖于FD的操作，比如无法open()
 * + read()读取/proc中的各种信息。为了不干扰APP的正常运行，我们仅仅预留了一个FD，用于在崩溃时可靠的创建出“崩溃信
 * 息记录文件”。
 4、Flash 空间耗尽
 * 在16G/32G存储空间的安卓设备中，这种情况经常发生。这意味着signal handler无法把崩溃信息记录到本地文件中。我们只
 * 能尝试在初始化时预先创建一些“占坑”文件，然后一直循环使用这些“占坑”文件来记录崩溃信息。如果“占坑”文件也创建失败，
 * 我们需要把最重要的一些崩溃信息（比如 backtrace）保存在内存中，然后立刻回调和发送这些信息。
 *
 * - xCrash架构与实现(http://www.itpub.net/2020/02/07/5193/)
 * 信号处理函数与子进程
 * 在信号处理函数（signal handler）代码执行的开始阶段，我们只能“忍辱偷生”：
 * 1、遵守它的各种限制。
 * 2、不使用堆内存。
 * 3、自己实现需要的调用的“异步信号安全版本”，比如：snprintf()、gettimeofday()。
 * 4、必要时直接调用 system call。
 * 但这并非长久之计，我们要尽快在信号处理函数中执行“逃逸”，即使用clone() + execl()创建新的子进程，然后在子进程
 * 中继续收集崩溃信息。这样做的目的是：
 * 1、避开 async-signal-safe 的限制。
 * 2、避开虚拟内存地址耗尽的问题。
 * 3、避开 FD 耗尽的问题。
 * 4、使用ptrace() suspend崩溃进程中所有的线程。与iOS不同，Linux/Android不支持suspend本进程内的线程。（如果
 *   不做suspend，则其他未崩溃的线程还在继续执行，还在继续写logcat，当我们收集logcat时，崩溃时间点附近的logcat
 *   可能早已被淹没。类似的，其他的业务log buffers也存在被淹没的问题。）
 * 5、除了崩溃线程本身的registers、backtrace等，还能用ptrace()收集到进程中其他所有线程的registers、backtrace
 *   等信息，这对于某些崩溃问题的分析是有意义的。
 * 6、更安全的读取内存数据。（ptrace读数据失败会返回错误码，但是在崩溃线程内直接读内存数据，如果内存地址非法，会导
 *   致段错误）
 * xCrash 整体分为两部分：运行于崩溃的APP进程内的部分，和独立进程的部分（我们称为 dumper）。
 * （2）Native 部分：
 * ①JNI Bridge。负责与 Java 层的交互。（传参与回调）
 * ②Signal handlers。负责信号捕获，以及启动独立进程 dumper。
 * ③Fallback mode。负责当 dumper 捕获崩溃信息失败时，尝试在崩溃进行的 signal handler 中收集崩溃信息。
 *
 */
static xcc_signal_crash_info_t xcc_signal_crash_info[] = {
    // 调用abort()/kill()/tkill()/tgkill()自杀，或被其他进程通过kill()/tkill()/tgkill()他杀
    {.signum = SIGABRT},  // (用户态进程发出的)
    {.signum = SIGBUS},   // 错误的物理设备地址访问(kernel发出的信号)
    {.signum = SIGFPE},   // 除数为零(kernel发出的信号)
    {.signum = SIGILL},   // 无法识别的 CPU 指令(kernel发出的信号)
    {.signum = SIGSEGV},  // 错误的虚拟内存地址访问(kernel发出的信号)
    {.signum = SIGTRAP},  //
    {.signum = SIGSYS},   // 无法识别的系统调用(system call)(kernel发出的信号)
    {.signum = SIGSTKFLT} //
};

// 注册Crash信号字处理函数
int xcc_signal_crash_register(void (*handler) (int, siginfo_t*, void*)) {
    stack_t ss;

    if (NULL == (ss.ss_sp = calloc(1, XCC_SIGNAL_CRASH_STACK_SIZE))) {
        return XCC_ERRNO_NOMEM;
    }

    ss.ss_size  = XCC_SIGNAL_CRASH_STACK_SIZE;
    ss.ss_flags = 0;
    if (0 != sigaltstack(&ss, NULL)) {
        return XCC_ERRNO_SYS;
    }

    struct sigaction act;
    memset(&act, 0, sizeof(act));
    sigfillset(&act.sa_mask);
    act.sa_sigaction = handler;
    act.sa_flags = SA_RESTART | SA_SIGINFO | SA_ONSTACK;
    
    size_t i;
    size_t count = sizeof(xcc_signal_crash_info) / sizeof(xcc_signal_crash_info[0])
    for (i = 0; i < count; i++) {
        if (0 != sigaction(xcc_signal_crash_info[i].signum, &act, &(xcc_signal_crash_info[i].oldact))) {
            return XCC_ERRNO_SYS;
        }
    }

    return 0;
}

// 注销Crash信号字处理函数
int xcc_signal_crash_unregister(void) {
    int r = 0;
    size_t i;
    size_t count = sizeof(xcc_signal_crash_info) / sizeof(xcc_signal_crash_info[0])
    for (i = 0; i < count; i++) {
        if (0 != sigaction(xcc_signal_crash_info[i].signum, &(xcc_signal_crash_info[i].oldact), NULL)) {
            r = XCC_ERRNO_SYS;
        }
    }
    
    return r;
}

int xcc_signal_crash_ignore(void) {
    struct sigaction act;
    xcc_libc_support_memset(&act, 0, sizeof(act));
    sigemptyset(&act.sa_mask);
    act.sa_handler = SIG_DFL;
    act.sa_flags = SA_RESTART;
    
    int r = 0;
    size_t i;
    size_t count = sizeof(xcc_signal_crash_info) / sizeof(xcc_signal_crash_info[0])
    for (i = 0; i < count; i++) {
        if (0 != sigaction(xcc_signal_crash_info[i].signum, &act, NULL)) {
            r = XCC_ERRNO_SYS;
        }
    }

    return r;
}

int xcc_signal_crash_queue(siginfo_t* si) {
    if (SIGABRT == si->si_signo || SI_FROMUSER(si)) {
        if (0 != syscall(SYS_rt_tgsigqueueinfo, getpid(), gettid(), si->si_signo, si)) {
            return XCC_ERRNO_SYS;
        }
    }

    return 0;
}

static sigset_t xcc_signal_trace_oldset;
static struct sigaction xcc_signal_trace_oldact;

int xcc_signal_trace_register(void (*handler) (int, siginfo_t*, void*)) {
    int              r;
    sigset_t         set;
    struct sigaction act;

    //un-block the SIGQUIT mask for current thread, hope this is the main thread
    sigemptyset(&set);
    sigaddset(&set, SIGQUIT);
    if (0 != (r = pthread_sigmask(SIG_UNBLOCK, &set, &xcc_signal_trace_oldset))) {
        return r;
    }

    //register new signal handler for SIGQUIT
    memset(&act, 0, sizeof(act));
    sigfillset(&act.sa_mask);
    act.sa_sigaction = handler;
    act.sa_flags = SA_RESTART | SA_SIGINFO;
    if (0 != sigaction(SIGQUIT, &act, &xcc_signal_trace_oldact)) {
        pthread_sigmask(SIG_SETMASK, &xcc_signal_trace_oldset, NULL);
        return XCC_ERRNO_SYS;
    }

    return 0;
}

void xcc_signal_trace_unregister(void) {
    pthread_sigmask(SIG_SETMASK, &xcc_signal_trace_oldset, NULL);
    sigaction(SIGQUIT, &xcc_signal_trace_oldact, NULL);
}
