#!/usr/bin/python
# @lint-avoid-python-3-compatibility-imports
#
# kvmstats KVM-related stats (guest runtime and exit rate by reason)
#          For Linux, uses BCC, eBPF.
#
# USAGE: kvmstats.py [-h] [-C] [-r MAXROWS] [interval] [count]
#
# This uses in-kernel eBPF maps to store per process summaries for efficiency.
#
# Copyright 2019 DigitalOcean
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 27-Feb-2019   Julien Desfossez

from __future__ import print_function
from bcc import BPF
from time import sleep, strftime
from datetime import datetime
import argparse
import signal
from subprocess import call, check_output

# arguments
examples = """examples:
    ./kvmstats            # file I/O top, 1 second refresh
    ./kvmstats -C         # don't clear the screen
    ./kvmstats -p 181     # PID 181 only
    ./kvmstats 5          # 5 second summaries
    ./kvmstats 5 10       # 5 second summaries, 10 times only
"""
parser = argparse.ArgumentParser(
    description="KVM stats by VM",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-C", "--noclear", action="store_true",
    help="don't clear the screen")
parser.add_argument("-z", "--zero", action="store_true",
    help="Zero stats after each output")
parser.add_argument("-r", "--maxrows", default=20,
    help="maximum rows to print, default 20")
parser.add_argument("-p", "--pid", type=int, metavar="PID", dest="tgid",
    help="trace this PID only")
parser.add_argument("interval", nargs="?", default=1,
    help="output interval, in seconds, -1 to only output on Ctrl+c")
parser.add_argument("count", nargs="?", default=99999999,
    help="number of outputs")
parser.add_argument("--ebpf", action="store_true",
    help=argparse.SUPPRESS)
args = parser.parse_args()
interval = int(args.interval)
if interval == -1:
    interval = 99999999
countdown = int(args.count)
maxrows = int(args.maxrows)
clear = not int(args.noclear)
debug = 0

exit_reasons = [ 'EXCEPTION_NMI', 'EXTERNAL_INTERRUPT', 'TRIPLE_FAULT', '', '', '', '',
            'PENDING_INTERRUPT', 'NMI_WINDOW', 'TASK_SWITCH', 'CPUID', '', 'HLT', 'INVD',
            'INVLPG', 'RDPMC', 'RDTSC', '', 'VMCALL', 'VMCLEAR', 'VMLAUNCH', 'VMPTRLD',
            'VMPTRST', 'VMREAD', 'VMRESUME', 'VMWRITE', 'VMOFF', 'VMON', 'CR_ACCESS',
            'DR_ACCESS', 'IO_INSTRUCTION', 'MSR_READ', 'MSR_WRITE', 'INVALID_STATE', 'MSR_LOAD_FAIL',
            '', 'MWAIT_INSTRUCTION', 'MONITOR_TRAP_FLAG', '', 'MONITOR_INSTRUCTION', 'PAUSE_INSTRUCTION',
            'MCE_DURING_VMENTRY', '', 'TPR_BELOW_THRESHOLD', 'APIC_ACCESS', 'EOI_INDUCED', 'GDTR_IDTR',
            'LDTR_TR', 'EPT_VIOLATION', 'EPT_MISCONFIG', 'INVEPT', 'RDTSCP', 'PREEMPTION_TIMER',
            'INVVPID', 'WBINVD', 'XSETBV ', 'APIC_WRITE', 'RDRAND', 'INVPCID', 'VMFUNC', 'ENCLS',
            'RDSEED', 'PML_FULL', 'XSAVES', 'XRSTORS']

# define BPF program
bpf_text = """
#define MAX_KVM_EXIT_REASONS 64

struct vm_stats_t {
    u64 total_runtime;
    u32 reasons_count[MAX_KVM_EXIT_REASONS];
};

struct per_cpu_status_t {
    u64 last_kvm_entry;
};

struct msr_stats_key_t {
    u32 tgid;
    u32 ecx;
};

struct msr_stats_t {
    u32 count;
};

BPF_HASH(vm_stats, u32, struct vm_stats_t);
BPF_HASH(per_cpu_status, u32, struct per_cpu_status_t);
BPF_HASH(vm_msr_stats, struct msr_stats_key_t, struct msr_stats_t);

TRACEPOINT_PROBE(kvm, kvm_entry) {
    struct per_cpu_status_t *cpu_status, cpu_zero = {};
    u32 cpu = bpf_get_smp_processor_id();
    u64 ts = bpf_ktime_get_ns();
    u32 tgid = bpf_get_current_pid_tgid() >> 32;

    if (TGID_FILTER)
        return 0;

    cpu_status = per_cpu_status.lookup_or_init(&cpu, &cpu_zero);
    if (!cpu_status)
        return 0;
    cpu_status->last_kvm_entry = ts;

    return 0;
}

TRACEPOINT_PROBE(kvm, kvm_exit) {
    struct per_cpu_status_t *cpu_status, cpu_zero = {};
    u32 cpu = bpf_get_smp_processor_id();
    u64 ts = bpf_ktime_get_ns();
    u32 tgid = bpf_get_current_pid_tgid() >> 32;
    struct vm_stats_t *current_stats, vm_stat_zero = {};
    unsigned int exit_reason = args->exit_reason;

    cpu_status = per_cpu_status.lookup_or_init(&cpu, &cpu_zero);
    if (!cpu_status || cpu_status->last_kvm_entry == 0)
        return 0;

    current_stats = vm_stats.lookup_or_init(&tgid, &vm_stat_zero);
    if (!current_stats)
        return 0;

    current_stats->total_runtime += ts - cpu_status->last_kvm_entry;
    cpu_status->last_kvm_entry = 0;
    if (exit_reason >= MAX_KVM_EXIT_REASONS)
        return 0;
    current_stats->reasons_count[exit_reason]++;

    return 0;
}

TRACEPOINT_PROBE(kvm, kvm_msr) {
    u32 tgid = bpf_get_current_pid_tgid() >> 32;
    struct msr_stats_key_t msr_key = {
            .tgid = tgid,
            .ecx = args->ecx };
    struct msr_stats_t *stats, stats_zero = {};

    if (args->write != 1)
        return 0;

    stats = vm_msr_stats.lookup_or_init(&msr_key, &stats_zero);
    if (!stats)
        return 0;
    stats->count++;

    return 0;
}
"""
if args.tgid:
    bpf_text = bpf_text.replace('TGID_FILTER', 'tgid != %d' % args.tgid)
else:
    bpf_text = bpf_text.replace('TGID_FILTER', '0')

if debug or args.ebpf:
    print(bpf_text)
    if args.ebpf:
        exit()

vm_cmdlines = {}
ret = check_output('pgrep -fa qemu-system-x86', shell=True).strip()
for i in ret.split('\n'):
    pid = i.split(' ')[0]
    cmdline = i[len(pid)+1:]
    vm_cmdlines[pid] = cmdline

vm_list = {}
vm_names = check_output("virsh list --name", shell=True).strip()
for i in vm_names.split('\n'):
    for pid in vm_cmdlines.keys():
        if i in vm_cmdlines[pid]:
            vm_list[int(pid)] = i
            break

# initialize BPF
b = BPF(text=bpf_text)
begin_ts = datetime.utcnow()
if interval < 99999999:
    print('Tracing... Output every %d secs. Hit Ctrl-C to end' % interval)
else:
    print('Tracing... Output on Ctrl-C')

vm_stats = b.get_table('vm_stats')
msr_stats = b.get_table('vm_msr_stats')
exiting = 0

while 1:
    try:
        sleep(interval)
    except KeyboardInterrupt:
        exiting = 1

    if clear:
        call("clear")
    else:
        print()

    line = 0
    duration = datetime.utcnow() - begin_ts
    total_count = {}
    total_exits = 0
    per_pid_msr_write = {}
    for k, v in msr_stats.items():
        if k.tgid not in per_pid_msr_write.keys():
            per_pid_msr_write[k.tgid] = {}
        if k.ecx not in per_pid_msr_write[k.tgid].keys():
            per_pid_msr_write[k.tgid][k.ecx] = 0
        per_pid_msr_write[k.tgid][k.ecx] += int(v.count)

    print("## Collected data for %s seconds" % (duration.total_seconds()))
    for k, v in sorted(vm_stats.items(), key=lambda counts: counts[1].total_runtime,
                       reverse=True):
        runtime = float(v.total_runtime) / 1000000000.0
        pc_runtime = runtime / float(duration.total_seconds()) * 100
        pid = int(k.value)
        print("%s\n  vcpu(s) total runtime: %f s (%0.03f %%)" % (vm_list[pid], runtime, pc_runtime))
        print("  KVM exit reasons:")
        reason_idx = 0
        tmp_count = {}
        total_vm_exits = 0
        for exit_count in v.reasons_count:
            if exit_count > 0:
                tmp_count[reason_idx] = exit_count
                if reason_idx not in total_count:
                    total_count[reason_idx] = exit_count
                else:
                    total_count[reason_idx] += exit_count
                total_vm_exits += exit_count
                total_exits += exit_count
            reason_idx += 1

        for reason_idx, exit_count in sorted(tmp_count.iteritems(), key=lambda (k,v): (v,k),
                                             reverse=True):
            print("    %s: %d (%0.03f / sec)" % (exit_reasons[reason_idx], exit_count,
                                  exit_count / duration.total_seconds()))
            if exit_reasons[reason_idx] == 'MSR_WRITE':
                for msr, count in sorted(per_pid_msr_write[pid].items(), key=lambda (k,v): (v,k),
                                         reverse=True):
                    print("      0x%x: %d (%0.03f%%)" % (msr, count, float(count) / float(exit_count) * 100))
        print("    total: %d (%0.03f/sec)" % (total_vm_exits, total_vm_exits / duration.total_seconds()))
        line += 1
        if line >= maxrows:
            break
        print()

    print("Total:")
    for reason_idx, exit_count in sorted(total_count.iteritems(), key=lambda (k,v): (v,k),
                                         reverse=True):
        print("  %s: %d (%0.03f / sec)" % (exit_reasons[reason_idx], exit_count,
                              exit_count / duration.total_seconds()))
    print("  total: %d (%0.03f/sec)" % (total_exits, total_exits / duration.total_seconds()))

    if args.zero:
        vm_stats.clear()
        msr_stats.clear()
        begin_ts = datetime.utcnow()

    countdown -= 1
    if exiting or countdown == 0:
        print("Detaching...")
        exit()
