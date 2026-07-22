#!/bin/sh
# Determine the number of CPUs actually usable in this container,
# accounting for cgroup v1/v2 CPU quotas that `nproc` is blind to.
# Usage: . ci/detect-cpus.sh   (source it, don't execute it, so JOBS
# is exported into the calling shell)

detect_cpus() {
    if [ -f /sys/fs/cgroup/cpu.max ]; then
        # cgroup v2 unified hierarchy
        read -r quota period < /sys/fs/cgroup/cpu.max
        if [ "$quota" = "max" ]; then
            nproc
        else
            echo $(( quota / period ))
        fi
    elif [ -f /sys/fs/cgroup/cpu/cpu.cfs_quota_us ]; then
        # cgroup v1 legacy/hybrid hierarchy
        quota=$(cat /sys/fs/cgroup/cpu/cpu.cfs_quota_us)
        period=$(cat /sys/fs/cgroup/cpu/cpu.cfs_period_us)
        if [ "$quota" -le 0 ]; then
            nproc
        else
            echo $(( quota / period ))
        fi
    else
        nproc
    fi
}

CPUS=$(detect_cpus)
[ "$CPUS" -ge 1 ] || CPUS=1
export CPUS
echo "detect-cpus: CPUS=$CPUS (nproc reports $(nproc))"
