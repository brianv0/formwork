// Temporary probe: struct offsets from the SDK, sandbox_check across processes, 4-tuple lookup.
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <libproc.h>
#include <sys/proc_info.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <dlfcn.h>

int sandbox_check(pid_t pid, const char *operation, int type, ...);

int main(int argc, char **argv) {
    printf("sizeof socket_fdinfo=%zu proc_fileinfo=%zu socket_info=%zu vinfo_stat=%zu in_sockinfo=%zu\n",
        sizeof(struct socket_fdinfo), sizeof(struct proc_fileinfo), sizeof(struct socket_info),
        sizeof(struct vinfo_stat), sizeof(struct in_sockinfo));
    printf("off psi=%zu family=%zu kind=%zu proto=%zu fport=%zu lport=%zu vflag=%zu faddr=%zu laddr=%zu\n",
        offsetof(struct socket_fdinfo, psi),
        offsetof(struct socket_fdinfo, psi.soi_family),
        offsetof(struct socket_fdinfo, psi.soi_kind),
        offsetof(struct socket_fdinfo, psi.soi_proto),
        offsetof(struct socket_fdinfo, psi.soi_proto.pri_in.insi_fport),
        offsetof(struct socket_fdinfo, psi.soi_proto.pri_in.insi_lport),
        offsetof(struct socket_fdinfo, psi.soi_proto.pri_in.insi_vflag),
        offsetof(struct socket_fdinfo, psi.soi_proto.pri_in.insi_faddr),
        offsetof(struct socket_fdinfo, psi.soi_proto.pri_in.insi_laddr));
    printf("SOCKINFO_IN=%d SOCKINFO_TCP=%d PROC_PIDFDSOCKETINFO=%d PROX_FDTYPE_SOCKET=%d PROC_PIDFDSOCKETINFO_SIZE=%d\n",
        SOCKINFO_IN, SOCKINFO_TCP, PROC_PIDFDSOCKETINFO, PROX_FDTYPE_SOCKET, (int)PROC_PIDFDSOCKETINFO_SIZE);
    int *no_report = dlsym(RTLD_DEFAULT, "SANDBOX_CHECK_NO_REPORT");
    printf("SANDBOX_CHECK_NO_REPORT sym=%p value=%#x\n", (void*)no_report, no_report ? *no_report : -1);
    if (argc > 1) {
        // argv: pid path...
        pid_t pid = atoi(argv[1]);
        int flags = 1 | (no_report ? *no_report : 0);
        for (int i = 2; i < argc; i++) {
            int r = sandbox_check(pid, "file-read-data", flags, argv[i]);
            printf("sandbox_check(%d, file-read-data, %s) = %d\n", pid, argv[i], r);
        }
        printf("sandbox_check(%d, NULL, NONE) = %d\n", pid, sandbox_check(pid, NULL, 0));
        // find TCP sockets of pid
        int n = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, NULL, 0);
        struct proc_fdinfo *fds = malloc(n);
        n = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, fds, n);
        for (int i = 0; i < n / (int)sizeof(struct proc_fdinfo); i++) {
            if (fds[i].proc_fdtype != PROX_FDTYPE_SOCKET) continue;
            struct socket_fdinfo si;
            int got = proc_pidfdinfo(pid, fds[i].proc_fd, PROC_PIDFDSOCKETINFO, &si, sizeof si);
            if (got <= 0) continue;
            if (si.psi.soi_kind != SOCKINFO_TCP && si.psi.soi_kind != SOCKINFO_IN) continue;
            char l[64], f[64];
            inet_ntop(AF_INET, &si.psi.soi_proto.pri_in.insi_laddr.ina_46.i46a_addr4, l, sizeof l);
            inet_ntop(AF_INET, &si.psi.soi_proto.pri_in.insi_faddr.ina_46.i46a_addr4, f, sizeof f);
            printf("fd %d kind %d vflag %d %s:%d -> %s:%d (got %d)\n", fds[i].proc_fd, si.psi.soi_kind,
                si.psi.soi_proto.pri_in.insi_vflag, l, ntohs(si.psi.soi_proto.pri_in.insi_lport), f,
                ntohs(si.psi.soi_proto.pri_in.insi_fport), got);
        }
    }
    return 0;
}
