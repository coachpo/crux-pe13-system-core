#include "crux_storage_guard.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/fs.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>

#include <array>
#include <string>

namespace android {
namespace init {
namespace {

struct Partition {
    const char* name;
    bool readonly;
    unsigned major = 0;
    unsigned minor = 0;
    std::string node = {};
};

// These are the original MIUI OS/data partitions. Persist and firmware/security
// storage retain their existing PE contracts; the four PE partitions remain writable.
const std::array<Partition, 14> kPartitions = {{
    {"userdata", true}, {"metadata", true}, {"misc", true}, {"cache", true},
    {"system", true}, {"vendor", true}, {"boot", true}, {"recovery", true},
    {"dtbo", true}, {"vbmeta", true},
    {"pesystem", false}, {"pevendor", false}, {"peuserdata", false}, {"pemetadata", false},
}};

bool Error(int log_fd, const std::string& message) {
    dprintf(log_fd, "<3>crux-pe-storage-guard: failed: %s (%s)\n", message.c_str(),
            strerror(errno));
    return false;
}

bool Discover(const char* sysfs_dir, std::array<Partition, 14>* partitions, int log_fd) {
    *partitions = kPartitions;
    DIR* dir = opendir(sysfs_dir);
    if (!dir) return Error(log_fd, sysfs_dir);
    while (dirent* entry = readdir(dir)) {
        if (entry->d_name[0] == '.') continue;
        std::string path = std::string(sysfs_dir) + "/" + entry->d_name + "/uevent";
        FILE* file = fopen(path.c_str(), "re");
        if (!file) continue;
        char line[512];
        std::string name;
        unsigned major = 0, minor = 0;
        while (fgets(line, sizeof(line), file)) {
            if (strncmp(line, "PARTNAME=", 9) == 0) {
                line[strcspn(line, "\r\n")] = 0;
                name = line + 9;
            }
            sscanf(line, "MAJOR=%u", &major);
            sscanf(line, "MINOR=%u", &minor);
        }
        bool read_error = ferror(file);
        fclose(file);
        if (read_error) {
            closedir(dir);
            return Error(log_fd, path);
        }
        for (auto& partition : *partitions) {
            if (name != partition.name) continue;
            if (partition.major || !major) {
                closedir(dir);
                errno = EINVAL;
                return Error(log_fd, "ambiguous GPT partition " + name);
            }
            partition.major = major;
            partition.minor = minor;
            partition.node = entry->d_name;
        }
    }
    closedir(dir);
    return true;
}

}  // namespace

bool ProtectCruxPeStorage(const char* sysfs_dir, const char* node_dir, const char* marker,
                          int log_fd, unsigned attempts) {
    std::array<Partition, 14> partitions;
    bool complete = false;
    for (unsigned attempt = 0; attempt < attempts; ++attempt) {
        if (!Discover(sysfs_dir, &partitions, log_fd)) return false;
        complete = true;
        for (const auto& partition : partitions) complete &= partition.major != 0;
        if (complete) break;
        usleep(100000);
    }
    if (!complete) {
        errno = ENODEV;
        return Error(log_fd, "original/PE GPT partition discovery timed out");
    }
    if (mkdir(node_dir, 0700) && errno != EEXIST) return Error(log_fd, node_dir);
    std::string inventory;
    for (const auto& partition : partitions) {
        std::string path = std::string(node_dir) + "/" + partition.name;
        dev_t device = makedev(partition.major, partition.minor);
        if (mknod(path.c_str(), S_IFBLK | 0600, device) && errno != EEXIST)
            return Error(log_fd, path);
        struct stat st;
        if (lstat(path.c_str(), &st) || !S_ISBLK(st.st_mode) || st.st_rdev != device) {
            errno = ENODEV;
            return Error(log_fd, "block node mismatch: " + path);
        }
        int fd = open(path.c_str(), O_RDONLY | O_CLOEXEC);
        if (fd < 0) return Error(log_fd, path);
        int readonly = 1;
        if (partition.readonly && ioctl(fd, BLKROSET, &readonly)) {
            close(fd);
            return Error(log_fd, "BLKROSET: " + path);
        }
        readonly = -1;
        if (ioctl(fd, BLKROGET, &readonly) || readonly != int(partition.readonly)) {
            close(fd);
            errno = EROFS;
            return Error(log_fd, "BLKROGET: " + path);
        }
        close(fd);
        std::string record = std::string(partition.name) + " " + partition.node + " " +
                std::to_string(partition.major) + ":" + std::to_string(partition.minor) +
                " ro=" + std::to_string(readonly) + "\n";
        dprintf(log_fd, "<6>crux-pe-storage-guard: %s", record.c_str());
        inventory += record;
    }
    int fd = open(marker, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0444);
    if (fd < 0) return Error(log_fd, marker);
    bool written = write(fd, inventory.data(), inventory.size()) == ssize_t(inventory.size());
    close(fd);
    if (!written) return Error(log_fd, marker);
    dprintf(log_fd, "<6>crux-pe-storage-guard: active before first-stage mount; "
                    "10 original partitions RO, 4 PE partitions RW\n");
    return true;
}

}  // namespace init
}  // namespace android
