// Crux PE protects the original OS partitions before first-stage mount.
#pragma once

namespace android {
namespace init {

// The paths also permit exercising the same discovery/ioctl code against local loop devices.
bool ProtectCruxPeStorage(const char* sysfs_dir, const char* node_dir, const char* marker,
                          int log_fd, unsigned attempts = 100);

}  // namespace init
}  // namespace android
