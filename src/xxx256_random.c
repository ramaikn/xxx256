#include "xxx256_internal.h"

#include <limits.h>

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>
#elif defined(__APPLE__) || defined(__OpenBSD__) || defined(__FreeBSD__)
#include <stdlib.h>
#elif defined(__linux__)
#include <errno.h>
#include <sys/random.h>
#else
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#endif

xxx256_result xxx256_random_bytes(uint8_t *output, size_t length)
{
    if (output == NULL && length != 0u) {
        return XXX256_ERR_INVALID_ARGUMENT;
    }

#if defined(_WIN32)
    while (length != 0u) {
        ULONG amount = length > (size_t)ULONG_MAX ? ULONG_MAX : (ULONG)length;
        NTSTATUS status = BCryptGenRandom(
            NULL, output, amount, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
        if (status < 0) {
            return XXX256_ERR_RANDOM;
        }
        output += amount;
        length -= amount;
    }
    return XXX256_OK;
#elif defined(__APPLE__) || defined(__OpenBSD__) || defined(__FreeBSD__)
    arc4random_buf(output, length);
    return XXX256_OK;
#elif defined(__linux__)
    while (length != 0u) {
        ssize_t received = getrandom(output, length, 0);
        if (received < 0) {
            if (errno == EINTR) {
                continue;
            }
            return XXX256_ERR_RANDOM;
        }
        if (received == 0) {
            return XXX256_ERR_RANDOM;
        }
        output += (size_t)received;
        length -= (size_t)received;
    }
    return XXX256_OK;
#else
    {
        int descriptor = open("/dev/urandom", O_RDONLY);
        if (descriptor < 0) {
            return XXX256_ERR_RANDOM;
        }
        while (length != 0u) {
            ssize_t received = read(descriptor, output, length);
            if (received < 0) {
                if (errno == EINTR) {
                    continue;
                }
                (void)close(descriptor);
                return XXX256_ERR_RANDOM;
            }
            if (received == 0) {
                (void)close(descriptor);
                return XXX256_ERR_RANDOM;
            }
            output += (size_t)received;
            length -= (size_t)received;
        }
        if (close(descriptor) != 0) {
            return XXX256_ERR_RANDOM;
        }
        return XXX256_OK;
    }
#endif
}
