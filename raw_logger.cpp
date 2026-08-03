/*
 * raw_logger.cpp — code/rw/bl 三文件写入器实现
 */

#include "raw_logger.h"

#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>

#include <cstring>
#include <mutex>

// 每文件缓存大小
static constexpr size_t kCacheSize = 1 << 20; // 1MB
// 每隔多少行 flush 一次（行号 & mask == 0）
static constexpr uint64_t kFlushMask = 0xFFF;

// 全局 logger 实例
RawMemoryLogger *g_raw_logger = nullptr;
RawMemoryLogger *g_rw_logger = nullptr;
RawMemoryLogger *g_bl_logger = nullptr;

// 保护三个全局 logger 的并发写
static std::mutex g_loggers_mutex;

RawMemoryLogger::RawMemoryLogger()
	: fd_(-1)
	, cache_(nullptr)
	, cacheSize_(kCacheSize)
	, used_(0)
	, offset_(0)
	, inited_(false)
{
}

RawMemoryLogger::~RawMemoryLogger()
{
	close();
}

int RawMemoryLogger::init(const char *path)
{
	close();

	fd_ = ::open(path, O_CREAT | O_WRONLY | O_TRUNC | O_CLOEXEC, 0644);
	if (fd_ < 0) {
		return -1;
	}

	cache_ = static_cast<char *>(
		mmap(nullptr, cacheSize_, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
	if (cache_ == MAP_FAILED) {
		::close(fd_);
		fd_ = -1;
		cache_ = nullptr;
		return -2;
	}

	used_ = 0;
	offset_ = 0;
	inited_ = true;
	return 0;
}

void RawMemoryLogger::writeCached(const char *buf, size_t len)
{
	if (!inited_ || buf == nullptr || len == 0) {
		return;
	}

	// 大块数据（>= 缓存大小）直接绕过缓存写盘
	if (len >= cacheSize_) {
		flush();
		const char *p = buf;
		size_t remaining = len;
		while (remaining > 0) {
			ssize_t n = ::write(fd_, p, remaining);
			if (n <= 0) {
				break;
			}
			p += n;
			remaining -= static_cast<size_t>(n);
		}
		offset_ += static_cast<uint64_t>(len - remaining);
		return;
	}

	if (used_ + len > cacheSize_) {
		flush();
	}
	memcpy(cache_ + used_, buf, len);
	used_ += len;
}

void RawMemoryLogger::flush()
{
	if (!inited_ || used_ == 0) {
		return;
	}

	const char *p = cache_;
	size_t remaining = used_;
	while (remaining > 0) {
		ssize_t n = ::write(fd_, p, remaining);
		if (n <= 0) {
			break;
		}
		p += n;
		remaining -= static_cast<size_t>(n);
	}
	offset_ += static_cast<uint64_t>(used_ - remaining);
	used_ = 0;
}

void RawMemoryLogger::close()
{
	flush();
	if (cache_ != nullptr) {
		munmap(cache_, cacheSize_);
		cache_ = nullptr;
	}
	if (fd_ >= 0) {
		::close(fd_);
		fd_ = -1;
	}
	inited_ = false;
}

// ============================================================================
// C 风格便捷封装
// ============================================================================

int raw_logger_init(RawMemoryLogger *logger, const char *path)
{
	if (logger == nullptr || path == nullptr) {
		return -1;
	}
	return logger->init(path);
}

void raw_logger_write_cached(RawMemoryLogger *logger, const char *buf, size_t len)
{
	if (logger == nullptr) {
		return;
	}
	std::lock_guard<std::mutex> lock(g_loggers_mutex);
	logger->writeCached(buf, len);
}

void raw_logger_check_and_flush(uint64_t lineNum)
{
	if ((lineNum & kFlushMask) != 0) {
		return;
	}
	std::lock_guard<std::mutex> lock(g_loggers_mutex);
	if (g_raw_logger != nullptr) {
		g_raw_logger->flush();
	}
	if (g_rw_logger != nullptr) {
		g_rw_logger->flush();
	}
	if (g_bl_logger != nullptr) {
		g_bl_logger->flush();
	}
}

void raw_logger_flush_all(void)
{
	std::lock_guard<std::mutex> lock(g_loggers_mutex);
	if (g_raw_logger != nullptr) {
		g_raw_logger->flush();
	}
	if (g_rw_logger != nullptr) {
		g_rw_logger->flush();
	}
	if (g_bl_logger != nullptr) {
		g_bl_logger->flush();
	}
}
