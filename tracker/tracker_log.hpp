#pragma once

/// @file tracker_log.hpp
/// The tracker's console log: one timestamped line per event on stdout.

#include <mutex>
#include <string>

/// Writes "[HH:MM:SS] message" lines to stdout. Thread-safe: lines from
/// different connection threads never interleave.
///
/// Never pass a password, key or session ID: use safeCommand() and
/// safeResponse() to describe client traffic.
class TrackerLog {
public:
    /// Logs a normal event.
    static void info(const std::string &message);

    /// Logs a failure, prefixed with "ERROR: ".
    static void error(const std::string &message);

    /// @param commandLine A client command line.
    /// @return The command with secret arguments replaced by "***": the
    ///         password of create_user and login, and everything after the
    ///         file name of upload_file (hashes, address and peer key).
    static std::string safeCommand(const std::string &commandLine);

    /// @param response A reply sent to a client.
    /// @return The reply, with a META reply (which carries seeder tickets)
    ///         shortened to "META ..." and long replies cut to 200 bytes.
    static std::string safeResponse(const std::string &response);

private:
    static void write(const std::string &line);

    static std::mutex mutex_;   ///< One line at a time.
};
