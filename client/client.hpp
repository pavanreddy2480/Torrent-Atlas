#pragma once

/// @file client.hpp
/// The client program: a command prompt, a peer server that seeds files,
/// and the downloads in progress.

#include "client/command_line.hpp"
#include "client/download/download_manager.hpp"
#include "client/peer/peer_server.hpp"
#include "client/peer/peer_stats.hpp"
#include "client/storage/shared_files.hpp"
#include "client/tracker_client.hpp"

#include <istream>
#include <ostream>

/// Owns every part of a running client and routes each typed command.
///
/// Local commands (upload_file, download_file, resume_download,
/// show_downloads, cancel_download, peer_stats/show_peers, stats) are
/// handled here; everything else is forwarded to the tracker as typed.
class Client {
public:
    /// Makes a fresh random peer key for this run (see peer_ticket.hpp).
    /// @param self   The address the peer server listens on and that the
    ///               tracker gives to downloaders.
    /// @param config The tracker's address and public key.
    Client(Endpoint self, ClientConfig config);

    /// Starts the peer server, then reads commands from in and writes
    /// replies to out until "quit" or end of input. Downloads still running
    /// are cancelled when the Client is destroyed.
    /// @return 0 on a normal exit; 1 if the peer key could not be made or
    ///         the peer server could not listen.
    int run(std::istream &in, std::ostream &out);

private:
    /// Runs one parsed command and prints its result to out.
    void execute(CommandLine &command, std::ostream &out);

    /// Hashes the file at path, registers this client as its seeder in
    /// group, and starts serving it. Prints the tracker's reply.
    void uploadFile(const std::string &group, const std::string &path, std::ostream &out);

    /// Sends a command to the tracker, hex-encoding file names where the
    /// protocol needs it, erases passwords afterwards, prints the reply, and
    /// mirrors successful stop_share / leave_group / logout in shared_.
    void forwardToTracker(CommandLine &command, std::ostream &out);

    // Declared in this order so they are built in it, and so downloads stop
    // before the peer server on destruction.
    Endpoint self_;
    const std::string peerKey_;   ///< Raw 32 bytes; see peer_ticket.hpp. New for every run.
    TrackerClient tracker_;
    SharedFiles shared_;
    PeerStats peerStats_;
    PeerServer peerServer_;
    DownloadManager downloads_;
};
