#include "client/client.hpp"

#include "client/storage/piece_file.hpp"

#include "common/crypto/crypto.hpp"

#include <filesystem>

Client::Client(Endpoint self, ClientConfig config)
    : self_(self), tracker_(std::move(config), self), peerServer_(shared_),
      downloads_(tracker_, shared_, peerStats_) {}

int Client::run(std::istream &in, std::ostream &out) {
    if (!peerServer_.start(self_)) {
        out << "could not listen for peers on " << self_.toString() << '\n';
        return 1;
    }
    out << "Client listening on " << self_.toString() << '\n';
    for (std::string line; out << "> " && std::getline(in, line);) {
        CommandLine command = CommandLine::parse(line);
        if (command.name == "quit") break;
        if (!command.name.empty()) execute(command, out);
    }
    return 0;
}

void Client::execute(CommandLine &command, std::ostream &out) {
    const std::string &name = command.name;
    const std::vector<std::string> &args = command.args;
    if (name == "upload_file") {
        if (args.size() < 2) out << "ERR usage: upload_file <group> <path>\n";
        else uploadFile(args[0], args[1], out);
    } else if (name == "download_file" || name == "resume_download") {
        if (args.size() < 3) out << "ERR usage: " << name << " <group> <file-name> <destination>\n";
        else downloads_.start(args[0], args[1], args[2], out);
    } else if (name == "show_downloads") {
        downloads_.printDownloads(out);
    } else if (name == "cancel_download") {
        if (args.empty()) out << "ERR usage: cancel download <file-name>\n";
        else downloads_.cancel(args[0], out);
    } else if (name == "peer_stats" || name == "show_peers") {
        peerStats_.print(out);
    } else if (name == "stats") {
        downloads_.printStats(out);
    } else {
        forwardToTracker(command, out);
    }
}

void Client::uploadFile(const std::string &group, const std::string &path, std::ostream &out) {
    LocalFile file{path, {}, {}};
    if (!PieceFile::hash(path, file.metadata)) {
        out << "ERR upload file: cannot read " << path << '\n';
        return;
    }
    file.metadata.capability = toHex(crypto::randomBytes(32));
    if (file.metadata.capability.size() != 64) {
        out << "ERR secure random generation failed\n";
        return;
    }
    file.available.assign(file.metadata.pieceCount(), true);
    std::string name = std::filesystem::path(path).filename().string();
    std::string response;
    tracker_.share(group, name, file.metadata, response);
    if (response.rfind("OK", 0) != 0) {
        out << response << '\n';
        return;
    }
    // "OK file shared <capability>": a file already shared by others keeps
    // its first capability.
    std::vector<std::string> words = parseCommandWords(response);
    if (words.size() >= 4 && words[3].size() == 64) file.metadata.capability = words[3];
    shared_.add(group, name, std::move(file));
    out << "OK file shared\n";
}

// Every other command goes to the tracker as typed, except that file names
// travel hex-encoded.
void Client::forwardToTracker(CommandLine &command, std::ostream &out) {
    std::vector<std::string> &args = command.args;
    std::string request = command.name;
    for (std::size_t i = 0; i < args.size(); ++i)
        request += " " + (command.name == "stop_share" && i == 1 ? toHex(args[i]) : args[i]);
    std::string response;
    tracker_.request(request, response);
    if (command.name == "login" || command.name == "create_user") {
        crypto::secureErase(request);
        for (std::string &arg : args) crypto::secureErase(arg);
    }
    bool ok = response.rfind("OK", 0) == 0;
    if (command.name == "list_files" && ok) {
        std::vector<std::string> words = parseCommandWords(response);
        std::string fileName;
        for (std::size_t i = 1; i < words.size(); ++i)
            if (fromHex(words[i], fileName)) out << fileName << '\n';
    } else {
        out << response << '\n';
    }
    if (!ok) return;
    if (command.name == "stop_share" && args.size() >= 2) shared_.remove(args[0], args[1]);
    if (command.name == "leave_group" && !args.empty()) shared_.removeGroup(args[0]);
    if (command.name == "logout") shared_.clear();
}
