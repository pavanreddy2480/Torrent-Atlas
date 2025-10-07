#include <bits/stdc++.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <thread>
#include <mutex>
#include <atomic>
#include <condition_variable>
#include <readline/readline.h>
#include <sys/select.h>

using namespace std;
using u32=uint32_t;using u64=uint64_t;
static const size_t MAX_FRAME=10*1024*1024;

namespace P2PTracker{
    inline u64 hton64(u64 v){
    #if __BYTE_ORDER==__LITTLE_ENDIAN
        return(((u64)htonl((uint32_t)(v&0xffffffffULL)))<<32)|htonl((uint32_t)((v>>32)&0xffffffffULL));
    #else
        return v;
    #endif
    }
    inline u64 ntoh64(u64 v){
    #if __BYTE_ORDER==__LITTLE_ENDIAN
        return(((u64)ntohl((uint32_t)(v&0xffffffffULL)))<<32)|ntohl((uint32_t)((v>>32)&0xffffffffULL));
    #else
        return v;
    #endif
    }
    inline ssize_t readn(int fd,void* buf,size_t n){
        size_t left=n;char* p=(char*)buf;
        while(left){
            ssize_t r=recv(fd,p,left,0);
            if(r<0){if(errno==EINTR)continue;return -1;}
            if(r==0)return 0;
            left-=r;p+=r;
        }
        return n;
    }
    inline ssize_t writen(int fd,const void* buf,size_t n){
        size_t left=n;const char* p=(const char*)buf;
        while(left){
            ssize_t w=send(fd,p,left,0);
            if(w<=0){if(errno==EINTR)continue;return -1;}
            left-=w;p+=w;
        }
        return n;
    }
    struct GroupInfo{
        string owner;
        unordered_set<string> members;
        unordered_set<string> pending;
    };
    struct FileInfo{
        string group;
        string owner;
        string file_name;
        string whole_sha1;
        vector<string> piece_sha1;
        size_t file_size=0;
        unordered_set<u64> seeder_sessions;
    };
    class Tracker{
        mutex m;
        unordered_map<string,string> users;
        unordered_map<u64,string> sessions;
        unordered_map<u64,string> session_addrs;
        unordered_map<u64,unordered_set<string>> session_files;
        unordered_map<string,GroupInfo> groups;
        unordered_map<string,FileInfo> files;
        static u64 nextId(){static atomic<u64> c(1);return c++;}
        static string make_key(const string&g,const string&f){return g+"/"+f;}
    public:
        pair<string,u64> handle(u64 sess,const string& cmdline,const string& peer_ip,int peer_port){
            stringstream ss(cmdline);
            string cmd;ss>>cmd;
            if(cmd.empty())return {"ERR empty",sess};
            lock_guard<mutex> lk(m);
            string user=(sess&&sessions.count(sess))?sessions[sess]:"";
            if(cmd=="create_user"){
                string u,p;ss>>u>>p;
                if(u.empty()||p.empty())return {"ERR usage",sess};
                if(users.count(u))return {"ERR exists",sess};
                users[u]=p;return {"OK user created",sess};
            }
            if(cmd=="login"){
                string u,p;ss>>u>>p;
                if(!users.count(u)||users[u]!=p)return {"ERR bad credentials",sess};
                if(sess==0)sess=nextId();
                sessions[sess]=u;
                if(!peer_ip.empty()&&peer_port>0)session_addrs[sess]=peer_ip+":"+to_string(peer_port);
                return {"OK logged in",sess};
            }
            if(user.empty()&&cmd!="login"&&cmd!="create_user"){
                return {"ERR login required",sess};
            }
            if(cmd=="logout"){
                for(auto const& key:session_files[sess]){
                    if(files.count(key))files[key].seeder_sessions.erase(sess);
                }
                session_files.erase(sess);
                sessions.erase(sess);
                session_addrs.erase(sess);
                return {"OK logged out",0};
            }
            if(cmd=="set_addr"){
                string ip;int port;ss>>ip>>port;
                if(ip.empty()||port<=0)return {"ERR usage",sess};
                session_addrs[sess]=ip+":"+to_string(port);
                return {"OK set_addr",sess};
            }
            if(cmd=="create_group"){
                string g;ss>>g;
                if(g.empty())return {"ERR usage",sess};
                if(groups.count(g))return {"ERR group exists",sess};
                groups[g]={user,{user},{}};
                return {"OK group created",sess};
            }
            if(cmd=="join_group"){
                string g;ss>>g;
                if(g.empty())return {"ERR usage",sess};
                if(!groups.count(g))return {"ERR no such group",sess};
                auto& gi=groups[g];
                if(gi.members.count(user)||gi.owner==user)return {"ERR already member",sess};
                gi.pending.insert(user);
                return {"OK join requested",sess};
            }
            if(cmd=="leave_group"){
                 string g;ss>>g;
                 if(g.empty())return {"ERR usage",sess};
                 if(!groups.count(g))return {"ERR no such group",sess};
                 auto& gi=groups[g];
                 if(!gi.members.count(user))return {"ERR not a member",sess};
                 if(gi.owner==user)return {"ERR owner cannot leave",sess};
                 gi.members.erase(user);
                 return {"OK left group",sess};
            }
            if(cmd=="list_groups"){
                string out="Groups:";
                for(auto const& [key,val]:groups)out+=" "+key;
                return {out,sess};
            }
            if(cmd=="list_requests"){
                string g;ss>>g;
                if(g.empty())return {"ERR usage",sess};
                if(!groups.count(g))return {"ERR no such group",sess};
                auto& gi=groups[g];
                if(gi.owner!=user)return {"ERR not owner",sess};
                string out="Requests:";
                for(const auto& u:gi.pending)out+=" "+u;
                return {out,sess};
            }
            if(cmd=="accept_request"){
                string g,u;ss>>g>>u;
                if(!groups.count(g))return {"ERR no group",sess};
                auto& gi=groups[g];
                if(gi.owner!=user)return {"ERR not owner",sess};
                if(!gi.pending.count(u))return {"ERR no such req",sess};
                gi.pending.erase(u);gi.members.insert(u);
                return {"OK accepted",sess};
            }
            if(cmd=="upload_file"){
                string g,fname,fsize_s,whole;
                int num_pieces=0;
                ss>>g>>fname>>fsize_s>>whole>>num_pieces;
                if(g.empty()||fname.empty()||fsize_s.empty()||whole.empty()||num_pieces<=0)return {"ERR usage",sess};
                if(!groups.count(g))return {"ERR no such group",sess};
                if(!groups[g].members.count(user))return {"ERR not a member",sess};
                size_t fsize=stoull(fsize_s);
                vector<string> pieces(num_pieces);
                for(int i=0;i<num_pieces;i++){ss>>pieces[i];}
                string key=make_key(g,fname);
                if(!files.count(key)){
                     files[key]={g,user,fname,whole,pieces,fsize,{sess}};
                }else{
                    files[key].seeder_sessions.insert(sess);
                }
                session_files[sess].insert(key);
                return {"OK uploaded",sess};
            }
            if(cmd=="list_files"){
                string g;ss>>g;
                if(g.empty())return {"ERR usage",sess};
                if(!groups.count(g))return {"ERR no such group",sess};
                if(!groups[g].members.count(user))return {"ERR not a member",sess};
                string out="Files:";
                for(auto const& [key,val]:files){
                    if(val.group==g)out+=" "+val.file_name;
                }
                return {out,sess};
            }
            if(cmd=="get_file"){
                string g,fname;ss>>g>>fname;
                if(g.empty()||fname.empty())return {"ERR usage",sess};
                if(!groups.count(g))return {"ERR no such group",sess};
                if(!groups[g].members.count(user))return {"ERR not a member",sess};
                string key=make_key(g,fname);
                if(!files.count(key))return {"ERR no such file",sess};
                auto& fi=files[key];
                unordered_set<u64> valid_sessions;
                for(u64 seeder_sess:fi.seeder_sessions){
                    if(sessions.count(seeder_sess)&&session_addrs.count(seeder_sess)){
                        valid_sessions.insert(seeder_sess);
                    }
                }
                fi.seeder_sessions=valid_sessions;
                string out="FILEINFO ";
                out+=to_string(fi.file_size)+" "+fi.whole_sha1+" "+to_string(fi.piece_sha1.size());
                for(auto& p:fi.piece_sha1)out+=" "+p;
                out+=" SEEDERS";
                bool first=true;
                for(u64 seeder_sess:fi.seeder_sessions){
                     out+=(first?" ":",")+session_addrs.at(seeder_sess);
                     first=false;
                }
                return {out,sess};
            }
            if(cmd=="stop_share"){
                string g,fname;ss>>g>>fname;
                if(g.empty()||fname.empty())return {"ERR usage",sess};
                string key=make_key(g,fname);
                if(files.count(key)){
                    files[key].seeder_sessions.erase(sess);
                    session_files[sess].erase(key);
                }
                return {"OK stopped",sess};
            }
            return {"ERR unknown",sess};
        }
    };
    class SyncQueue{
    public:
        SyncQueue(const string& ip,int port){}
        void run(){}
    };
    inline void sessionWorker(int fd,Tracker& tracker){
        u32 netlen;
        if(readn(fd,&netlen,sizeof(netlen))<=0){close(fd);return;}
        u32 len=ntohl(netlen);
        if(len<sizeof(u64)||len>MAX_FRAME){close(fd);return;}
        u64 netsess;
        if(readn(fd,&netsess,sizeof(netsess))<=0){close(fd);return;}
        u64 sess=ntoh64(netsess);
        string cmd_payload;
        size_t pay_len=len-sizeof(u64);
        if(pay_len>0){
            cmd_payload.resize(pay_len);
            if(readn(fd,cmd_payload.data(),pay_len)<=0){close(fd);return;}
        }
        sockaddr_in peer{};socklen_t plen=sizeof(peer);
        string origin_ip;int origin_port=0;
        if(getpeername(fd,(sockaddr*)&peer,&plen)==0){
            char buf[INET_ADDRSTRLEN];
            inet_ntop(AF_INET,&peer.sin_addr,buf,sizeof(buf));
            origin_ip=string(buf);
            origin_port=ntohs(peer.sin_port);
        }
        auto [reply,newSess]=tracker.handle(sess,cmd_payload,origin_ip,origin_port);
        u32 respLen=htonl(sizeof(u64)+reply.size());
        u64 respSess=hton64(newSess==0?sess:newSess);
        writen(fd,&respLen,sizeof(respLen));
        writen(fd,&respSess,sizeof(respSess));
        if(!reply.empty())writen(fd,reply.data(),reply.size());
        close(fd);
    }
    inline int prepare_listener(const string& ip,int port){
        int fd=socket(AF_INET,SOCK_STREAM,0);
        if(fd<0){perror("socket");exit(1);}
        int opt=1;setsockopt(fd,SOL_SOCKET,SO_REUSEADDR,&opt,sizeof(opt));
        sockaddr_in addr{};addr.sin_family=AF_INET;addr.sin_port=htons(port);
        inet_pton(AF_INET,ip.c_str(),&addr.sin_addr);
        if(::bind(fd,(sockaddr*)&addr,sizeof(addr))<0){perror("bind");exit(1);}
        if(listen(fd,50)<0){perror("listen");exit(1);}
        return fd;
    }
}

atomic<bool> should_exit(false);
void console_listener(){
    while(!should_exit.load()){
        char* input=readline("> ");
        if(!input){should_exit=true;break;}
        string line(input);
        free(input);
        if(line=="exit"||line=="quit"){
            should_exit=true;
        }
    }
}
int main(int argc,char* argv[]){
    if(argc!=3){
        cerr<<"Usage: "<<argv[0]<<" <tracker_info_file> <tracker_no>\n";
        return 1;
    }
    string tracker_file_path=argv[1];
    int tracker_no=0;
    try{
        tracker_no=stoi(argv[2]);
    }catch(...){
        cerr<<"Error: <tracker_no> must be a number (1 or 2).\n";
        return 1;
    }
    ifstream infile(tracker_file_path);
    if(!infile.is_open()){
        cerr<<"Error: Could not open tracker info file: "<<tracker_file_path<<"\n";
        return 1;
    }
    vector<pair<string,int>> trackers;
    string line;
    while(getline(infile,line)){
        size_t p=line.find(':');
        if(p!=string::npos){
            try{
                trackers.push_back({line.substr(0,p),stoi(line.substr(p+1))});
            }catch(...){
                cerr<<"Error: Invalid line in tracker info file: "<<line<<"\n";
                return 1;
            }
        }
    }
    if(trackers.size()!=2){
        cerr<<"Error: tracker_info.txt must contain exactly two tracker addresses.\n";
        return 1;
    }
    if(tracker_no!=1&&tracker_no!=2){
        cerr<<"Error: <tracker_no> must be 1 or 2.\n";
        return 1;
    }
    string bind_ip=trackers[tracker_no-1].first;
    int bind_port=trackers[tracker_no-1].second;
    string peer_ip=trackers[tracker_no==1?1:0].first;
    int peer_port=trackers[tracker_no==1?1:0].second;
    P2PTracker::Tracker tracker_state;
    P2PTracker::SyncQueue sync_queue(peer_ip,peer_port);
    thread sync_thread(&P2PTracker::SyncQueue::run,&sync_queue);
    sync_thread.detach();
    int listenFd=P2PTracker::prepare_listener(bind_ip,bind_port);
    cerr<<"Tracker "<<tracker_no<<" listening on "<<bind_ip<<":"<<bind_port<<" (peer: "<<peer_ip<<":"<<peer_port<<")\n";
    cerr<<"Type 'exit' or 'quit' to shut down.\n";
    thread console_thread(console_listener);
    while(!should_exit.load()){
        fd_set read_fds;
        FD_ZERO(&read_fds);
        FD_SET(listenFd,&read_fds);
        struct timeval tv;
        tv.tv_sec=1;
        tv.tv_usec=0;
        int activity=select(listenFd+1,&read_fds,nullptr,nullptr,&tv);
        if((activity<0)&&(errno!=EINTR)){
            perror("select error");
        }
        if(FD_ISSET(listenFd,&read_fds)){
            int cfd=accept(listenFd,nullptr,nullptr);
            if(cfd<0){
                if(errno==EINTR)continue;
                perror("accept");
                break;
            }
            thread(P2PTracker::sessionWorker,cfd,ref(tracker_state)).detach();
        }
    }
    cout<<"\nShutting down tracker...\n";
    close(listenFd);
    if(console_thread.joinable()){
        pthread_cancel(console_thread.native_handle());
        console_thread.join();
    }
    return 0;
}

