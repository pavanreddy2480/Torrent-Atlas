#include <string>
#include <iostream>
#include <fstream>
#include <vector>
#include <thread>
#include <mutex>
#include <atomic>
#include <condition_variable>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <readline/readline.h>
#include <readline/history.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <openssl/sha.h>
#include <random>
#include <algorithm>
#include <unordered_map>
#include <sstream>

using namespace std;
using u32 = uint32_t;
using u64 = uint64_t;

static const size_t PIECE_SIZE = 512*1024;
static const size_t MAX_FRAME = 10*1024*1024;

static vector<pair<string,int>> trackers;
static atomic<int> current_tracker_idx(0);

struct DownloadState{
    string group_id;
    string file_name;
    atomic<int> completed_pieces;
    int total_pieces;
    atomic<bool> is_complete;
    DownloadState(string gid,string fname,int t_pieces):group_id(std::move(gid)),file_name(std::move(fname)),completed_pieces(0),total_pieces(t_pieces),is_complete(false){}
    DownloadState(const DownloadState& other):group_id(other.group_id),file_name(other.file_name),completed_pieces(other.completed_pieces.load()),total_pieces(other.total_pieces),is_complete(other.is_complete.load()){}
};
static mutex downloads_mtx;
static unordered_map<string,DownloadState> ongoing_downloads;

static pair<string,u64> send_request_to_tracker(u64 session,const string& payload);
void do_download_file_parallel(u64& session_id,const string& group,const string& file_name,const string& dest_path);

u64 hton64(u64 v){
#if __BYTE_ORDER==__LITTLE_ENDIAN
    return (((u64)htonl((uint32_t)(v&0xffffffffULL)))<<32)|htonl((uint32_t)((v>>32)&0xffffffffULL));
#else
    return v;
#endif
}
u64 ntoh64(u64 v){
#if __BYTE_ORDER==__LITTLE_ENDIAN
    return (((u64)ntohl((uint32_t)(v&0xffffffffULL)))<<32)|ntohl((uint32_t)((v>>32)&0xffffffffULL));
#else
    return v;
#endif
}
ssize_t readn(int fd,void* buf,size_t n){
    size_t left=n;char* ptr=(char*)buf;
    while(left){
        ssize_t r=::recv(fd,ptr,left,0);
        if(r<0){if(errno==EINTR)continue;return -1;}
        if(r==0)return 0;
        left-=r;ptr+=r;
    }
    return (ssize_t)n;
}
ssize_t writen(int fd,const void* buf,size_t n){
    size_t left=n;const char* ptr=(const char*)buf;
    while(left){
        ssize_t w=::send(fd,ptr,left,0);
        if(w<=0){if(errno==EINTR)continue;return -1;}
        left-=w;ptr+=w;
    }
    return (ssize_t)n;
}
static int connect_to(const string& ip,int port){
    int fd=socket(AF_INET,SOCK_STREAM,0);
    if(fd<0)return -1;
    sockaddr_in s{};s.sin_family=AF_INET;s.sin_port=htons(port);
    if(inet_pton(AF_INET,ip.c_str(),&s.sin_addr)<=0){close(fd);return -1;}
    struct timeval tv;tv.tv_sec=2;tv.tv_usec=0;
    setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof(tv));
    setsockopt(fd,SOL_SOCKET,SO_SNDTIMEO,&tv,sizeof(tv));
    if(::connect(fd,(sockaddr*)&s,sizeof(s))<0){close(fd);return -1;}
    return fd;
}
static string bytes_to_hex(const unsigned char* d,size_t n){
    static const char hex[]="0123456789abcdef";string s;s.reserve(n*2);
    for(size_t i=0;i<n;i++){s.push_back(hex[(d[i]>>4)&0xF]);s.push_back(hex[d[i]&0xF]);}
    return s;
}
static string sha1_hex_of_buffer(const void* data,size_t len){
    unsigned char digest[SHA_DIGEST_LENGTH];
    SHA1((const unsigned char*)data,len,digest);
    return bytes_to_hex(digest,SHA_DIGEST_LENGTH);
}
static bool compute_file_piece_hashes(const string& path,uint64_t& file_size,string& whole_sha,vector<string>& piece_sha){
    int fd=open(path.c_str(),O_RDONLY);
    if(fd<0)return false;
    struct stat st;if(fstat(fd,&st)<0){close(fd);return false;}
    file_size=(uint64_t)st.st_size;
    SHA_CTX whole_ctx;
    SHA1_Init(&whole_ctx);
    piece_sha.clear();
    vector<char> buf(65536);
    uint64_t total_read=0;
    while(total_read<file_size){
        SHA_CTX piece_ctx;
        SHA1_Init(&piece_ctx);
        uint64_t piece_to_read=min((uint64_t)PIECE_SIZE,file_size-total_read);
        uint64_t piece_read=0;
        lseek(fd,total_read,SEEK_SET);
        while(piece_read<piece_to_read){
            ssize_t r=read(fd,buf.data(),min(buf.size(),(size_t)(piece_to_read-piece_read)));
            if(r<=0){close(fd);return false;}
            SHA1_Update(&piece_ctx,(const unsigned char*)buf.data(),r);
            SHA1_Update(&whole_ctx,(const unsigned char*)buf.data(),r);
            piece_read+=r;
        }
        unsigned char pd[SHA_DIGEST_LENGTH];
        SHA1_Final(pd,&piece_ctx);
        piece_sha.push_back(bytes_to_hex(pd,SHA_DIGEST_LENGTH));
        total_read+=piece_to_read;
    }
    unsigned char wd[SHA_DIGEST_LENGTH];
    SHA1_Final(wd,&whole_ctx);
    whole_sha=bytes_to_hex(wd,SHA_DIGEST_LENGTH);
    close(fd);
    return true;
}
struct LocalFile{string group,file_name,path;};
static unordered_map<string,LocalFile> local_files;
static mutex local_files_mtx;
static inline string make_key(const string& g,const string& f){return g+"/"+f;}
static atomic<bool> stop_peer_listener(false);
static int peer_listen_fd=-1;
static int agreed_listen_port=0;

void handle_peer_connection(int cfd){
    u32 netlen;
    if(readn(cfd,&netlen,sizeof(netlen))<=0){close(cfd);return;}
    u32 len=ntohl(netlen);
    if(len>1024*1024){close(cfd);return;}
    vector<char> buf(len);
    if(len>0&&readn(cfd,buf.data(),len)<=0){close(cfd);return;}
    string req(buf.data(),len);
    stringstream ss(req);
    string cmd;ss>>cmd;
    if(cmd!="GET_PIECE"){close(cfd);return;}
    string group,fname;int idx;ss>>group>>fname>>idx;
    if(group.empty()||fname.empty()||idx<0){close(cfd);return;}
    string key=make_key(group,fname);
    string file_path;
    {
        lock_guard<mutex> lk(local_files_mtx);
        if(!local_files.count(key)){close(cfd);return;}
        file_path=local_files[key].path;
    }
    struct stat st;if(stat(file_path.c_str(),&st)<0){close(cfd);return;}
    uint64_t file_size=st.st_size;
    uint64_t piece_offset=(uint64_t)idx*PIECE_SIZE;
    if(piece_offset>=file_size){close(cfd);return;}
    size_t piece_len=(size_t)min<uint64_t>(PIECE_SIZE,file_size-piece_offset);
    int fd=open(file_path.c_str(),O_RDONLY);
    if(fd<0){close(cfd);return;}
    vector<char> out(piece_len);
    ssize_t r=pread(fd,out.data(),piece_len,piece_offset);
    close(fd);
    if(r!=(ssize_t)piece_len){close(cfd);return;}
    u32 outlen=htonl((u32)piece_len);
    if(writen(cfd,&outlen,sizeof(outlen))<0){close(cfd);return;}
    if(writen(cfd,out.data(),piece_len)<0){close(cfd);return;}
    close(cfd);
}
void peer_listener_thread(int listen_port){
    peer_listen_fd=socket(AF_INET,SOCK_STREAM,0);
    if(peer_listen_fd<0){perror("peer socket");return;}
    int opt=1;setsockopt(peer_listen_fd,SOL_SOCKET,SO_REUSEADDR,&opt,sizeof(opt));
    sockaddr_in addr{};addr.sin_family=AF_INET;addr.sin_port=htons(listen_port);addr.sin_addr.s_addr=INADDR_ANY;
    if(::bind(peer_listen_fd,(sockaddr*)&addr,sizeof(addr))<0){perror("peer bind");close(peer_listen_fd);return;}
    sockaddr_in got{};socklen_t gl=sizeof(got);
    if(getsockname(peer_listen_fd,(sockaddr*)&got,&gl)==0)agreed_listen_port=ntohs(got.sin_port);
    if(listen(peer_listen_fd,50)<0){perror("peer listen");close(peer_listen_fd);return;}
    cerr<<"[peer] listening on port "<<agreed_listen_port<<"\n";
    while(!stop_peer_listener.load()){
        int c=accept(peer_listen_fd,nullptr,nullptr);
        if(c<0){if(errno==EINTR||errno==EBADF)continue;break;}
        thread(handle_peer_connection,c).detach();
    }
    close(peer_listen_fd);
}
static pair<string,u64> send_request_to_tracker(u64 session,const string& payload){
    int fd=-1;
    for(size_t i=0;i<trackers.size();++i){
        int idx=(current_tracker_idx.load()+i)%trackers.size();
        const auto& tracker_addr=trackers[idx];
        fd=connect_to(tracker_addr.first,tracker_addr.second);
        if(fd>=0){
            current_tracker_idx.store(idx);
            break;
        }
        cerr<<"[net] Connection to "<<tracker_addr.first<<":"<<tracker_addr.second<<" failed. Trying next tracker.\n";
    }
    if(fd<0)return {"ERR connect: No trackers available",0};
    u64 netsess=hton64(session);
    u32 frame_len=(u32)(sizeof(netsess)+payload.size());
    u32 netlen=htonl(frame_len);
    if(writen(fd,&netlen,sizeof(netlen))<0){close(fd);return {"ERR send",0};}
    if(writen(fd,&netsess,sizeof(netsess))<0){close(fd);return {"ERR send",0};}
    if(!payload.empty()&&writen(fd,payload.data(),payload.size())<0){close(fd);return {"ERR send",0};}
    u32 resp_netlen;
    if(readn(fd,&resp_netlen,sizeof(resp_netlen))<=0){close(fd);return {"ERR no resp",0};}
    u32 resp_len=ntohl(resp_netlen);
    if(resp_len<sizeof(u64)||resp_len>MAX_FRAME){close(fd);return {"ERR bad resp len",0};}
    u64 resp_netsess;
    if(readn(fd,&resp_netsess,sizeof(resp_netsess))<=0){close(fd);return {"ERR no resp sess",0};}
    string resp_payload;
    size_t payload_size=resp_len-sizeof(u64);
    if(payload_size>0){
        resp_payload.resize(payload_size);
        if(readn(fd,resp_payload.data(),payload_size)<=0){close(fd);return {"ERR resp read fail",0};}
    }
    close(fd);
    return {resp_payload,ntoh64(resp_netsess)};
}
static void do_upload_file(u64& session_id,const string& group,const string& file_path){
    uint64_t file_size;string whole_sha;vector<string> piece_hashes;
    cerr<<"[upload] computing hashes (this may take a bit)...\n";
    if(!compute_file_piece_hashes(file_path,file_size,whole_sha,piece_hashes)){cerr<<"hash computation failed\n";return;}
    string fname;size_t pos=file_path.find_last_of("/\\");fname=(pos==string::npos)?file_path:file_path.substr(pos+1);
    stringstream ss;ss<<"upload_file "<<group<<" "<<fname<<" "<<file_size<<" "<<whole_sha<<" "<<piece_hashes.size();
    for(auto& p:piece_hashes)ss<<" "<<p;
    auto [resp,new_sess]=send_request_to_tracker(session_id,ss.str());
    if(new_sess!=0)session_id=new_sess;
    if(resp.rfind("OK",0)==0){
        lock_guard<mutex> lk(local_files_mtx);
        local_files[make_key(group,fname)]={group,fname,file_path};
        cerr<<"[upload] tracker accepted metadata\n";
    }else{
        cerr<<"[upload] failed: "<<resp<<"\n";
    }
}
static bool download_piece_from_seeder(const string& seeder,const string& group,const string& fname,int idx,vector<char>& outbuf){
    size_t p=seeder.find(':');if(p==string::npos)return false;
    string ip=seeder.substr(0,p);
    int port;try{port=stoi(seeder.substr(p+1));}catch(...){return false;}
    int fd=connect_to(ip,port);
    if(fd<0)return false;
    string req=string("GET_PIECE ")+group+" "+fname+" "+to_string(idx);
    u32 nlen=htonl((u32)req.size());
    if(writen(fd,&nlen,sizeof(nlen))<0){close(fd);return false;}
    if(writen(fd,req.data(),req.size())<0){close(fd);return false;}
    u32 piece_netlen;
    if(readn(fd,&piece_netlen,sizeof(piece_netlen))<=0){close(fd);return false;}
    u32 piece_len=ntohl(piece_netlen);
    if(piece_len>PIECE_SIZE+10){close(fd);return false;}
    outbuf.resize(piece_len);
    if(piece_len>0&&readn(fd,outbuf.data(),piece_len)<=0){close(fd);return false;}
    close(fd);
    return true;
}
void do_download_file_parallel(u64& session_id,const string& group,const string& file_name,const string& dest_path){
    auto [resp,new_sess]=send_request_to_tracker(session_id,string("get_file ")+group+" "+file_name);
    if(new_sess!=0)session_id=new_sess;
    if(resp.rfind("ERR",0)==0){cerr<<"[get_file] "<<resp<<"\n";return;}
    stringstream ss(resp);
    string tag;ss>>tag;
    if(tag!="FILEINFO"){cerr<<"[get_file] unexpected reply: "<<resp<<"\n";return;}
    uint64_t file_size;string whole_sha;int num_pieces;
    ss>>file_size>>whole_sha>>num_pieces;
    if(!ss||num_pieces<=0){cerr<<"[get_file] bad metadata\n";return;}
    vector<string> piece_hashes(num_pieces);
    for(int i=0;i<num_pieces;i++){ss>>piece_hashes[i];}
    string seeders_token;ss>>seeders_token;string seeders_raw;
    if(seeders_token=="SEEDERS"){getline(ss,seeders_raw);if(!seeders_raw.empty()&&seeders_raw[0]==' ')seeders_raw.erase(0,1);}
    vector<string> seeders;
    if(!seeders_raw.empty()){
        string cur;for(char c:seeders_raw){if(c==','){if(!cur.empty())seeders.push_back(cur);cur.clear();}else cur.push_back(c);}if(!cur.empty())seeders.push_back(cur);
    }
    if(seeders.empty()){cerr<<"[download] no seeders available\n";return;}
    cerr<<"[download] file size="<<file_size<<" pieces="<<num_pieces<<" seeders="<<seeders.size()<<"\n";
    string dl_key=make_key(group,file_name);
    {
        lock_guard<mutex> lk(downloads_mtx);
        ongoing_downloads.emplace(piecewise_construct,make_tuple(dl_key),make_tuple(group,file_name,num_pieces));
    }
    thread([=,&session_id]()mutable{
        string tmp_path=dest_path+".part";
        int outfd=open(tmp_path.c_str(),O_CREAT|O_RDWR,0666);
        if(outfd<0){perror("open out");return;}
        if(file_size>0&&ftruncate(outfd,(off_t)file_size)<0){}
        vector<atomic<int>> piece_state(num_pieces);
        for(int i=0;i<num_pieces;++i)piece_state[i]=0;
        atomic<int> completed_pieces(0);
        auto worker=[&](int id){
            while(completed_pieces.load()<num_pieces){
                int idx=-1;
                for(int i=0;i<num_pieces;i++){
                    int expected=0;
                    if(piece_state[i].compare_exchange_strong(expected,1)){idx=i;break;}
                }
                if(idx==-1){if(completed_pieces.load()==num_pieces)break;this_thread::sleep_for(chrono::milliseconds(100));continue;}
                bool piece_ok=false;
                vector<string> current_seeders=seeders;
                std::random_device rd;std::mt19937 g(rd());
                std::shuffle(current_seeders.begin(),current_seeders.end(),g);
                for(const auto& seeder:current_seeders){
                    vector<char> piece_data;
                    if(download_piece_from_seeder(seeder,group,file_name,idx,piece_data)&&sha1_hex_of_buffer(piece_data.data(),piece_data.size())==piece_hashes[idx]){
                        if(pwrite(outfd,piece_data.data(),piece_data.size(),(off_t)idx*PIECE_SIZE)==(ssize_t)piece_data.size()){
                            piece_state[idx]=2;
                            completed_pieces.fetch_add(1);
                            lock_guard<mutex> lk(downloads_mtx);
                            ongoing_downloads.at(dl_key).completed_pieces.fetch_add(1);
                            piece_ok=true;
                            break;
                        }
                    }
                }
                if(!piece_ok){int expected=1;piece_state[idx].compare_exchange_strong(expected,0);}
            }
        };
        vector<thread> workers;
        int pool_size=min((int)seeders.size(),8);
        for(int i=0;i<pool_size;i++)workers.emplace_back(worker,i);
        for(auto& t:workers)t.join();
        if(completed_pieces.load()!=num_pieces){cerr<<"\n[download] failed to get all pieces\n";close(outfd);unlink(tmp_path.c_str());return;}
        fsync(outfd);
        SHA_CTX ctx;SHA1_Init(&ctx);
        vector<char> buf(65536);
        lseek(outfd,0,SEEK_SET);
        ssize_t r;
        while((r=read(outfd,buf.data(),buf.size()))>0)SHA1_Update(&ctx,(const unsigned char*)buf.data(),r);
        unsigned char digest[SHA_DIGEST_LENGTH];SHA1_Final(digest,&ctx);
        close(outfd);
        if(bytes_to_hex(digest,SHA_DIGEST_LENGTH)!=whole_sha){
            cerr<<"\n[download] whole-file hash mismatch!\n";unlink(tmp_path.c_str());return;
        }
        if(rename(tmp_path.c_str(),dest_path.c_str())<0){perror("rename");unlink(tmp_path.c_str());return;}
        cerr<<"\n[download] complete and verified: "<<dest_path<<"\n";
        {
            lock_guard<mutex> lk(downloads_mtx);
            ongoing_downloads.at(dl_key).is_complete=true;
            lock_guard<mutex> lk2(local_files_mtx);
            local_files[dl_key]={group,file_name,dest_path};
        }
        stringstream upl;
        upl<<"upload_file "<<group<<" "<<file_name<<" "<<file_size<<" "<<whole_sha<<" "<<num_pieces;
        for(auto& p:piece_hashes)upl<<" "<<p;
        auto [resp,final_sess]=send_request_to_tracker(session_id,upl.str());
        session_id=final_sess;
        if(resp.rfind("OK",0)==0)cerr<<"[auto-upload] registered as seeder\n";
        else cerr<<"[auto-upload] failed: "<<resp<<"\n";
    }).detach();
}
static void do_show_downloads(){
    lock_guard<mutex> lk(downloads_mtx);
    if(ongoing_downloads.empty()){cout<<"No active or completed downloads.\n";return;}
    for(const auto& [key,state]:ongoing_downloads){
        if(state.is_complete.load()){
            cout<<"[C] ["<<state.group_id<<"] "<<state.file_name<<"\n";
        }else{
            cout<<"[D] ["<<state.group_id<<"] "<<state.file_name<<" ("<<state.completed_pieces.load()<<"/"<<state.total_pieces<<" pieces)\n";
        }
    }
}
static bool send_set_addr_if_logged_in(u64& session_id){
    if(session_id==0||agreed_listen_port==0)return false;
    string local_ip="127.0.0.1";
    string cmd=string("set_addr ")+local_ip+" "+to_string(agreed_listen_port);
    auto [resp,new_sess]=send_request_to_tracker(session_id,cmd);
    if(new_sess!=0)session_id=new_sess;
    return (resp.rfind("OK",0)==0);
}
int main(int argc,char** argv){
    if(argc<2){
        cerr<<"Usage: "<<argv[0]<<" <tracker_info_file> [listen_port]\n";
        return 1;
    }
    string tracker_file=argv[1];
    ifstream infile(tracker_file);
    if(!infile.is_open()){cerr<<"Error opening tracker file: "<<tracker_file<<"\n";return 1;}
    string line;
    while(getline(infile,line)){
        size_t p=line.find(':');
        if(p!=string::npos){
            try{
                trackers.push_back({line.substr(0,p),stoi(line.substr(p+1))});
            }catch(...){}
        }
    }
    if(trackers.empty()){cerr<<"No valid trackers found in "<<tracker_file<<"\n";return 1;}
    int requested_listen=(argc>=3)?stoi(argv[2]):0;
    thread listener(peer_listener_thread,requested_listen);
    this_thread::sleep_for(chrono::milliseconds(300));
    u64 session_id=0;
    char* input;
    while((input=readline("> "))!=nullptr){
        string line(input);
        free(input);
        if(line.empty())continue;
        if(line=="quit")break;
        add_history(line.c_str());
        stringstream ss(line);
        string cmdword;ss>>cmdword;
        if(cmdword=="upload_file"){
            string group,path;ss>>group>>path;
            if(group.empty()||path.empty()){cerr<<"Usage: upload_file <group> <file_path>\n";continue;}
            if(session_id==0){cerr<<"Login required\n";continue;}
            do_upload_file(session_id,group,path);
        }else if(cmdword=="download_file"){
            string group,fname,dest;ss>>group>>fname>>dest;
            if(group.empty()||fname.empty()||dest.empty()){cerr<<"Usage: download_file <group> <file_name> <destination_path>\n";continue;}
            if(session_id==0){cerr<<"Login required\n";continue;}
            do_download_file_parallel(session_id,group,fname,dest);
        }else if(cmdword=="show_downloads"){
            do_show_downloads();
        }else{
            auto [resp,new_sess]=send_request_to_tracker(session_id,line);
            if(new_sess!=0)session_id=new_sess;
            cout<<"< "<<resp;
            if(!resp.empty()&&resp.back()!='\n')cout<<"\n";
            if(cmdword=="login"&&resp.rfind("OK",0)==0){
                if(send_set_addr_if_logged_in(session_id))cerr<<"[main] registered listening address with tracker\n";
                else cerr<<"[main] failed to register listening address\n";
            }
        }
    }
    stop_peer_listener.store(true);
    if(peer_listen_fd>0){shutdown(peer_listen_fd,SHUT_RDWR);}
    if(listener.joinable())listener.join();
    cout<<"\nClient exiting\n";
    return 0;
}
