#pragma once

#include "secure_crypto.hpp"
#include <gmp.h>
#include <stdexcept>
#include <string>

struct ElGamalCipher { std::string c1, c2; };
struct ElGamalSignature { std::string r, s; };

class ElGamalKey {
    mpz_t p_, g_, private_, public_;

    static const char *primeHex() {
        return "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
               "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
               "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF";
    }

    static void powMod(mpz_t result, const mpz_t baseInput, const mpz_t exponentInput, const mpz_t modulus) {
        mpz_t base, exponent; mpz_inits(base, exponent, nullptr);
        mpz_mod(base, baseInput, modulus); mpz_set(exponent, exponentInput); mpz_set_ui(result, 1);
        while(mpz_sgn(exponent)>0){if(mpz_odd_p(exponent)){mpz_mul(result,result,base);mpz_mod(result,result,modulus);}mpz_mul(base,base,base);mpz_mod(base,base,modulus);mpz_fdiv_q_2exp(exponent,exponent,1);}
        mpz_clears(base, exponent, nullptr);
    }

    static bool inverse(mpz_t result, const mpz_t value, const mpz_t modulus) {
        mpz_t oldR,r,oldS,s,q,temp;mpz_inits(oldR,r,oldS,s,q,temp,nullptr);
        mpz_set(oldR,modulus);mpz_mod(r,value,modulus);mpz_set_ui(oldS,0);mpz_set_ui(s,1);
        while(mpz_sgn(r)){mpz_fdiv_q(q,oldR,r);mpz_mul(temp,q,r);mpz_sub(temp,oldR,temp);mpz_set(oldR,r);mpz_set(r,temp);mpz_mul(temp,q,s);mpz_sub(temp,oldS,temp);mpz_set(oldS,s);mpz_set(s,temp);}
        bool ok=mpz_cmp_ui(oldR,1)==0;if(ok)mpz_mod(result,oldS,modulus);mpz_clears(oldR,r,oldS,s,q,temp,nullptr);return ok;
    }

    static bool randomRange(mpz_t result, const mpz_t upperExclusive) {
        std::size_t bytes=(mpz_sizeinbase(upperExclusive,2)+7)/8;std::string random=randomBytes(bytes+16);if(random.empty())return false;
        mpz_import(result,random.size(),1,1,1,0,random.data());mpz_mod(result,result,upperExclusive);return true;
    }
    static std::string toHex(const mpz_t value){char *raw=mpz_get_str(nullptr,16,value);std::string result(raw);void(*freeFunction)(void*,size_t);mp_get_memory_functions(nullptr,nullptr,&freeFunction);freeFunction(raw,result.size()+1);return result;}
    static bool fromHex(mpz_t value,const std::string &text){return !text.empty()&&mpz_set_str(value,text.c_str(),16)==0;}
    static void importBytes(mpz_t value,const std::string &bytes){mpz_import(value,bytes.size(),1,1,1,0,bytes.data());}

public:
    ElGamalKey(){mpz_inits(p_,g_,private_,public_,nullptr);mpz_set_str(p_,primeHex(),16);mpz_set_ui(g_,2);mpz_t range;mpz_init(range);mpz_sub_ui(range,p_,3);if(!randomRange(private_,range)){mpz_clear(range);throw std::runtime_error("secure random generation failed");}mpz_add_ui(private_,private_,2);powMod(public_,g_,private_,p_);mpz_clear(range);}
    ~ElGamalKey(){mpz_clears(p_,g_,private_,public_,nullptr);}
    ElGamalKey(const ElGamalKey&)=delete;ElGamalKey&operator=(const ElGamalKey&)=delete;
    std::string publicHex()const{return toHex(public_);}
    static unsigned securityBits(){return 2048;}

    ElGamalCipher encrypt(const std::string &message,const std::string &publicHex)const{
        mpz_t y,m,k,range,c1,shared,c2;mpz_inits(y,m,k,range,c1,shared,c2,nullptr);bool ok=fromHex(y,publicHex)&&mpz_cmp_ui(y,1)>0&&mpz_cmp(y,p_)<0;importBytes(m,message);mpz_sub_ui(range,p_,3);ok=ok&&randomRange(k,range);ElGamalCipher out;if(ok){mpz_add_ui(k,k,2);powMod(c1,g_,k,p_);powMod(shared,y,k,p_);mpz_mul(c2,m,shared);mpz_mod(c2,c2,p_);out={toHex(c1),toHex(c2)};}mpz_clears(y,m,k,range,c1,shared,c2,nullptr);return out;}
    bool decrypt(const ElGamalCipher &cipher,std::string &message,std::size_t size)const{
        mpz_t c1,c2,shared,inverted,m;mpz_inits(c1,c2,shared,inverted,m,nullptr);bool ok=fromHex(c1,cipher.c1)&&fromHex(c2,cipher.c2)&&mpz_cmp_ui(c1,0)>0&&mpz_cmp(c1,p_)<0&&mpz_sgn(c2)>=0&&mpz_cmp(c2,p_)<0; if(ok){powMod(shared,c1,private_,p_);ok=inverse(inverted,shared,p_);}if(ok){mpz_mul(m,c2,inverted);mpz_mod(m,m,p_);message.assign(size,'\0');std::size_t written=0;std::string temporary(size,'\0');mpz_export(&temporary[0],&written,1,1,1,0,m);if(written>size)ok=false;else std::copy(temporary.begin(),temporary.begin()+written,message.begin()+size-written);}mpz_clears(c1,c2,shared,inverted,m,nullptr);return ok;}
    ElGamalSignature sign(const std::string &digest)const{
        mpz_t h,k,pMinus1,gcd,inverted,r,s,temp;mpz_inits(h,k,pMinus1,gcd,inverted,r,s,temp,nullptr);importBytes(h,digest);mpz_sub_ui(pMinus1,p_,1);bool ok=false;do{ok=randomRange(k,pMinus1);if(!ok)break;mpz_gcd(gcd,k,pMinus1);}while(mpz_cmp_ui(k,1)<0||mpz_cmp_ui(gcd,1)!=0);ElGamalSignature out;if(ok){powMod(r,g_,k,p_);inverse(inverted,k,pMinus1);mpz_mul(temp,private_,r);mpz_sub(temp,h,temp);mpz_mul(s,temp,inverted);mpz_mod(s,s,pMinus1);out={toHex(r),toHex(s)};}mpz_clears(h,k,pMinus1,gcd,inverted,r,s,temp,nullptr);return out;}
    bool verify(const std::string &digest,const ElGamalSignature &signature,const std::string &publicHex)const{
        mpz_t h,r,s,y,pMinus1,left,yr,rs,right;mpz_inits(h,r,s,y,pMinus1,left,yr,rs,right,nullptr);importBytes(h,digest);mpz_sub_ui(pMinus1,p_,1);bool ok=fromHex(r,signature.r)&&fromHex(s,signature.s)&&fromHex(y,publicHex)&&mpz_cmp_ui(r,0)>0&&mpz_cmp(r,p_)<0&&mpz_sgn(s)>=0&&mpz_cmp(s,pMinus1)<0&&mpz_cmp_ui(y,1)>0&&mpz_cmp(y,p_)<0; if(ok){powMod(left,g_,h,p_);powMod(yr,y,r,p_);powMod(rs,r,s,p_);mpz_mul(right,yr,rs);mpz_mod(right,right,p_);ok=mpz_cmp(left,right)==0;}mpz_clears(h,r,s,y,pMinus1,left,yr,rs,right,nullptr);return ok;}
};
