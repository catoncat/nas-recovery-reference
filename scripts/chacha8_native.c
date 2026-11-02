/* ChaCha8, original 64-bit nonce/counter layout. No persistent key state.
 * SSE2 lanes are four independent blocks; scalar code handles short tails.
 * ABI caller validates lengths/counter range before entering this function. */
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#if defined(__SSE2__)
#include <emmintrin.h>
#endif
static uint32_t load32(const uint8_t *p) {
    return (uint32_t)p[0] | (uint32_t)p[1]<<8 | (uint32_t)p[2]<<16 | (uint32_t)p[3]<<24;
}
static uint32_t rol(uint32_t x, unsigned n) { return (x<<n)|(x>>(32-n)); }
#define QR(a,b,c,d) do { a+=b; d=rol(d^a,16); c+=d; b=rol(b^c,12); a+=b; d=rol(d^a,8); c+=d; b=rol(b^c,7); } while(0)
#define ROUNDS(Q,x) for (unsigned r=0;r<4;r++) { \
    Q(x[0],x[4],x[8],x[12]); Q(x[1],x[5],x[9],x[13]); \
    Q(x[2],x[6],x[10],x[14]); Q(x[3],x[7],x[11],x[15]); \
    Q(x[0],x[5],x[10],x[15]); Q(x[1],x[6],x[11],x[12]); \
    Q(x[2],x[7],x[8],x[13]); Q(x[3],x[4],x[9],x[14]); }
#if defined(__SSE2__)
#define ADD(a,b) _mm_add_epi32(a,b)
#define XOR(a,b) _mm_xor_si128(a,b)
#define ROT(a,n) _mm_or_si128(_mm_slli_epi32(a,n),_mm_srli_epi32(a,32-n))
#define VQR(a,b,c,d) do { a=ADD(a,b); d=ROT(XOR(d,a),16); c=ADD(c,d); b=ROT(XOR(b,c),12); a=ADD(a,b); d=ROT(XOR(d,a),8); c=ADD(c,d); b=ROT(XOR(b,c),7); } while(0)
static void four(uint8_t *dst,const uint8_t *src,const uint32_t fixed[16],uint64_t counter) {
    __m128i x[16];
    for(unsigned i=0;i<16;i++) x[i]=_mm_set1_epi32((int)fixed[i]);
    __m128i lo=_mm_set_epi32((int)(uint32_t)(counter+3),(int)(uint32_t)(counter+2),(int)(uint32_t)(counter+1),(int)(uint32_t)counter);
    __m128i hi=_mm_set_epi32((int)((counter+3)>>32),(int)((counter+2)>>32),(int)((counter+1)>>32),(int)(counter>>32));
    x[12]=lo; x[13]=hi;
    ROUNDS(VQR,x);
    for(unsigned i=0;i<16;i++) x[i]=ADD(x[i],i==12?lo:i==13?hi:_mm_set1_epi32((int)fixed[i]));
    for(unsigned i=0;i<16;i+=4) {
        __m128i a=_mm_unpacklo_epi32(x[i],x[i+1]), b=_mm_unpackhi_epi32(x[i],x[i+1]);
        __m128i c=_mm_unpacklo_epi32(x[i+2],x[i+3]), d=_mm_unpackhi_epi32(x[i+2],x[i+3]);
        __m128i words[4]={_mm_unpacklo_epi64(a,c),_mm_unpackhi_epi64(a,c),_mm_unpacklo_epi64(b,d),_mm_unpackhi_epi64(b,d)};
        for(unsigned lane=0;lane<4;lane++) {
            size_t off=lane*64+i*4;
            _mm_storeu_si128((__m128i *)(dst+off),XOR(words[lane],_mm_loadu_si128((const __m128i *)(src+off))));
        }
    }
}
#endif
int c3rb3r_chacha8_abi(void) { return 1; }
const char *c3rb3r_chacha8_backend(void) {
#if defined(__SSE2__)
    return "c-sse2-4block";
#else
    return "c-scalar";
#endif
}
int c3rb3r_chacha8_xor(uint8_t *dst,const uint8_t *src,size_t n,const uint8_t *key,const uint8_t *nonce,uint64_t counter) {
    uint32_t fixed[16]={0x61707865,0x3320646e,0x79622d32,0x6b206574};
    for(unsigned i=0;i<8;i++) fixed[4+i]=load32(key+4*i);
    fixed[14]=load32(nonce); fixed[15]=load32(nonce+4);
#if defined(__SSE2__)
    while(n>=256) { four(dst,src,fixed,counter); src+=256; dst+=256; n-=256; counter+=4; }
#endif
    while(n) {
        uint32_t x[16]; uint8_t stream[64];
        fixed[12]=(uint32_t)counter; fixed[13]=(uint32_t)(counter>>32);
        memcpy(x,fixed,sizeof x); ROUNDS(QR,x);
        for(unsigned i=0;i<16;i++) {
            uint32_t word=x[i]+fixed[i];
            for(unsigned j=0;j<4;j++) stream[4*i+j]=(uint8_t)(word>>(8*j));
        }
        size_t take=n<64?n:64;
        for(size_t i=0;i<take;i++) dst[i]=src[i]^stream[i];
        src+=take; dst+=take; n-=take; counter++;
    }
    return 0;
}
