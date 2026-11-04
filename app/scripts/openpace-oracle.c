/* Independent offline card-side oracle. Synthetic CAN only, no PC/SC linkage. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <eac/eac.h>
#include <eac/pace.h>
#include <eac/objects.h>
#include <openssl/buffer.h>
#define REQUIRE(x) do { if(!(x)){fprintf(stderr,"oracle failure at line %d\n",__LINE__);return 1;} }while(0)
static BUF_MEM *buf(const unsigned char *p,size_t n){BUF_MEM*b=BUF_MEM_new();BUF_MEM_grow(b,n);memcpy(b->data,p,n);return b;}
static void reply(const unsigned char *p,size_t n){for(size_t i=0;i<n;i++)printf("%02X",p[i]);puts("9000");fflush(stdout);}
static void ga(int tag,BUF_MEM*b){unsigned char out[512];size_t n=0;out[n++]=0x7c;out[n++]=b->length+2;out[n++]=tag;out[n++]=b->length;memcpy(out+n,b->data,b->length);reply(out,n+b->length);BUF_MEM_free(b);}
int main(void){
 EAC_init();EAC_CTX*ctx=EAC_CTX_new();REQUIRE(ctx);
 REQUIRE(EAC_CTX_init_pace(ctx,EAC_OBJ_txt2nid("0.4.0.127.0.7.2.2.4.2.4"),15));
 PACE_SEC*secret=PACE_SEC_new("123456",6,PACE_CAN);REQUIRE(secret);
 char line[4096];unsigned char in[2048];BUF_MEM*peer=NULL;
 int step=0;
 while(fgets(line,sizeof(line),stdin)){
  size_t len=strcspn(line,"\r\n")/2;REQUIRE(len<sizeof(in));for(size_t i=0;i<len;i++){unsigned v;REQUIRE(sscanf(line+2*i,"%2x",&v)==1);in[i]=v;}
  if(step==0){REQUIRE(in[1]==0x22);reply(NULL,0);}
  else if(step==1){BUF_MEM*b=PACE_STEP1_enc_nonce(ctx,secret);REQUIRE(b);ga(0x80,b);}
  else if(step==2){BUF_MEM*b=PACE_STEP3A_generate_mapping_data(ctx);REQUIRE(b);BUF_MEM*p=buf(in+9,in[8]);REQUIRE(PACE_STEP3A_map_generator(ctx,p));BUF_MEM_free(p);ga(0x82,b);}
  else if(step==3){BUF_MEM*b=PACE_STEP3B_generate_ephemeral_key(ctx);REQUIRE(b);peer=buf(in+9,in[8]);REQUIRE(PACE_STEP3B_compute_shared_secret(ctx,peer));REQUIRE(PACE_STEP3C_derive_keys(ctx));ga(0x84,b);}
  else if(step==4){BUF_MEM*p=buf(in+9,in[8]);REQUIRE(PACE_STEP3D_verify_authentication_token(ctx,p)==1);BUF_MEM_free(p);BUF_MEM*b=PACE_STEP3D_compute_authentication_token(ctx,peer);REQUIRE(b);ga(0x86,b);REQUIRE(EAC_CTX_set_encryption_ctx(ctx,EAC_ID_PACE));}
  else{
   REQUIRE(in[0]==0x0c&&(in[1]==0xb0||in[1]==0xa4));
   REQUIRE(EAC_increment_ssc(ctx));
   size_t data_len=in[4]-10;REQUIRE(in[5+data_len]==0x8e&&in[6+data_len]==8);
   unsigned char signed_data[512]={0};memcpy(signed_data,in,4);signed_data[4]=0x80;memcpy(signed_data+16,in+5,data_len);
   BUF_MEM*d=buf(signed_data,16+data_len);BUF_MEM*m=buf(in+7+data_len,8);
   BUF_MEM*command_padded=EAC_add_iso_pad(ctx,d);REQUIRE(EAC_verify_authentication(ctx,command_padded,m)==1);BUF_MEM_free(command_padded);BUF_MEM_free(d);BUF_MEM_free(m);
   if(in[1]==0xa4){
    REQUIRE(in[5]==0x87&&in[7]==1);BUF_MEM*cipher=buf(in+8,in[6]-1);BUF_MEM*plain=EAC_decrypt(ctx,cipher);REQUIRE(plain);BUF_MEM*decoded=EAC_remove_iso_pad(plain);
    unsigned char aid[]={0xa0,0,0,2,0x47,0x10,1};REQUIRE(decoded&&decoded->length==7&&!memcmp(decoded->data,aid,7));BUF_MEM_free(cipher);BUF_MEM_free(plain);BUF_MEM_free(decoded);
   }
   REQUIRE(EAC_increment_ssc(ctx));unsigned char response[128];size_t n=0;
   if(in[1]==0xb0){unsigned char plain[]={1,2,3,4};d=buf(plain,4);BUF_MEM*padded=EAC_add_iso_pad(ctx,d);BUF_MEM*encrypted=EAC_encrypt(ctx,padded);REQUIRE(encrypted);
    response[n++]=0x87;response[n++]=17;response[n++]=1;memcpy(response+n,encrypted->data,encrypted->length);n+=encrypted->length;BUF_MEM_free(d);BUF_MEM_free(padded);BUF_MEM_free(encrypted);}
   response[n++]=0x99;response[n++]=2;response[n++]=0x90;response[n++]=0;
   BUF_MEM*auth=buf(response,n);BUF_MEM*auth_padded=EAC_add_iso_pad(ctx,auth);BUF_MEM*tag=EAC_authenticate(ctx,auth_padded);BUF_MEM_free(auth_padded);REQUIRE(tag&&tag->length==8);response[n++]=0x8e;response[n++]=8;memcpy(response+n,tag->data,8);reply(response,n+8);
   BUF_MEM_free(auth);BUF_MEM_free(tag);
  }
  step++;
 }
 BUF_MEM_free(peer);PACE_SEC_clear_free(secret);EAC_CTX_clear_free(ctx);EAC_cleanup();return 0;
}
