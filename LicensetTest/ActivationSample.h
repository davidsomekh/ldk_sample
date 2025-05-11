/*
* Sentinel LDK Activation Sample Header File
*
* Copyright (C) 2024 THALES. All rights reserved.
*
* 
*/


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include "hasp_api.h"         // For hasp_update and hasp_status_t

int david();

void clean_val(char *val, char** var);
void print_welcome_message(void);
void create_message_for_V2CP(void);
void create_message_for_PK(void);
void read_configuration_file(void);
void fetch_keys_list(void);
char* read_fingerprint(void);
int customer_login(void);
static char* send_request(WCHAR* server,WCHAR* body,WCHAR* uri,const WCHAR* method);
void get_xml_tag_val(char *xml, char *tag_name, char** out);
char* read_c2v_from_key(void);
WCHAR* generate_customer_xml(void);
int do_activation(void);
int do_v2cp_activation(void);
void generate_request(char* c2v, char** out);
void register_customer(WCHAR* customer_xml);
char* get_c2v_from_response(char* response);
char *replace_all ( const char *string, const char *substr, const char *replacement );
int parse_url(LPCWSTR _url);
int index_of(LPCWSTR string, LPCWSTR sub_string, int start_at);
WCHAR *substring(WCHAR* string, int start_pos, int endt_pos);
int get_response_content_len(HINTERNET req);
int get_ws_polling_frequency_time(HINTERNET req);
BOOL AnsiToUnicode16(CHAR *in_src, WCHAR *out_dst, INT in_maxlen);
BOOL Unicode16ToAnsi(WCHAR *in_src, CHAR *out_dst, INT in_maxlen);
WCHAR *replace_all_unicode(const WCHAR *s, const WCHAR *old, const WCHAR *_new);
static unsigned char *to_utf8(const wchar_t *unicode_string);
static int index_of_ansi(char* string, char* sub_string, int start_at);
