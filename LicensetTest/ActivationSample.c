/*
* Sentinel LDK Activation Sample
*
* Copyright (C) 2024 THALES. All rights reserved.
*
* 
*/

#ifndef _UNICODE
#define _UNICODE
#endif
#ifndef UNICODE
#define UNICODE
#endif

#include <tchar.h>
#include <stdio.h>
#include <conio.h>
#include <windows.h>
#include <wininet.h>
#include <string.h>
#include "hasp_api.h"
#include "ActivationSample.h"
#pragma comment(lib, "Wininet")


#define CUST_LOGIN_BODY_LEN              501
#define CUST_LOGIN_PK_BODY_LEN           500
#define CUST_LOGIN_PK_BODY_KEY_LEN       256
#define HTTP_RES_STATUS_CODE_LEN         128
#define HTTP_RES_STATUS_CODE_TEXT_LEN   1024
#define HTTP_RES_CONTENT_LENGTH_LEN     1024
#define HTTP_REQ_UNICODE_HEADERS_LEN     256
#define HTTP_CONFIG_FILE_LINE_LEN        501
#define HTTP_CONFIG_FILE_LINE_BUFF_LEN   500

/*
* This sample, does the following:
* 1. Logs in to the LDK-EMS server via web service.
* 2. Checks if customer registration is needed, if so it will register the customer details via web service.
* 3. Reads the C2V (fingerprint)
* 4. Activates the key.
*/
WCHAR *url;
WCHAR *email;
WCHAR *first_name;
WCHAR *last_name;
WCHAR *product_key;

const WCHAR* HTTP_METHOD_POST = L"POST";
const WCHAR* HTTP_METHOD_PUT = L"PUT";
/*DEMOMA vendor code*/
const char* VENDOR_CODE = "AzIceaqfA1hX5wS+M8cGnYh5ceevUnOZIzJBbXFD6dgf3tBkb9cvUF/Tkd/iKu2fsg9wAysYKw7RMAsVvIp4KcXle/v1RaXrLVnNBJ2H2DmrbUMOZbQUFXe698qmJsqNpLXRA367xpZ54i8kC5DTXwDhfxWTOZrBrh5sRKHcoVLumztIQjgWh37AzmSd1bLOfUGI0xjAL9zJWO3fRaeB0NS2KlmoKaVT5Y04zZEc06waU2r6AU2Dc4uipJqJmObqKM+tfNKAS0rZr5IudRiC7pUwnmtaHRe5fgSI8M7yvypvm+13Wm4Gwd4VnYiZvSxf8ImN3ZOG9wEzfyMIlH2+rKPUVHI+igsqla0Wd9m7ZUR9vFotj1uYV0OzG7hX0+huN2E/IdgLDjbiapj1e2fKHrMmGFaIvI6xzzJIQJF9GiRZ7+0jNFLKSyzX/K3JAyFrIPObfwM+y+zAgE1sWcZ1YnuBhICyRHBhaJDKIZL8MywrEfB2yF+R3k9wFG1oN48gSLyfrfEKuB/qgNp+BeTruWUk0AwRE9XVMUuRbjpxa4YA67SKunFEgFGgUfHBeHJTivvUl0u4Dki1UKAT973P+nXy2O0u239If/kRpNUVhMg8kpk7s8i6Arp7l/705/bLCx4kN5hHHSXIqkiG9tHdeNV8VYo5+72hgaCx3/uVoVLmtvxbOIvo120uTJbuLVTvT8KtsOlb3DxwUrwLzaEMoAQAFk6Q9bNipHxfkRQER4kR7IYTMzSoW5mxh3H9O8Ge5BqVeYMEW36q9wnOYfxOLNw6yQMf8f9sJN4KhZty02xm707S7VEfJJ1KNq7b5pP/3RjE0IKtB2gE6vAPRvRLzEohu0m7q1aUp8wAvSiqjZy7FLaTtLEApXYvLvz6PEJdj4TegCZugj7c8bIOEqLXmloZ6EgVnjQ7/ttys7VFITB3mazzFiyQuKf4J6+b/a/Y";
/*registration indication flags values*/
const int REG_NOTREQUIRED=1;
const int REG_DESIRED=2;
const int REG_MANDATORY=3;
/*the jsessionid for initiating WS calls to the LDK-EMS server*/
char *j_session_id=NULL;
/*flag indicating if registration is needed*/
int reg_required;
int server_port;
WCHAR* protocol;

/*
* Registers the customer
*/
static void register_customer(WCHAR* customer_xml){
   WCHAR* uri;
   char* res;

   uri = L"ems/v21/ws/customer.ws";
   res = send_request(url,customer_xml,uri,HTTP_METHOD_PUT);
   if(res == NULL || !strcmp(res, "")){
      printf("Registration succeeded.\n");
   }else{
      printf("Registration failed.\n");
   }
   if (res != NULL) {
      free(res);
      res = NULL;
   }
}

/*
* Displays welcome message
*/
static void print_welcome_message(void){
   printf("\nWelcome to the Activation Sample!\n");
   printf("\n");
   printf("If a HL or SL key exists on this machine then use \nGet Pending Updates by KeyID.\n");
   printf("\nIf no key exists on this machine use \nProduct Key Activation.\n");
   printf("\nEnter '1' for Product Key Activation\n");
   printf("\nOR\n");
   printf("\nEnter '2' for Get Pending Updates by KeyID\n");
}

/*
* Displays welcome message for V2CP
*/
static void create_message_for_V2CP() {

   printf("\nThis sample demonstrates the steps required to get pending updates for\n HL or SL(AdminMode/UserMode) Key and apply them. \n");
   printf("1. Use hasp_get_info() API to retrieve the C2V of selected key id. \n");
   printf("2. Use get pending updates WS to get V2CP file.\n");
   printf("3. Apply the V2CP file using the hasp_update() API.\n");
   printf("\n");
   printf("Press <Enter> to continue.");
}

/**
* Displays message for activation flow.
* 
*/
static void create_message_for_PK() {

   printf("\nThis sample demonstrates the steps required to activate an SL license and\n register an end user.\n");
   printf("1. You first use the \"hasp_get_info\" function to retrieve a fingerprint \nof the end user's computer. \n");
   printf("2. The fingerprint is used together with a Product Key in Sentinel LDK-EMS to \ngenerate an Activation V2C file.\n");
   printf("3. Next, you apply the V2C file to the end user's computer using the \n\"hasp_update\" function.\n");
   printf("\n");
   printf("Note:\n");
   printf("Sentinel LDK-EMS URL, Entitlement Product Key and Registration info are \nconfigurable in the activation.properties file.\n");
   printf("\n");
   printf("Press <Enter> to continue.");
}

/*
* gets the V2C from the server
*/
static char* get_c2v_from_response(char* response){
   char* escapedV2C = NULL;
   get_xml_tag_val(response, "activationString", &escapedV2C);
   escapedV2C = replace_all(escapedV2C,"&gt;",">");
   escapedV2C = replace_all(escapedV2C,"&lt;","<");
   escapedV2C = replace_all(escapedV2C,"&quot;","\"");
   return escapedV2C;
}

/*
* Replaces a substring with another substring
*/
static char *replace_all(const char *s, const char *old, const char *_new){  
   size_t slen = strlen(s)+1;
   char *cout = (char*)malloc(slen), *p=cout;
   size_t  tmp_size;

   if( !p ) {
      return 0;
   }
   while( *s )
      if(!strncmp(s, old, strlen(old)) ) {
         p = (char*)(p - cout);
         cout= realloc(cout, slen += strlen(_new)-strlen(old) );
         p=cout+(size_t)p ;
         tmp_size = strlen(memcpy(p,_new,strlen(_new)+1) );
         p  +=  tmp_size;
         s  += strlen(old);
      }else {
         *p++=*s++; 
      }
      *p=0;
      return cout;
} 

static WCHAR *replace_all_unicode(const WCHAR *s, const WCHAR *old, const WCHAR *_new){  
   size_t slen = wcslen(s)+1;  
   WCHAR *cout = (WCHAR*)malloc(slen*sizeof(WCHAR));
   WCHAR* p=cout;
   size_t  tmp_size;

   if( !p ) {
      return 0;
   }
   while( *s )
      if( !wcsncmp(s, old, wcslen(old)) ) {
         p = (WCHAR*)(p - cout);
         slen += wcslen(_new)-wcslen(old);
         cout= realloc(cout, slen*sizeof(WCHAR) );
         p=cout+(size_t)p;
         tmp_size = wcslen(memcpy(p,_new,(wcslen(_new)*sizeof(WCHAR))+sizeof(WCHAR)) );
         p  +=  tmp_size;
         s  += wcslen(old);
      }else {
         *p++=*s++;
      }
      *p=0;
      return cout;
} 

/**
* Reads list of available Keys.
*/
static void fetch_keys_list(void) {
   hasp_status_t st = HASP_STATUS_OK;
   const char* scope = 
      "<?xml version=\"1.0\" encoding=\"UTF-8\" ?>"
      "<haspscope>"
      " <license_manager hostname=\"localhost\" >"
      " <hasp key_type=\"~SL-Legacy\" />"
      " </license_manager>"
      "</haspscope>";

   char *result = NULL;
   const char *format = "<haspformat root=\"hasp_info\">"
      "<hasp>"
      "<attribute name=\"id\" />"
      "<attribute name=\"type\" />"
      "</hasp>"
      "</haspformat>";

   st = hasp_get_info(scope, format, VENDOR_CODE, &result);

   if (st) {
      printf("Failed to fetch available key list. \"hasp_get_info()\" retuned error code %d \n", st);
      return;
   } else {
      printf("HASP IDs fetched successfully.\n");
      printf(result);
   }
}

/*
* Handles the activation process by calling the LDK-EMS WebServer and updating the runtime.
*/

int david()
{
    return 2;

}
 int do_v2cp_activation(void){
   char *c2v = NULL, *res = NULL, *v2cp = NULL;
   WCHAR uri[] = L"/ems/v78/ws/activation/target.ws";
   WCHAR* req_unicode = NULL;
   hasp_status_t st = HASP_STATUS_OK;

   fetch_keys_list();

   c2v = read_c2v_from_key();
   if (c2v == NULL || !strcmp(c2v,"")) {
      return 0;
   }

   req_unicode = (WCHAR*)malloc((strlen(c2v) + 1) * sizeof(WCHAR));
   
   
   AnsiToUnicode16(c2v, req_unicode, (INT)(strlen(c2v) + 1));

   res = send_request(url, req_unicode, uri, HTTP_METHOD_POST);

   if (res != NULL) {
      if(index_of_ansi(res, "<hasp_info>", 0) >= 0) {
         //v2cp = get_c2v_from_response(res);
         v2cp = res;
         st = hasp_update(v2cp, &c2v);

         if (st) {
            printf("Updating key failed with Sentinel Runtime error code %d \n",st);
         } else {
            printf("Activation succeeded.\n");
         }
      }
      else {
         printf("Web Service response :  %s\n", res);
      }
   }
   else {
      printf("Web Service returned NULL. \n");
   }

   if (v2cp != NULL) {
      free(v2cp);
      v2cp = NULL; 
   }
   if (req_unicode != NULL) {
      free(req_unicode);
      req_unicode = NULL;
   }
   return 1;
}

/**
* Creates a customer web service request with the information loaded from the configuration file.
*/
static WCHAR* generate_customer_xml(void){
   WCHAR* cust_template;

   if(email==NULL || !wcscmp(email,L"")){
      printf("Registration failed: Customer email is null.\n");
      return L"";
   }else if(first_name==NULL || !wcscmp(first_name,L"")){
      printf("Registration failed: Customer first name is null.\n");
      return L"";
   }else if(last_name==NULL || !wcscmp(last_name,L"")){
      printf("Registration failed: Customer last name is null.\n");
      return L"";
   }


   cust_template = L"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
      L"<customer xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\"\n"
      L"    xsi:noNamespaceSchemaLocation=\"../xsd/customer.xsd\">\n"
      L"    <type>ind</type>\n"
      L"    <name></name>\n"
      L"    <enabled>true</enabled>\n"
      L"    <description></description>\n"
      L"    <crmId></crmId>\n"
      L"    <refId></refId>\n"
      L"    <phone></phone>\n"
      L"    <fax></fax>\n"
      L"    <addresses>\n"
      L"        <shippingSameAsBilling>true</shippingSameAsBilling>\n"
      L"        <address>\n"
      L"                  <type>billing</type>\n"
      L"                  <street></street>\n"
      L"                  <city></city>\n"
      L"                  <state></state>\n"
      L"                  <country></country>\n"
      L"                  <zip></zip>\n"
      L"        </address>\n"
      L"    </addresses>\n"
      L"    <defaultContact>\n"
      L"        <emailId>{EMAIL}</emailId>\n"
      L"        <firstName><![CDATA[{FIRSTNAME}]]></firstName>\n"
      L"        <middleName></middleName>\n"
      L"       <lastName><![CDATA[{LASTNAME}]]></lastName>\n"
      L"        <locale></locale>\n"
      L"    </defaultContact>\n"
      L"</customer>\n";


   cust_template = replace_all_unicode(cust_template,L"{EMAIL}",email);
   cust_template = replace_all_unicode(cust_template,L"{FIRSTNAME}",first_name);
   cust_template = replace_all_unicode(cust_template,L"{LASTNAME}",last_name);

   return cust_template;

}

/*
* Creates a web service request for activation.
* The out argument will be set with the request string and must be freed
* when no longer used.
*/
static void generate_request(char* c2v, char** out){
   char *xml_part_1,*xml_part_2;
   size_t c2v_size,template_size;

   xml_part_1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" ?>\n"
      "<activation xsi:noNamespaceSchemaLocation=\"License.xsd\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">\n"
      "<activationInput>\n"
      "<activationAttribute>\n"
      "<attributeValue>\n"
      "<![CDATA[";

   xml_part_2 = "]]> \n"
      "</attributeValue>\n"
      "<attributeName>C2V</attributeName> \n"
      "</activationAttribute>\n"
      "<comments></comments> \n"
      "</activationInput>\n"
      "</activation>\n";

   c2v_size = strlen(c2v);
   template_size = strlen(xml_part_1);
   template_size+=strlen(xml_part_2);
   *out = (char *)malloc((sizeof(char))*(c2v_size+template_size+1));

   memset(*out,'\0',c2v_size+template_size+1);

   strncat_s(*out,(sizeof(char))*(c2v_size+template_size+1),xml_part_1,strlen(xml_part_1));
   strncat_s(*out,(sizeof(char))*(c2v_size+template_size+1),c2v,strlen(c2v));
   strncat_s(*out,(sizeof(char))*(c2v_size+template_size+1),xml_part_2,strlen(xml_part_2));
}

/**
* Reads the C2V from the key
*/
static char* read_c2v_from_key(void) {
   hasp_status_t st = HASP_STATUS_OK;
   size_t haspId_size = 0, scope_size = 0;
   char *scope = NULL;
   char *result = NULL;
   char keyid[64] = "";
   const char scope1[] =
      "<?xml version=\"1.0\" encoding=\"UTF-8\" ?>"
      "<haspscope>     <hasp id=\"";
   const char scope2[] = "\" /></haspscope>";

   const char format[] = "<haspformat format=\"updateinfo\"/>" ;

   // read Hasp Id from USer input
   printf("Enter the HASP ID: ");
   scanf_s("%s", keyid, 64);

   haspId_size = strlen(keyid);
   scope_size = strlen(scope1);
   scope_size += strlen(scope2);

   scope_size = haspId_size + scope_size + 1;
   scope = (char *)malloc((sizeof(char))*(scope_size));

   memset(scope,'\0', scope_size);

   strncat_s(scope, (sizeof(char))*(scope_size), scope1, strlen(scope1));
   strncat_s(scope, (sizeof(char))*(scope_size), keyid, strlen(keyid));
   strncat_s(scope, (sizeof(char))*(scope_size), scope2, strlen(scope2));

   st = hasp_get_info(scope, format, VENDOR_CODE, &result);
   if (scope != NULL) {
      free(scope);
      scope = NULL;
   }
   if (st) {
      printf("Failed to C2V for HASP ID: %s. \"hasp_get_info()\" returned error code %d\n", keyid, st);
      return "";
   } else {
      printf("C2V fetched successfully.\n");
      printf("\n\n");
      return result;
   }
}

/*
* This function calls the LDK-EMS login by product key web service to create a working session.
* The web service returns the session id and a flag indicating if registration is required.
*/
static int customer_login(void){
   WCHAR body[CUST_LOGIN_BODY_LEN] ;
   char* login_xml;
   char *reg_req;
   char* stat = NULL;

   memset(body,'\0',CUST_LOGIN_BODY_LEN+sizeof(WCHAR));

   printf("Logging in...\n");
   if(url==L"" ||  product_key==L""){
      printf("Product key and URL cannot be null. Check the activation.cfg file.\n");
      return 0;
   }

   wcsncat_s(body,CUST_LOGIN_PK_BODY_KEY_LEN,L"productKey=",wcslen(L"productKey="));
   wcsncat_s(body,CUST_LOGIN_PK_BODY_LEN,product_key,wcslen(product_key));

   login_xml = send_request(url,body,L"ems/v21/ws/loginByProductKey.ws",HTTP_METHOD_POST);

   if(!login_xml)
      return 0;
  
   //parse the data
   get_xml_tag_val(login_xml, "stat", &stat);
   if(stat==NULL){
      return 0;
   }else{
      if(!strcmp(stat,"ok")){
         get_xml_tag_val(login_xml,"sessionId",&j_session_id);
         if(j_session_id==NULL){
            printf("Sentinel LDK-EMS error: The server did not return a session.\n");
            return 0;
         }

         get_xml_tag_val(login_xml,"regRequired",&reg_req);
         if(strcmp(reg_req,"")){
            reg_required = atoi(reg_req);
         }
         free(reg_req);
         printf("Logged in successfully.\n");
      }else{
         printf("Got the following error status from LDK-EMS server: %s\n" ,stat );
      }
      free(stat);
   }
   
   return 1;
}

/*
* Reads the value of an XML tag and sets it to the out argument.
* The out parameter must be freed when no longer in use.
*/
static void get_xml_tag_val(char *xml, char *tag_name, char** out){
   char *open_tag = NULL, *end_tag = NULL, *_out = NULL, *open_tag_p = NULL, *end_tag_p = NULL;
   size_t len = 0, open_pos = 0, end_pos = 0, sub_str_size  = 0, i = 0;

   len = strlen(tag_name);

   open_tag = (char *)malloc((sizeof(char)) * (len + 3));
   end_tag = (char *)malloc((sizeof(char)) * (len + 4));
   memset(open_tag, '\0', len + 3);
   memset(end_tag, '\0', len + 4);

   open_tag[0] = '<';
   end_tag[0] = '<';
   end_tag[1] = '/';
   for (i = 1; i <= len; i++) {
      open_tag[i] = tag_name[i - 1];
      end_tag[i+1] = tag_name[i - 1];
   }
   open_tag[len+1] = '>';
   end_tag[len+2] = '>';

   open_tag_p = strstr(xml, open_tag);
   if (!open_tag_p) {
      free(open_tag);
      free(end_tag);
      return;
   }

   end_tag_p = strstr(xml,end_tag);
   open_pos = (open_tag_p - xml) + (len + 2);
   end_pos = end_tag_p - xml;
   sub_str_size = end_pos-open_pos;
   _out = (char *)malloc((sizeof(char)) * (sub_str_size + 1));
   memset(_out, '\0', sub_str_size + 1);
   for (i = 0; i < sub_str_size; i++) {
      _out[i] = xml[open_pos + i];
   }
   _out[sub_str_size] = '\0';

   if (open_tag != NULL) {
      free(open_tag);
      open_tag = NULL;
   }
   if (end_tag != NULL) {
      free(end_tag);
      end_tag = NULL;
   }
   *out = _out;
}

/*
* Sends an HTTP request to an LDK-EMS server web service and returns the server response.
* If an error is sent back from the server the error will be printed to the console.
*/
static char* send_request(WCHAR* server, WCHAR* body, WCHAR* uri, const WCHAR* method) {
   DWORD lst_err = GetLastError();
   const WCHAR* lplpszAcceptTypes[] = {L"Accept: */*", NULL};

   HINTERNET hConn;
   HINTERNET req;
   int res = 0, indx = 0, result = 0, status_code = 0, result2 = 0, ws_polling_freq = 0;
   int content_length = 0;
   size_t szTmp = 0, szJsession = 0;

   char tmp[]="Accept: application/vnd.ems.v12\r\nContent-Type: application/xml;charset=utf-8\r\nCookie: JSESSIONID=";
   char* ret = NULL;
   DWORD dwSize = HTTP_RES_STATUS_CODE_LEN;
   DWORD dwSize2 = HTTP_RES_STATUS_CODE_TEXT_LEN;
   DWORD dwDownloaded = 0, body_len = 0, dwFlags = 0;
   DWORD dwBuffLen = sizeof (dwFlags);
   LPCWSTR outBuffer2[HTTP_RES_STATUS_CODE_TEXT_LEN];
   LPCWSTR outBuffer[HTTP_RES_STATUS_CODE_LEN];
   LPCWSTR data = NULL;

   HINTERNET hSession = InternetOpen(L"ActivationSample", INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);

   if(!hSession) {
      printf("Connection to Sentinel LDK-EMS server failed.\n");
      return NULL;
   }

   body_len = (DWORD)wcslen(body);

   hConn = InternetConnect(hSession, server, server_port, NULL, NULL, INTERNET_SERVICE_HTTP, 0, (DWORD_PTR)NULL);
   if(!hConn){
      printf("Connection to LDK-EMS server failed\n");
      return NULL;
   }
   lst_err = GetLastError();

   if(!wcscmp(protocol,L"http")){
      req = HttpOpenRequest(hConn,
         method,
         uri,
         L"HTTP/1.0",
         NULL,
         (LPCTSTR *) lplpszAcceptTypes, 
         INTERNET_FLAG_RELOAD | 
         INTERNET_FLAG_NO_CACHE_WRITE |
         INTERNET_FLAG_NO_COOKIES |
         INTERNET_FLAG_KEEP_CONNECTION,
         0);
   }else{
      req = HttpOpenRequest(hConn,
         method,
         uri,
         L"HTTP/1.0",
         NULL,
         (LPCTSTR *) lplpszAcceptTypes, 
         INTERNET_FLAG_RELOAD |  
         INTERNET_FLAG_NO_CACHE_WRITE | 
         INTERNET_FLAG_IGNORE_CERT_CN_INVALID | 
         INTERNET_FLAG_IGNORE_CERT_DATE_INVALID | 
         INTERNET_FLAG_SECURE |
         INTERNET_FLAG_NO_COOKIES |
         INTERNET_FLAG_KEEP_CONNECTION,
         0);

      InternetQueryOption (req, INTERNET_OPTION_SECURITY_FLAGS, (LPVOID) &dwFlags, &dwBuffLen); 
      dwFlags  =  SECURITY_FLAG_IGNORE_UNKNOWN_CA; 
      InternetSetOption (req, INTERNET_OPTION_SECURITY_FLAGS, &dwFlags, sizeof (dwFlags));
   }

   lst_err = GetLastError();

   if(j_session_id == NULL) {
      char *ansiBody = NULL;
      LPCWSTR headers = NULL;
      size_t req_len = body_len + 1;

      ansiBody = (char*)malloc(sizeof(char) * req_len);
      memset(ansiBody, '\0', req_len);
      //headers = L"Accept: application/vnd.ems.v12\r\nContent-Type: application/x-www-form-urlencoded"; 

      if (index_of(uri, L"target.ws", 0) > 0){
         headers = L"Accept: application/vnd.ems.v12\r\nContent-Type: application/xml; charset=utf-8";
      }
      else {
         headers = L"Accept: application/vnd.ems.v12\r\nContent-Type: application/x-www-form-urlencoded; charset=utf-8";
      }
      if(!wcscmp(method, HTTP_METHOD_POST)){
         Unicode16ToAnsi(body, ansiBody, req_len);
         res = HttpSendRequest(req, headers, (DWORD)wcslen(headers), (LPVOID)ansiBody, req_len);
      }else{
         res = HttpSendRequest(req, headers, (DWORD)wcslen(headers), (LPVOID)body, body_len*sizeof(WCHAR));
      }

      if (ansiBody != NULL) {
         free(ansiBody);
         ansiBody = NULL;
      }
   }else{
      char* utf8_body = NULL;
      char* headers;

      WCHAR unicodeHeaders[HTTP_REQ_UNICODE_HEADERS_LEN];

      szJsession = strlen(j_session_id);
      szTmp = strlen(tmp);
      headers = (char *)malloc((sizeof(char))*(szJsession+szTmp+1));
      memset(headers,'\0',szTmp+szJsession+1);
      strncat_s(headers,szTmp+szJsession+1,tmp,strlen(tmp));
      strncat_s(headers,szTmp+szJsession+1,j_session_id,strlen(j_session_id));
      AnsiToUnicode16(headers,unicodeHeaders,HTTP_REQ_UNICODE_HEADERS_LEN);
      utf8_body = (char*)to_utf8(body);
      res = HttpSendRequest(req, (LPCWSTR)unicodeHeaders, (DWORD)wcslen(unicodeHeaders), (LPVOID)utf8_body,(DWORD)strlen(utf8_body));

      free(headers);
      if(utf8_body != NULL){
         free(utf8_body);
      }
   }
   lst_err = GetLastError();

   if(res){
      result = HttpQueryInfo(req, HTTP_QUERY_STATUS_CODE, (void*)&outBuffer, &dwSize, NULL);
      status_code = _wtoi((wchar_t*)outBuffer);

      result2 = HttpQueryInfo(req, HTTP_QUERY_STATUS_TEXT , (void*)&outBuffer2, &dwSize2, NULL);
      content_length =  get_response_content_len(req);
      data = (LPCWSTR)malloc((sizeof(LPCWSTR))*(content_length+1));
      memset((void*)data, '\0', (sizeof(LPCWSTR)*(content_length + 1)));

      if (InternetQueryDataAvailable(req, &dwSize, 0, 0)) {
         WCHAR *buffer = NULL;
         indx = 0;
         buffer = (WCHAR*)malloc((sizeof(WCHAR)) * (content_length + 1));
         memset(buffer, '\0', (content_length + 1) * sizeof(WCHAR));
         dwDownloaded = 0;

         while(InternetReadFile(req, buffer, content_length, &dwDownloaded)) {
            if (dwDownloaded == 0) {
               break;
            }

            if(indx < (content_length - 1)){
               wcsncat_s((wchar_t*)data, content_length, buffer, dwDownloaded);
               indx += dwDownloaded;
            }
         }

         if (status_code != HTTP_STATUS_OK && status_code != HTTP_STATUS_CREATED) {
            printf("Sentinel LDK-EMS error: ");
            printf("%s\n",(char*)data);
         }
         if (status_code == HTTP_STATUS_OK) {
            printf("WebService Call successful: Returned status %d\n", HTTP_STATUS_OK);

            // Get polling frequency value as available in web-service response
            ws_polling_freq = get_ws_polling_frequency_time(req);
         }

         ret = _strdup((char*)data);

         if (buffer != NULL) {
            free(buffer);
            buffer = NULL;
         }
      }
      if(data != NULL){
         free((void*)data);
         data = NULL;
      }
   }else{
      lst_err = GetLastError();
      printf("Error occurred while communicating with Sentinel LDK-EMS server: %d\n",lst_err);
   }

   InternetCloseHandle(req);
   InternetCloseHandle(hConn);
   InternetCloseHandle(hSession);

   return ret;
}

static int get_response_content_len(HINTERNET req){
   int res;
   DWORD dwSize = HTTP_RES_CONTENT_LENGTH_LEN;
   wchar_t outBuffer[HTTP_RES_CONTENT_LENGTH_LEN];

   int len = 0;
   res = HttpQueryInfo(req, HTTP_QUERY_CONTENT_LENGTH, &outBuffer, &dwSize, NULL);
   if(res){
      len = _wtoi(outBuffer);
   }

   return len;
}

/**
* Get the polling frequency time(in minutes) from response, header name 'polling-frequency'
* It is set in case of successful response of web-service
* This is configurable value for ISV in LDK-EMS Admin Console
*/
int get_ws_polling_frequency_time(HINTERNET hHttp)
{
   DWORD dwSize = 18;
   int pollingFrequency = 0;

   LPVOID lpOutBuffer = (char*)malloc((dwSize) * sizeof(char));
   strcpy_s((LPSTR)lpOutBuffer, dwSize, "polling-frequency");

retry:
   if (!HttpQueryInfo(hHttp, HTTP_QUERY_CUSTOM | HTTP_QUERY_FLAG_NUMBER, (LPVOID)lpOutBuffer, &dwSize, NULL)) {

      if (GetLastError()==ERROR_HTTP_HEADER_NOT_FOUND) {
         // Code to handle the case where the header isn't available.
         free(lpOutBuffer);
         lpOutBuffer = NULL;
         return 0;
      } else {
         // Check for an insufficient buffer.
         if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
            // Allocate the necessary buffer
            free(lpOutBuffer);
            lpOutBuffer = NULL;

            dwSize += 1;
            lpOutBuffer = (char*)malloc((dwSize) * sizeof(char));

            // Rewrite the header name in the buffer.
            strcpy_s((LPSTR)lpOutBuffer, dwSize, "polling-frequency");

            // Retry the call.
            goto retry;
         } else {
            // Error handling code.
            fprintf(stderr, "\nHttpQueryInfo() failed, error = %d (0x%x)\n", GetLastError(), GetLastError());
            if (lpOutBuffer) {
               free(lpOutBuffer);
               lpOutBuffer = NULL;
            }
            return 0;
         }
      }
   }

   pollingFrequency += ((int*)lpOutBuffer)[0];
   if (lpOutBuffer) {
      free(lpOutBuffer);
      lpOutBuffer = NULL;
   }

   return pollingFrequency;
}

/**
* Reads the configuration file and sets the global variables
* The variables are freed at the end of the program.
* Note - configuration file needs to be saved as UNICODE
*/
static void read_configuration_file(void){
   FILE *in;
   LPCWSTR st[HTTP_CONFIG_FILE_LINE_LEN];
   wchar_t *return_code;
   errno_t stat;
   LPCWSTR pwcstr;

   memset((void*)st,L'\0',HTTP_CONFIG_FILE_LINE_LEN);

   stat = _wfopen_s(&in, L"activation.cfg", L"r, ccs=UNICODE");

   if(stat == 0){
      while((return_code=fgetws((wchar_t*)st, HTTP_CONFIG_FILE_LINE_BUFF_LEN, in))!=NULL){
         pwcstr = wcsstr((wchar_t*)st,L"#");

         if(pwcstr == NULL || (pwcstr-*st)> sizeof(wchar_t)){
            LPCWSTR key;
            LPCWSTR val;
            LPCWSTR tmp;
            tmp = wcsstr((wchar_t*)st, L"=" );
            if(tmp != NULL){
               key=substring((WCHAR*)st,0,(int)(tmp-(LPCWSTR)st));
               val = substring((WCHAR*)st,(int)((tmp+1)-(LPCWSTR)st),(int)wcslen((wchar_t *)st));

               if(!wcscmp(key,L"url")){
                  parse_url(_wcsdup(val));
               }else if(!wcscmp(key,L"first_name")){
                  first_name = _wcsdup(val);
               }else if(!wcscmp(key,L"last_name")){
                  last_name = _wcsdup(val);
               }else if(!wcscmp(key,L"email")){
                  email = _wcsdup(val);
               }else if(!wcscmp(key,L"product_key")){
                  product_key = _wcsdup(val);
               }
               free((void*)key);
               free((void*)val);

            }
         }
      }
   } else {
      printf("Configuration file does not exist.\n");
      return;
   }

   fclose(in);

}

/*
* parses the url to extract the protocol, host name and the port
*/
static int parse_url(LPCWSTR _url) {
   WCHAR proto[6];
   WCHAR *host,*port,*_port; 
   int pos1,pos2;
   int protocol_flag=0;

   wcsncpy_s(proto,6,_url,5);
   if(wcscmp(proto,L"http:")==0){
      protocol = L"http";
      protocol_flag = 1;
   }else if(!wcscmp(proto,L"https")){
      protocol = L"https";
      protocol_flag = 2;
   }else{
      wprintf(L"Protocol is not supported or is not specified in URL: %s\n",_url);
      wprintf(L"Press any key to exit.");
      getchar();
      exit(1);
   }

   pos1 = index_of(_url,L"://",0);
   pos2 = index_of(_url,L":",pos1+3);
   if(pos1 == -1){
      wprintf(L"Protocol is not supported: %s\n",_url);
      wprintf(L"Press any key to exit.");
      getchar();
      exit(1);
   }
   //port not specified in url
   if(pos2 == -1){
      if(protocol_flag == 1){
         server_port = 80;
      }else if(protocol_flag == 2){
         server_port = 443;
      }
      wprintf(L"Port is not specified using default %d\n",server_port);
      host = substring((WCHAR*)_url,pos1+3,(int)wcslen(_url)-1);
      url = _wcsdup(host);
   }

   //port is specified
   if(pos2 != -1){
      if(pos1+3 > pos2){
         return 0;
      }else{
         host = substring((WCHAR*)_url,pos1+3,pos2);
         url = _wcsdup(host);
         port = substring((WCHAR*)_url,pos2+1,(int)wcslen(_url));
         _port = _wcsdup(port);
         server_port = _wtoi(_port);
      }
   }
   return 0;
}

/*
* returns the substring between startPos and end_pos of the given string
*/
static WCHAR* substring(WCHAR* string, int start_pos, int end_pos) {
   int i;
   int sz;
   WCHAR* substr;
   if(end_pos < start_pos){
      return NULL;
   }

   sz = (end_pos-start_pos+1)*sizeof(WCHAR);
   substr = (WCHAR*)malloc(sz);

   if((int)wcslen(string) >= end_pos){
      for(i=0;i<(end_pos-start_pos);i++){
         substr[i] = string[start_pos+i];
      }

      substr[end_pos-start_pos]='\0';
      return substr;
   }

   return NULL;
}

/*
* returns the ordinal position of the first occurance of a substring from the startAt
* position
*/
static int index_of(LPCWSTR string, LPCWSTR sub_string, int start_at) {
   WCHAR const *p = string;
   int i,found_at = -1;
   if(wcslen(string) == 0){
      return -1;
   }
   if(start_at > (int)wcslen(string)){
      return -1;
   }
   for (i=0; ;++i){
      p = wcsstr(p, sub_string);
      if (!p){
         found_at = -1;
         break;
      }else{
         found_at = (int)(p-string);
         if(found_at >= start_at){
            break;
         }
      }
      p++;
   }
   return found_at;
}

/*
* returns the ordinal position of the first occurance of a substring from the startAt
* position
*/
static int index_of_ansi(char* string, char* sub_string, int start_at) {
   char const *p = string;
   int i,found_at = -1;
   if(strlen(string) == 0){
      return -1;
   }
   if(start_at > (int)strlen(string)){
      return -1;
   }
   for (i=0; ;++i){
      p = strstr(p, sub_string);
      if (!p){
         found_at = -1;
         break;
      }else{
         found_at = (int)(p-string);
         if(found_at >= start_at){
            break;
         }
      }
      p++;
   }
   return found_at;

}

BOOL AnsiToUnicode16(CHAR *in_src, WCHAR *out_dst, INT in_maxlen) {
   INT lv_len;

   if (in_maxlen <= 0)
      return FALSE;

   lv_len = MultiByteToWideChar(CP_ACP, 0, in_src, -1, out_dst, in_maxlen);

   // validate
   if (lv_len < 0)
      lv_len = 0;

   if (lv_len < in_maxlen)
      out_dst[lv_len] = 0;
   else if (out_dst[in_maxlen-1])
      out_dst[0] = 0;

   return TRUE;
}

BOOL Unicode16ToAnsi(WCHAR *in_src, CHAR *out_dst, INT in_maxlen) {
   INT  lv_len;
   BOOL lv_useddefault;

   if (in_maxlen <= 0)
      return FALSE;

   lv_len = WideCharToMultiByte(CP_ACP, 0, in_src, -1, out_dst, in_maxlen, 0, &lv_useddefault);

   if (lv_len == 0) {
      if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
         printf("Insufficient buffer memory for HTTP request body.\n");
         wprintf(L"Press any key to exit.");
         getchar();
         exit(1);
      }
      else {
         printf("Some error occured in HTTP request body conversion to multibyte. GetLastError() returned %d\n", GetLastError());
         wprintf(L"Press any key to exit.");
         getchar();
         exit(1);
      }
   }

   // validate
   if (lv_len < 0)
      lv_len = 0;

   if (lv_len < in_maxlen)
      out_dst[lv_len] = 0;
   else if (out_dst[in_maxlen-1])
      out_dst[0] = 0;

   return !lv_useddefault;
}

static unsigned char *to_utf8(const wchar_t *unicode_string) {
   int sz = 0;
   int index = 0;
   int index2 = 0;
   unsigned char *out;
   unsigned short c;
   c = unicode_string[index++];

   while(c) {
      if(c < 0x0080) {
         sz += 1;
      } else if(c < 0x0800) {
         sz += 2;
      } else {
         sz += 3;
      }

      c = unicode_string[index++];
   }

   out = malloc(sz + 1);
   if (out == NULL){
      return NULL;
   }

   index = 0;
   c = unicode_string[index++];

   while(c){
      if(c < 0x080) {
         out[index2++] = (unsigned char)c;
      } else if(c < 0x800) {
         out[index2++] = 0xc0 | (c >> 6);
         out[index2++] =
            0x80 | (c & 0x3f);
      } else { 
         out[index2++] = 0xe0 | (c >> 12);
         out[index2++] = 0x80 | ((c >> 6) & 0x3f);
         out[index2++] = 0x80 | (c & 0x3f);
      }

      c = unicode_string[index++];
   }

   out[index2] = 0x00;
   return out;

} 

/**
* Reads the C2V from the key - in our case fingerprint
*/
static char* read_fingerprint(void){
   hasp_status_t st;
   const char *scope=
      "<?xml version=\"1.0\" encoding=\"UTF-8\" ?>"
      "<haspscope>"
      "<license_manager hostname=\"localhost\" />"
      "</haspscope>";

   char *result;
   const char *view = "<haspformat format=\"host_fingerprint\"/>";
   st=hasp_get_info(scope, view, VENDOR_CODE, &result);

   if (st){
      printf("Failed to read C2V file. Sentinel Runtime error code %d\n",st);
      return "";

   }else{
      printf("C2V file read successfully.\n");
      return result;
   }
}


/*
* Handles the activation process by calling the LDK-EMS webserver and updating the runtime.
*/
static int do_activation(void){
   char *req = NULL, *c2v = NULL, *res = NULL, *v2c = NULL;
   WCHAR tmp[] = L"/ems/v21/ws/productKey/{PK_ID}/activation.ws";
   WCHAR* uri = NULL;
   WCHAR* req_unicode = NULL;
   hasp_status_t st = HASP_STATUS_OK;

   c2v = read_fingerprint();
   if(c2v == NULL || !strcmp(c2v,"")){
      return 0;
   }

   generate_request(c2v, &req);
   req_unicode = (WCHAR*)malloc((strlen(req)+1)*sizeof(WCHAR));
   AnsiToUnicode16(req,req_unicode,(INT)(strlen(req)+1));

   uri = replace_all_unicode(tmp,L"{PK_ID}",product_key);
   res = send_request(url,req_unicode,uri,HTTP_METHOD_POST);

   if(index_of_ansi(res,"<activation>",0) >= 0){
      v2c = get_c2v_from_response(res);
      st = hasp_update(v2c, &c2v);

      if(st){
         printf("Updating key failed with Sentinel Runtime error code %d \n",st);
      }else{
         printf("Activation succeeded.\n");
      }
   }

   if (uri != NULL) {
      free(uri);
   }
   if (v2c != NULL) {
      free(v2c);
   }
   if (res != NULL) {
      free(res);
   }
   if (req != NULL) {
      free(req);
   }
   if (req_unicode != NULL) {
      free(req_unicode);
   }
   return 1;
}

int _tmain(int argc, _TCHAR* argv[]) {
   WCHAR* customer_xml = NULL;
   char inputType = '0';

   print_welcome_message();
   read_configuration_file();
   inputType = getchar();
   if (inputType == '1') {
      create_message_for_PK();
      
      if (customer_login()) {
         if (reg_required == REG_MANDATORY || reg_required == REG_DESIRED){
            if (reg_required == REG_MANDATORY) {
               printf("Registration is required.\n");
            } else {
               printf("Registration is desired.\n");
            }
            //registering
            customer_xml = generate_customer_xml();
            if (customer_xml == L"") {
               printf("Error occurred while creating customer registration data. Check the configuration file.\n");
               system("pause");
               return 1;
            }
            register_customer(customer_xml);
         }else if(reg_required == REG_DESIRED) {
            printf("Registration is desired. Bypassing registration.\n");
         }
         do_activation();
      }
   }
   else if (inputType == '2') {
      create_message_for_V2CP();
      do_v2cp_activation();
   }
   else {
      printf("WRONG INPUT PROVIDED.");
      return 1;
   }   
   free(product_key);
   free(email);
   free(first_name);
   free(last_name);
   system("pause");
   return 0;
}