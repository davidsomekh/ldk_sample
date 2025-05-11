#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <windows.h>
#include <wininet.h>

#pragma comment(lib, "wininet.lib")


#define CUST_LOGIN_BODY_LEN              501
#define CUST_LOGIN_PK_BODY_LEN           500
#define CUST_LOGIN_PK_BODY_KEY_LEN       256
#define HTTP_RES_STATUS_CODE_LEN         128
#define HTTP_RES_STATUS_CODE_TEXT_LEN   1024
#define HTTP_RES_CONTENT_LENGTH_LEN     1024
#define HTTP_REQ_UNICODE_HEADERS_LEN     256
#define HTTP_CONFIG_FILE_LINE_LEN        501
#define HTTP_CONFIG_FILE_LINE_BUFF_LEN   500

const WCHAR* HTTP_METHOD_POST = L"POST";

char* j_session_id = NULL;
const WCHAR* HTTP_METHOD_PUT = L"PUT";

int server_port = 8080;
const WCHAR* protocol = L"http";


WCHAR url[] = L"localhost";

int reg_required;

WCHAR product_key[] = L"fef57400-2667-4dc7-8eb6-b7e36ca02626";


#include "hasp_api.h"         // For hasp_update and hasp_status_t

// If send_request uses WinINet or WinHTTP internally, also include one of these:
// #include <wininet.h>         // For WinINet (if needed)
// #include <windows.h>         // For Windows API types

const char* VENDOR_CODE = "mIquiG/O128okER101YRGPcH+VEwwSc3g8hk3oUfNAwKFzBV+Cq4lKCuFwBCcaasMG5niofd6qpSV9LE"
        "pGa+5AwbPo3aCbHwlGnBzV3oMM8dPZyuW2gwYDdiKitxieAkNs6HluLL8xoksBo5+lNS/yHfCjdjfuoe"
        "R8Cc+atTSONBsQUg9AVgC5P0w7kIsnKRWmKCxPJ9rLohKhB2+DmIGzS6dkyoqtaxZsw5/hIsHhajz0jy"
        "NOjClSaTaHNkiqdHhRsCrYTI51vIIUxqxaEFVWbOXbR4mfeTo+/ml/lAxARz75MgTVLQoyS/Xm+1TV/j"
        "sYY1PoyHhSED5EnewiXASBwDxwL4wSlqu2mbIxP5UlNMjprMsWmgN4/ACwVqewqif5LaureBzr5PbaDI"
        "dpfRXm2/ibeAxL/Hs+xWbiqflOklgKf18qs2HQHtYcJ6jgs4TjLPm0VJeLrApBlkdaDoTgy9MAIClpb1"
        "anu24P3DNuIDNVtXnqf5qiKbSlCOT29xYUV89IDWgn/pMsAx1VOlM//7jNF/6I+5uNkru4Opxs1mcVlp"
        "ENNOqrWWpkQimlHXMFmdUvbYGBJOW7S7+aOSjpCVUULIL8K0BVDoBg6cGQr6tVwIHSOZTKaJLrb3mnkV"
        "miK0j+jg0U/ptRRrYMwMiYxUEorVkaXuardD7CUhzSj8bEwhkBaDMpM0yksQDcxPC1rF+YmHZZllN08J"
        "e67YNf7bO8+uz47FJ8XyjFskDPnP0FT+X8yTgtvyBMGnDW3y8B3a9QTEGJTimnpCITdrByHOhCYzuah+"
        "V4zAHDTVecUKtz7W7tXqcVRnNec+xcIIplSf8QU8UwtqdskOucvDh1i7WQ2Solj4NaPBycpWULmYvNrd"
        "pv+i8Ir0PNCPiREez38Bx3xwUjBFnNCdBcLkL5BNfOG99/74j9cTW7RZs9Y9iKeLRx6F28/5rNjN9zrI"
        "LTNYjKF+/PxLqMv6frbahg==";

static void get_xml_tag_val(char* xml,const char* tag_name, char** out) {
    char* open_tag = NULL, * end_tag = NULL, * _out = NULL, * open_tag_p = NULL, * end_tag_p = NULL;
    size_t len = 0, open_pos = 0, end_pos = 0, sub_str_size = 0, i = 0;

    len = strlen(tag_name);

    open_tag = (char*)malloc((sizeof(char)) * (len + 3));
    end_tag = (char*)malloc((sizeof(char)) * (len + 4));
    memset(open_tag, '\0', len + 3);
    memset(end_tag, '\0', len + 4);

    open_tag[0] = '<';
    end_tag[0] = '<';
    end_tag[1] = '/';
    for (i = 1; i <= len; i++) {
        open_tag[i] = tag_name[i - 1];
        end_tag[i + 1] = tag_name[i - 1];
    }
    open_tag[len + 1] = '>';
    end_tag[len + 2] = '>';

    open_tag_p = strstr(xml, open_tag);
    if (!open_tag_p) {
        free(open_tag);
        free(end_tag);
        return;
    }

    end_tag_p = strstr(xml, end_tag);
    open_pos = (open_tag_p - xml) + (len + 2);
    end_pos = end_tag_p - xml;
    sub_str_size = end_pos - open_pos;
    _out = (char*)malloc((sizeof(char)) * (sub_str_size + 1));
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


static char* read_fingerprint(void) {
    hasp_status_t st;
    const char* scope =
        "<?xml version=\"1.0\" encoding=\"UTF-8\" ?>"
        "<haspscope>"
        "<license_manager hostname=\"localhost\" />"
        "</haspscope>";

    char* result = NULL;
    const char* view = "<haspformat format=\"host_fingerprint\"/>";
    st = hasp_get_info(scope, view, VENDOR_CODE, &result);

    if (st) {
        printf("Failed to read fingerprint. Sentinel Runtime error code %d\n", st);
        return _strdup("");
    }
    else {
        printf("Fingerprint read successfully.\n");
        return result;
    }
}


static int index_of(LPCWSTR string, LPCWSTR sub_string, int start_at) {
    WCHAR const* p = string;
    int i, found_at = -1;
    if (wcslen(string) == 0) {
        return -1;
    }
    if (start_at > (int)wcslen(string)) {
        return -1;
    }
    for (i = 0; ; ++i) {
        p = wcsstr(p, sub_string);
        if (!p) {
            found_at = -1;
            break;
        }
        else {
            found_at = (int)(p - string);
            if (found_at >= start_at) {
                break;
            }
        }
        p++;
    }
    return found_at;
}


BOOL AnsiToUnicode16(CHAR* in_src, WCHAR* out_dst, INT in_maxlen) {
    INT lv_len;

    if (in_maxlen <= 0)
        return FALSE;

    lv_len = MultiByteToWideChar(CP_ACP, 0, in_src, -1, out_dst, in_maxlen);

    // validate
    if (lv_len < 0)
        lv_len = 0;

    if (lv_len < in_maxlen)
        out_dst[lv_len] = 0;
    else if (out_dst[in_maxlen - 1])
        out_dst[0] = 0;

    return TRUE;
}


static char* read_c2v_from_key(void) {
    hasp_status_t st = HASP_STATUS_OK;
    size_t haspId_size = 0, scope_size = 0;
    char* scope = NULL;
    char* result = NULL;
    char keyid[64] = "";
    const char scope1[] =
        "<?xml version=\"1.0\" encoding=\"UTF-8\" ?>"
        "<haspscope>     <hasp id=\"";
    const char scope2[] = "\" /></haspscope>";

    const char format[] = "<haspformat format=\"updateinfo\"/>";

    // read Hasp Id from USer input
    printf("Enter the HASP ID: ");
    scanf_s("%s", keyid, 64);

    haspId_size = strlen(keyid);
    scope_size = strlen(scope1);
    scope_size += strlen(scope2);

    scope_size = haspId_size + scope_size + 1;
    scope = (char*)malloc((sizeof(char)) * (scope_size));

    memset(scope, '\0', scope_size);

    strncat_s(scope, (sizeof(char)) * (scope_size), scope1, strlen(scope1));
    strncat_s(scope, (sizeof(char)) * (scope_size), keyid, strlen(keyid));
    strncat_s(scope, (sizeof(char)) * (scope_size), scope2, strlen(scope2));

    st = hasp_get_info(scope, format, VENDOR_CODE, &result);
    if (scope != NULL) {
        free(scope);
        scope = NULL;
    }
    if (st) {
        printf("Failed to C2V for HASP ID: %s. \"hasp_get_info()\" returned error code %d\n", keyid, st);
        return  _strdup("");
    }
    else {
        printf("C2V fetched successfully.\n");
        printf("\n\n");
        return result;
    }
}

BOOL Unicode16ToAnsi(WCHAR* in_src, CHAR* out_dst, INT in_maxlen) {
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
    else if (out_dst[in_maxlen - 1])
        out_dst[0] = 0;

    return !lv_useddefault;
}

 unsigned char* to_utf8(const wchar_t* unicode_string) {
    int sz = 0;
    int index = 0;
    int index2 = 0;
    unsigned char* out;
    unsigned short c;
    c = unicode_string[index++];

    while (c) {
        if (c < 0x0080) {
            sz += 1;
        }
        else if (c < 0x0800) {
            sz += 2;
        }
        else {
            sz += 3;
        }

        c = unicode_string[index++];
    }

    out = (unsigned char*)malloc(sz + 1);

    if (out == NULL) {
        return NULL;
    }

    index = 0;
    c = unicode_string[index++];

    while (c) {
        if (c < 0x080) {
            out[index2++] = (unsigned char)c;
        }
        else if (c < 0x800) {
            out[index2++] = 0xc0 | (c >> 6);
            out[index2++] =
                0x80 | (c & 0x3f);
        }
        else {
            out[index2++] = 0xe0 | (c >> 12);
            out[index2++] = 0x80 | ((c >> 6) & 0x3f);
            out[index2++] = 0x80 | (c & 0x3f);
        }

        c = unicode_string[index++];
    }

    out[index2] = 0x00;
    return out;

}


 void fetch_keys_list(void) {
    hasp_status_t st = HASP_STATUS_OK;
    const char* scope =
        "<?xml version=\"1.0\" encoding=\"UTF-8\" ?>"
        "<haspscope>"
        " <license_manager hostname=\"localhost\" >"
        " <hasp key_type=\"~SL-Legacy\" />"
        " </license_manager>"
        "</haspscope>";

    char* result = NULL;
    const char* format = "<haspformat root=\"hasp_info\">"
        "<hasp>"
        "<attribute name=\"id\" />"
        "<attribute name=\"type\" />"
        "</hasp>"
        "</haspformat>";

    st = hasp_get_info(scope, format, VENDOR_CODE, &result);

    if (st) {
        printf("Failed to fetch available key list. \"hasp_get_info()\" retuned error code %d \n", st);
        return;
    }
    else {
        printf("HASP IDs fetched successfully.\n");
        printf(result);
    }
}

 static int get_response_content_len(HINTERNET req) {
     int res;
     DWORD dwSize = HTTP_RES_CONTENT_LENGTH_LEN;
     wchar_t outBuffer[HTTP_RES_CONTENT_LENGTH_LEN];

     int len = 0;
     res = HttpQueryInfo(req, HTTP_QUERY_CONTENT_LENGTH, &outBuffer, &dwSize, NULL);
     if (res) {
         len = _wtoi(outBuffer);
     }

     return len;
 }

 int get_ws_polling_frequency_time(HINTERNET hHttp)
 {
     DWORD dwSize = 18;
     int pollingFrequency = 0;

     LPVOID lpOutBuffer = (char*)malloc((dwSize) * sizeof(char));
     strcpy_s((LPSTR)lpOutBuffer, dwSize, "polling-frequency");

 retry:
     if (!HttpQueryInfo(hHttp, HTTP_QUERY_CUSTOM | HTTP_QUERY_FLAG_NUMBER, (LPVOID)lpOutBuffer, &dwSize, NULL)) {

         if (GetLastError() == ERROR_HTTP_HEADER_NOT_FOUND) {
             // Code to handle the case where the header isn't available.
             free(lpOutBuffer);
             lpOutBuffer = NULL;
             return 0;
         }
         else {
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
             }
             else {
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




  char* send_request(WCHAR* server, WCHAR* body, WCHAR* uri, const WCHAR* method) {
     DWORD lst_err = GetLastError();
     const WCHAR* lplpszAcceptTypes[] = { L"Accept: */*", NULL };

     HINTERNET hConn;
     HINTERNET req;
     int res = 0, indx = 0, result = 0, status_code = 0, result2 = 0, ws_polling_freq = 0;
     int content_length = 0;
     size_t szTmp = 0, szJsession = 0;

     char tmp[] = "Accept: application/vnd.ems.v12\r\nContent-Type: application/xml;charset=utf-8\r\nCookie: JSESSIONID=";
     char* ret = NULL;
     DWORD dwSize = HTTP_RES_STATUS_CODE_LEN;
     DWORD dwSize2 = HTTP_RES_STATUS_CODE_TEXT_LEN;
     DWORD dwDownloaded = 0, body_len = 0, dwFlags = 0;
     DWORD dwBuffLen = sizeof(dwFlags);
     LPCWSTR outBuffer2[HTTP_RES_STATUS_CODE_TEXT_LEN];
     LPCWSTR outBuffer[HTTP_RES_STATUS_CODE_LEN];
     LPCWSTR data = NULL;

     HINTERNET hSession = InternetOpen(L"ActivationSample", INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);

     if (!hSession) {
         printf("Connection to Sentinel LDK-EMS server failed.\n");
         return NULL;
     }

     body_len = (DWORD)wcslen(body);

     hConn = InternetConnect(hSession, server, server_port, NULL, NULL, INTERNET_SERVICE_HTTP, 0, (DWORD_PTR)NULL);
     if (!hConn) {
         printf("Connection to LDK-EMS server failed\n");
         return NULL;
     }
     lst_err = GetLastError();

     if (!wcscmp(protocol, L"http")) {
         req = HttpOpenRequest(hConn,
             method,
             uri,
             L"HTTP/1.0",
             NULL,
             (LPCTSTR*)lplpszAcceptTypes,
             INTERNET_FLAG_RELOAD |
             INTERNET_FLAG_NO_CACHE_WRITE |
             INTERNET_FLAG_NO_COOKIES |
             INTERNET_FLAG_KEEP_CONNECTION,
             0);
     }
     else {
         req = HttpOpenRequest(hConn,
             method,
             uri,
             L"HTTP/1.0",
             NULL,
             (LPCTSTR*)lplpszAcceptTypes,
             INTERNET_FLAG_RELOAD |
             INTERNET_FLAG_NO_CACHE_WRITE |
             INTERNET_FLAG_IGNORE_CERT_CN_INVALID |
             INTERNET_FLAG_IGNORE_CERT_DATE_INVALID |
             INTERNET_FLAG_SECURE |
             INTERNET_FLAG_NO_COOKIES |
             INTERNET_FLAG_KEEP_CONNECTION,
             0);

         InternetQueryOption(req, INTERNET_OPTION_SECURITY_FLAGS, (LPVOID)&dwFlags, &dwBuffLen);
         dwFlags = SECURITY_FLAG_IGNORE_UNKNOWN_CA;
         InternetSetOption(req, INTERNET_OPTION_SECURITY_FLAGS, &dwFlags, sizeof(dwFlags));
     }

     lst_err = GetLastError();

     if (j_session_id == NULL) {
         char* ansiBody = NULL;
         LPCWSTR headers = NULL;
         size_t req_len = body_len + 1;

         ansiBody = (char*)malloc(sizeof(char) * req_len);
         memset(ansiBody, '\0', req_len);
         //headers = L"Accept: application/vnd.ems.v12\r\nContent-Type: application/x-www-form-urlencoded"; 

         if (index_of(uri, L"target.ws", 0) > 0) {
             headers = L"Accept: application/vnd.ems.v12\r\nContent-Type: application/xml; charset=utf-8";
         }
         else {
             headers = L"Accept: application/vnd.ems.v12\r\nContent-Type: application/x-www-form-urlencoded; charset=utf-8";
         }
         if (!wcscmp(method, HTTP_METHOD_POST)) {
             Unicode16ToAnsi(body, ansiBody, req_len);
             res = HttpSendRequest(req, headers, (DWORD)wcslen(headers), (LPVOID)ansiBody, req_len);
         }
         else {
             res = HttpSendRequest(req, headers, (DWORD)wcslen(headers), (LPVOID)body, body_len * sizeof(WCHAR));
         }

         if (ansiBody != NULL) {
             free(ansiBody);
             ansiBody = NULL;
         }
     }
     else {
         char* utf8_body = NULL;
         char* headers;

         WCHAR unicodeHeaders[HTTP_REQ_UNICODE_HEADERS_LEN];

         szJsession = strlen(j_session_id);
         szTmp = strlen(tmp);
         headers = (char*)malloc((sizeof(char)) * (szJsession + szTmp + 1));
         memset(headers, '\0', szTmp + szJsession + 1);
         strncat_s(headers, szTmp + szJsession + 1, tmp, strlen(tmp));
         strncat_s(headers, szTmp + szJsession + 1, j_session_id, strlen(j_session_id));
         AnsiToUnicode16(headers, unicodeHeaders, HTTP_REQ_UNICODE_HEADERS_LEN);
         utf8_body = (char*)to_utf8(body);
         res = HttpSendRequest(req, (LPCWSTR)unicodeHeaders, (DWORD)wcslen(unicodeHeaders), (LPVOID)utf8_body, (DWORD)strlen(utf8_body));

         free(headers);
         if (utf8_body != NULL) {
             free(utf8_body);
         }
     }
     lst_err = GetLastError();

     if (res) {
         result = HttpQueryInfo(req, HTTP_QUERY_STATUS_CODE, (void*)&outBuffer, &dwSize, NULL);
         status_code = _wtoi((wchar_t*)outBuffer);

         result2 = HttpQueryInfo(req, HTTP_QUERY_STATUS_TEXT, (void*)&outBuffer2, &dwSize2, NULL);
         content_length = get_response_content_len(req);
         data = (LPCWSTR)malloc((sizeof(LPCWSTR)) * (content_length + 1));
         memset((void*)data, '\0', (sizeof(LPCWSTR) * (content_length + 1)));

         if (InternetQueryDataAvailable(req, &dwSize, 0, 0)) {
             WCHAR* buffer = NULL;
             indx = 0;
             buffer = (WCHAR*)malloc((sizeof(WCHAR)) * (content_length + 1));
             memset(buffer, '\0', (content_length + 1) * sizeof(WCHAR));
             dwDownloaded = 0;

             while (InternetReadFile(req, buffer, content_length, &dwDownloaded)) {
                 if (dwDownloaded == 0) {
                     break;
                 }

                 if (indx < (content_length - 1)) {
                     wcsncat_s((wchar_t*)data, content_length, buffer, dwDownloaded);
                     indx += dwDownloaded;
                 }
             }

             if (status_code != HTTP_STATUS_OK && status_code != HTTP_STATUS_CREATED) {
                 printf("Sentinel LDK-EMS error: ");
                 printf("%s\n", (char*)data);
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
         if (data != NULL) {
             free((void*)data);
             data = NULL;
         }
     }
     else {
         lst_err = GetLastError();
         printf("Error occurred while communicating with Sentinel LDK-EMS server: %d\n", lst_err);
     }

     InternetCloseHandle(req);
     InternetCloseHandle(hConn);
     InternetCloseHandle(hSession);

     return ret;
 }
 static int index_of_ansi(const char* string, const char* sub_string, int start_at) {
     char const* p = string;
     int i, found_at = -1;
     if (strlen(string) == 0) {
         return -1;
     }
     if (start_at > (int)strlen(string)) {
         return -1;
     }
     for (i = 0; ; ++i) {
         p = strstr(p, sub_string);
         if (!p) {
             found_at = -1;
             break;
         }
         else {
             found_at = (int)(p - string);
             if (found_at >= start_at) {
                 break;
             }
         }
         p++;
     }
     return found_at;

 }

 static char* get_c2v_from_response(char* response) {
     char* start = strstr(response, "<activationString>");
     char* end = strstr(response, "</activationString>");
     if (!start || !end) return _strdup("");

     start += strlen("<activationString>");
     size_t len = end - start;
     char* v2c = (char*)malloc(len + 1);
     strncpy_s(v2c, len + 1, start, len);
     v2c[len] = '\0';

     // Replace XML escape codes
     char* p;
     while ((p = strstr(v2c, "&gt;"))) { memmove(p + 1, p + 4, strlen(p + 4) + 1); p[0] = '>'; }
     while ((p = strstr(v2c, "&lt;"))) { memmove(p + 1, p + 4, strlen(p + 4) + 1); p[0] = '<'; }
     while ((p = strstr(v2c, "&quot;"))) { memmove(p + 1, p + 6, strlen(p + 6) + 1); p[0] = '"'; }

     return v2c;
 }


 static WCHAR* replace_all_unicode(const WCHAR* src, const WCHAR* old, const WCHAR* new_str) {
     size_t src_len = wcslen(src);
     size_t old_len = wcslen(old);
     size_t new_len = wcslen(new_str);

     WCHAR* buffer = (WCHAR*)malloc((src_len + 1) * sizeof(WCHAR));
     wcscpy_s(buffer, src_len + 1, src);

     WCHAR* pos = wcsstr(buffer, old);
     if (!pos) return buffer;

     size_t prefix_len = pos - buffer;
     size_t final_len = prefix_len + new_len + (src_len - prefix_len - old_len) + 1;

     WCHAR* result = (WCHAR*)malloc(final_len * sizeof(WCHAR));
     wcsncpy_s(result, final_len, buffer, prefix_len);
     wcscat_s(result, final_len, new_str);
     wcscat_s(result, final_len, buffer + prefix_len + old_len);

     free(buffer);
     return result;
 }



 static void generate_request(char* c2v, char** out) {
     const char* xml_part_1 =
         "<?xml version=\"1.0\" encoding=\"UTF-8\" ?>\n"
         "<activation xsi:noNamespaceSchemaLocation=\"License.xsd\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">\n"
         "<activationInput>\n"
         "<activationAttribute>\n"
         "<attributeValue>\n"
         "<![CDATA[";

     const char* xml_part_2 =
         "]]>\n"
         "</attributeValue>\n"
         "<attributeName>C2V</attributeName>\n"
         "</activationAttribute>\n"
         "<comments></comments>\n"
         "</activationInput>\n"
         "</activation>\n";

     size_t size = strlen(xml_part_1) + strlen(c2v) + strlen(xml_part_2) + 1;
     *out = (char*)malloc(size);
     memset(*out, 0, size);
     strcat_s(*out, size, xml_part_1);
     strcat_s(*out, size, c2v);
     strcat_s(*out, size, xml_part_2);
 }




int do_v2cp_activation(void) {
    char* c2v = NULL;
    char* res = NULL;
    WCHAR uri[] = L"/ems/v78/ws/activation/target.ws";
    WCHAR* req_unicode = NULL;
    hasp_status_t st = HASP_STATUS_OK;

    fetch_keys_list();

    c2v = read_c2v_from_key();
    if (c2v == NULL || !strcmp(c2v, "")) {
        return 0;
    }

    req_unicode = (WCHAR*)malloc((strlen(c2v) + 1) * sizeof(WCHAR));
    if (req_unicode == NULL) {
        printf("Memory allocation for req_unicode failed.\n");
        free(c2v);
        return 0;
    }

    AnsiToUnicode16(c2v, req_unicode, (INT)(strlen(c2v) + 1));

    res = send_request((WCHAR*)L"http://activations.solidcam.com", req_unicode, uri, HTTP_METHOD_POST);


    if (res != NULL) {
        if (index_of_ansi(res, "<hasp_info>", 0) >= 0) {
            st = hasp_update(res, &c2v);
            if (st) {
                printf("Updating key failed with Sentinel Runtime error code %d\n", st);
            }
            else {
                printf("Activation succeeded.\n");
            }
        }
        else {
            printf("Web Service response: %s\n", res);
        }
    }
    else {
        printf("Web Service returned NULL.\n");
    }

    if (req_unicode != NULL) {
        free(req_unicode);
    }
    if (c2v != NULL) {
        free(c2v);
    }

    return 1;
}




 static int customer_login(void) {

     WCHAR body[CUST_LOGIN_BODY_LEN];
     char* login_xml;
     char* reg_req;
     char* stat = NULL;

     memset(body, '\0', CUST_LOGIN_BODY_LEN + sizeof(WCHAR));

     printf("Logging in...\n");
     if (url == L"" || product_key == L"") {
         printf("Product key and URL cannot be null. Check the activation.cfg file.\n");
         return 0;
     }

     wcsncat_s(body, CUST_LOGIN_PK_BODY_KEY_LEN, L"productKey=", wcslen(L"productKey="));
     wcsncat_s(body, CUST_LOGIN_PK_BODY_LEN, product_key, wcslen(product_key));

     login_xml = send_request(url, body, (WCHAR*)L"ems/v21/ws/loginByProductKey.ws", HTTP_METHOD_POST);

     if (!login_xml)
         return 0;

     //parse the data
     get_xml_tag_val(login_xml, "stat", &stat);
     if (stat == NULL) {
         return 0;
     }
     else {
         if (!strcmp(stat, "ok")) {
             get_xml_tag_val(login_xml, "sessionId", &j_session_id);
             if (j_session_id == NULL) {
                 printf("Sentinel LDK-EMS error: The server did not return a session.\n");
                 return 0;
             }

             get_xml_tag_val(login_xml, "regRequired", &reg_req);
             if (strcmp(reg_req, "")) {
                 reg_required = atoi(reg_req);
             }
             free(reg_req);
             printf("Logged in successfully.\n");
         }
         else {
             printf("Got the following error status from LDK-EMS server: %s\n", stat);
         }
         free(stat);
     }

     return 1;
 }

 int do_activation(void) {

     if (!customer_login())
         return 0;

     char* req = NULL, * c2v = NULL, * res = NULL, * v2c = NULL;
     WCHAR tmp[] = L"/ems/v21/ws/productKey/{PK_ID}/activation.ws";

     WCHAR* uri = NULL;
     WCHAR* req_unicode = NULL;


     hasp_status_t st = HASP_STATUS_OK;

     c2v = read_fingerprint();
     if (c2v == NULL || !strcmp(c2v, "")) {
         return 0;
     }

     generate_request(c2v, &req);
     req_unicode = (WCHAR*)malloc((strlen(req) + 1) * sizeof(WCHAR));
     AnsiToUnicode16(req, req_unicode, (INT)(strlen(req) + 1));

     uri = replace_all_unicode(tmp, L"{PK_ID}", product_key);
     res = send_request(url, req_unicode, uri, HTTP_METHOD_POST);

     if (!res)
         return 0;

     if (index_of_ansi(res, "<activation>", 0) >= 0) {
         v2c = get_c2v_from_response(res);
         st = hasp_update(v2c, &c2v);

         if (st) {
             printf("Updating key failed with Sentinel Runtime error code %d \n", st);
         }
         else {
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

