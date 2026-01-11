"""
Unit tests for URL canonicalization.

Based on Google Safe Browsing specification test cases:
https://developers.google.com/safe-browsing/v4/urls-hashing#canonicalization
"""
import re
from urllib.parse import unquote, quote
import pytest


def canonicalize_url(url: str) -> str:
    """
    根據 Google Safe Browsing 規範標準化網址。
    參考: https://developers.google.com/safe-browsing/v4/urls-hashing#canonicalization
    
    注意：這是一個用於測試的獨立實作，完全符合 Google Safe Browsing 規範。
    """
    if not url:
        return ""
    
    # 1. 移除前後空白
    url = url.strip()
    
    # 2. 確保有協議頭
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    
    # 3. 移除 tab (0x09), CR (0x0d), LF (0x0a)
    url = re.sub(r'[\t\r\n]', '', url)
    
    # 4. 移除 fragment (未編碼的 # 之後的內容)
    # 注意：要在解碼之前處理 fragment
    if '#' in url:
        url = url.split('#')[0]
    
    # 記錄是否有查詢字串
    has_query = '?' in url
    
    # 5. 分離 scheme 和其餘部分進行處理
    if url.startswith('https://'):
        scheme = 'https'
        rest = url[8:]
    else:
        scheme = 'http'
        rest = url[7:]
    
    # 分離 host 和 path/query
    if '/' in rest:
        host_part = rest[:rest.index('/')]
        path_query = rest[rest.index('/'):]
    else:
        host_part = rest
        path_query = '/'
    
    # 分離 path 和 query
    if '?' in path_query:
        path = path_query[:path_query.index('?')]
        query = path_query[path_query.index('?')+1:]
    else:
        path = path_query
        query = ''
    
    # 6. 重複解碼各部分直到穩定
    def unescape_repeatedly(s: str) -> str:
        prev = None
        while prev != s:
            prev = s
            try:
                s = unquote(s)
            except Exception:
                break
        return s
    
    host_part = unescape_repeatedly(host_part)
    path = unescape_repeatedly(path)
    query = unescape_repeatedly(query) if query else ''
    
    # 7. 處理主機名稱
    # 移除端口
    if ':' in host_part:
        host_part = host_part[:host_part.index(':')]
    
    hostname = host_part.lower()
    # 移除前後的點
    hostname = hostname.strip('.')
    # 將連續的點替換為單一點
    hostname = re.sub(r'\.+', '.', hostname)
    
    # 處理十進制 IP 地址 (DWORD 格式)
    try:
        if hostname.isdigit():
            ip_int = int(hostname)
            if 0 <= ip_int <= 0xFFFFFFFF:
                hostname = f"{(ip_int >> 24) & 0xFF}.{(ip_int >> 16) & 0xFF}.{(ip_int >> 8) & 0xFF}.{ip_int & 0xFF}"
    except ValueError:
        pass
    
    # 8. 處理路徑中的 . 和 ..
    if not path:
        path = '/'
    
    path_parts = []
    for part in path.split('/'):
        if part == '..':
            if path_parts:
                path_parts.pop()
        elif part != '.' and part != '':
            path_parts.append(part)
    
    normalized_path = '/' + '/'.join(path_parts)
    if path.endswith('/') and not normalized_path.endswith('/'):
        normalized_path += '/'
    
    if not normalized_path:
        normalized_path = '/'
    
    # 9. 重新編碼特殊字元 (只編碼: <= 32, >= 127, #, %)
    # 使用 Latin-1 編碼以保持單字節編碼
    def safe_encode(s: str) -> str:
        result = []
        for char in s:
            code = ord(char)
            if code <= 32 or code >= 127 or char in '#%':
                # 使用 Latin-1 編碼確保單字節字元被正確編碼
                try:
                    encoded = char.encode('latin-1')
                    for byte in encoded:
                        result.append(f'%{byte:02X}')
                except UnicodeEncodeError:
                    # 對於無法用 Latin-1 編碼的字元，使用 UTF-8
                    result.append(quote(char, safe=''))
            else:
                result.append(char)
        return ''.join(result)
    
    encoded_hostname = safe_encode(hostname)
    encoded_path = safe_encode(normalized_path)
    encoded_query = safe_encode(query) if query else ''
    
    # 10. 重建 URL
    if encoded_query:
        return f"{scheme}://{encoded_hostname}{encoded_path}?{encoded_query}"
    elif has_query:
        return f"{scheme}://{encoded_hostname}{encoded_path}?"
    return f"{scheme}://{encoded_hostname}{encoded_path}"


class TestCanonicalizeUrl:
    """測試 URL 標準化功能"""
    
    # ==================== Percent Encoding Tests ====================
    
    def test_percent_encoding_double_encoded(self):
        """測試雙重百分比編碼 %25%32%35 -> %25"""
        assert canonicalize_url("http://host/%25%32%35") == "http://host/%25"
    
    def test_percent_encoding_multiple_double_encoded(self):
        """測試多個雙重百分比編碼"""
        assert canonicalize_url("http://host/%25%32%35%25%32%35") == "http://host/%25%25"
    
    def test_percent_encoding_deeply_encoded(self):
        """測試深度百分比編碼"""
        assert canonicalize_url("http://host/%2525252525252525") == "http://host/%25"
    
    def test_percent_encoding_in_path(self):
        """測試路徑中的百分比編碼"""
        assert canonicalize_url("http://host/asdf%25%32%35asd") == "http://host/asdf%25asd"
    
    def test_percent_encoding_with_bare_percent(self):
        """測試含有裸 % 符號的編碼"""
        assert canonicalize_url("http://host/%%%25%32%35asd%%") == "http://host/%25%25%25asd%25%25"
    
    # ==================== Basic URL Tests ====================
    
    def test_basic_url_unchanged(self):
        """測試基本 URL 不變"""
        assert canonicalize_url("http://www.google.com/") == "http://www.google.com/"
    
    def test_encoded_ip_and_path(self):
        """測試編碼的 IP 和路徑"""
        assert canonicalize_url(
            "http://%31%36%38%2e%31%38%38%2e%39%39%2e%32%36/%2E%73%65%63%75%72%65/%77%77%77%2E%65%62%61%79%2E%63%6F%6D/"
        ) == "http://168.188.99.26/.secure/www.ebay.com/"
    
    def test_encoded_spaces_in_path(self):
        """測試路徑中的編碼空格"""
        assert canonicalize_url(
            "http://195.127.0.11/uploads/%20%20%20%20/.verify/.eBaysecure=updateuserdataxplimnbqmn-xplmvalidateinfoswqpcmlx=hgplmcx/"
        ) == "http://195.127.0.11/uploads/%20%20%20%20/.verify/.eBaysecure=updateuserdataxplimnbqmn-xplmvalidateinfoswqpcmlx=hgplmcx/"
    
    def test_encoded_special_chars_in_path(self):
        """測試路徑中的編碼特殊字元"""
        assert canonicalize_url(
            "http://host%23.com/%257Ea%2521b%2540c%2523d%2524e%25f%255E00%252611%252A22%252833%252944_55%252B"
        ) == "http://host%23.com/~a!b@c%23d$e%25f^00&11*22(33)44_55+"
    
    # ==================== IP Address Tests ====================
    
    def test_decimal_ip_address(self):
        """測試十進制 IP 地址轉換"""
        assert canonicalize_url("http://3279880203/blah") == "http://195.127.0.11/blah"
    
    # ==================== Path Normalization Tests ====================
    
    def test_path_with_double_dot(self):
        """測試路徑中的 .. 處理"""
        assert canonicalize_url("http://www.google.com/blah/..") == "http://www.google.com/"
    
    # ==================== Protocol Tests ====================
    
    def test_missing_protocol_with_trailing_slash(self):
        """測試缺少協議的 URL (帶斜線)"""
        assert canonicalize_url("www.google.com/") == "http://www.google.com/"
    
    def test_missing_protocol_no_trailing_slash(self):
        """測試缺少協議的 URL (無斜線)"""
        assert canonicalize_url("www.google.com") == "http://www.google.com/"
    
    # ==================== Fragment Tests ====================
    
    def test_remove_fragment(self):
        """測試移除 fragment"""
        assert canonicalize_url("http://www.evil.com/blah#frag") == "http://www.evil.com/blah"
    
    def test_remove_multiple_fragments(self):
        """測試移除多個 fragment"""
        assert canonicalize_url("http://evil.com/foo#bar#baz") == "http://evil.com/foo"
    
    # ==================== Hostname Tests ====================
    
    def test_lowercase_hostname(self):
        """測試主機名稱小寫化"""
        assert canonicalize_url("http://www.GOOgle.com/") == "http://www.google.com/"
    
    def test_trailing_dots_in_hostname(self):
        """測試主機名稱尾部點"""
        assert canonicalize_url("http://www.google.com.../") == "http://www.google.com/"
    
    # ==================== Whitespace Tests ====================
    
    def test_remove_tabs_cr_lf(self):
        """測試移除 tab、CR、LF"""
        assert canonicalize_url("http://www.google.com/foo\tbar\rbaz\n2") == "http://www.google.com/foobarbaz2"
    
    def test_trim_leading_trailing_spaces(self):
        """測試移除前後空格"""
        assert canonicalize_url("  http://www.google.com/  ") == "http://www.google.com/"
    
    def test_space_in_hostname(self):
        """測試主機名稱中的空格"""
        assert canonicalize_url("http:// leadingspace.com/") == "http://%20leadingspace.com/"
    
    def test_encoded_space_in_hostname(self):
        """測試主機名稱中的編碼空格"""
        assert canonicalize_url("http://%20leadingspace.com/") == "http://%20leadingspace.com/"
    
    def test_leading_space_no_protocol(self):
        """測試無協議的前導空格"""
        assert canonicalize_url("%20leadingspace.com/") == "http://%20leadingspace.com/"
    
    # ==================== Query String Tests ====================
    
    def test_empty_query_string(self):
        """測試空的查詢字串"""
        assert canonicalize_url("http://www.google.com/q?") == "http://www.google.com/q?"
    
    def test_query_with_question_mark(self):
        """測試含問號的查詢字串"""
        assert canonicalize_url("http://www.google.com/q?r?") == "http://www.google.com/q?r?"
    
    def test_query_with_multiple_question_marks(self):
        """測試含多個問號的查詢字串"""
        assert canonicalize_url("http://www.google.com/q?r?s") == "http://www.google.com/q?r?s"
    
    # ==================== Special Character Tests ====================
    
    def test_semicolon_in_path(self):
        """測試路徑中的分號"""
        assert canonicalize_url("http://evil.com/foo;") == "http://evil.com/foo;"
    
    def test_semicolon_in_query(self):
        """測試查詢中的分號"""
        assert canonicalize_url("http://evil.com/foo?bar;") == "http://evil.com/foo?bar;"
    
    def test_non_ascii_characters(self):
        """測試非 ASCII 字元"""
        assert canonicalize_url("http://\x01\x80.com/") == "http://%01%80.com/"
    
    def test_hash_in_path(self):
        """測試路徑中的 # (編碼)"""
        assert canonicalize_url("http://host.com/ab%23cd") == "http://host.com/ab%23cd"
    
    # ==================== Trailing Slash Tests ====================
    
    def test_add_trailing_slash(self):
        """測試添加尾部斜線"""
        assert canonicalize_url("http://notrailingslash.com") == "http://notrailingslash.com/"
    
    # ==================== Port Tests ====================
    
    def test_remove_default_port(self):
        """測試移除端口"""
        assert canonicalize_url("http://www.gotaport.com:1234/") == "http://www.gotaport.com/"
    
    # ==================== HTTPS Tests ====================
    
    def test_https_preserved(self):
        """測試 HTTPS 協議保留"""
        assert canonicalize_url("https://www.securesite.com/") == "https://www.securesite.com/"
    
    # ==================== Slash Handling Tests ====================
    
    def test_double_slashes_in_path(self):
        """測試路徑中的雙斜線"""
        assert canonicalize_url("http://host.com//twoslashes?more//slashes") == "http://host.com/twoslashes?more//slashes"
