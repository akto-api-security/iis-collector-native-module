// Module.cpp
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <httpserv.h>
#include <winhttp.h>
#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <queue>
#include <sstream>
#include <atomic>
#include <fstream>
#include <iomanip>
#include <ctime>
#include <cstring>
#include <ws2tcpip.h>
#include <map>

#include <Shlwapi.h>
#pragma comment(lib, "Shlwapi.lib")

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "ws2_32.lib")

// ------------------- Logging helper -------------------
enum class LogLevel {
    NONE = 0,
    ERR = 1,
    WARNING = 2,
    INFO = 3,
    DEBUG = 4
};

static LogLevel gLogLevel = LogLevel::INFO;  // Default log level

static void SafeLog(const std::string& msg, LogLevel level = LogLevel::INFO)
{
    try {
        // Skip logging if we're at NONE or message level is higher (less important) than threshold
        if (gLogLevel == LogLevel::NONE || level > gLogLevel) {
            return;
        }

        SYSTEMTIME st;
        GetLocalTime(&st);

        char buf[128];
        sprintf_s(buf, "%04d-%02d-%02d %02d:%02d:%02d.%03d ",
            st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);

        // Add log level prefix
        const char* levelStr = "";
        switch (level) {
            case LogLevel::ERR:     levelStr = "[ERROR] "; break;
            case LogLevel::WARNING: levelStr = "[WARN]  "; break;
            case LogLevel::INFO:    levelStr = "[INFO]  "; break;
            case LogLevel::DEBUG:   levelStr = "[DEBUG] "; break;
            default: levelStr = "[INFO]  "; break;
        }

        std::string folder = "C:\\akto_configs\\logs\\";

        // Try to create directories with error checking
        DWORD attr = GetFileAttributesA("C:\\akto_configs");
        if (attr == INVALID_FILE_ATTRIBUTES) {
            if (!CreateDirectoryA("C:\\akto_configs", nullptr)) {
                DWORD err = GetLastError();
                if (err != ERROR_ALREADY_EXISTS) {
                    return; // Can't create directory
                }
            }
        }

        attr = GetFileAttributesA(folder.c_str());
        if (attr == INVALID_FILE_ATTRIBUTES) {
            if (!CreateDirectoryA(folder.c_str(), nullptr)) {
                DWORD err = GetLastError();
                if (err != ERROR_ALREADY_EXISTS) {
                    return; // Can't create directory
                }
            }
        }

        std::ostringstream filename;
        filename << folder
            << "log_" << st.wYear
            << std::setw(2) << std::setfill('0') << st.wMonth
            << std::setw(2) << std::setfill('0') << st.wDay
            << ".txt";

        std::ofstream f(filename.str(), std::ios::app);
        if (f.is_open()) {
            f << buf << levelStr << msg << "\n";
            f.flush(); // Force write to disk
            f.close();
        }
        else {
            // Fallback to Windows Event Log if file logging fails
            HANDLE hEventLog = RegisterEventSourceA(NULL, "AktoIISCollector");
            if (hEventLog) {
                std::string eventMsg = std::string(levelStr) + msg;
                const char* msgs[] = { eventMsg.c_str() };
                WORD eventType = EVENTLOG_INFORMATION_TYPE;
                if (level == LogLevel::ERR) eventType = EVENTLOG_ERROR_TYPE;
                else if (level == LogLevel::WARNING) eventType = EVENTLOG_WARNING_TYPE;

                ReportEventA(hEventLog, eventType, 0, 0, NULL, 1, 0, msgs, NULL);
                DeregisterEventSource(hEventLog);
            }
        }
    }
    catch (...) {
        // swallow logging failures
    }
}

// ------------------- Config loader -------------------
static std::wstring gBackendUrl;
static size_t gMaxQueueSize = 5000;  // Default value
static size_t gMinPayloadSize = 0;  // Default: capture all sizes (0 = no minimum)

static void LoadConfig()
{
    try {
        std::string configPath = "C:\\akto_configs\\config.json";
        if (!PathFileExistsA(configPath.c_str())) {
            SafeLog("Config file not found: " + configPath, LogLevel::WARNING);
            return;
        }

        std::ifstream f(configPath);
        if (!f.is_open()) {
            SafeLog("Unable to open config.json", LogLevel::ERR);
            return;
        }

        std::string content((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());

        // Very simple "backendUrl":"..." parser (no external deps)
        size_t pos = content.find("\"backendUrl\"");
        if (pos != std::string::npos) {
            pos = content.find(':', pos);
            if (pos != std::string::npos) {
                pos = content.find('"', pos);
                size_t end = content.find('"', pos + 1);
                if (pos != std::string::npos && end != std::string::npos) {
                    std::string url = content.substr(pos + 1, end - pos - 1);
                    int wlen = MultiByteToWideChar(CP_UTF8, 0, url.c_str(), -1, nullptr, 0);
                    std::wstring wurl(wlen, 0);
                    MultiByteToWideChar(CP_UTF8, 0, url.c_str(), -1, &wurl[0], wlen);
                    gBackendUrl = wurl;
                }
            }
        }

        // Parse "maxQueueSize": number
        pos = content.find("\"maxQueueSize\"");
        if (pos != std::string::npos) {
            pos = content.find(':', pos);
            if (pos != std::string::npos) {
                // Skip whitespace
                while (pos < content.length() && (content[pos] == ':' || content[pos] == ' ' || content[pos] == '\t')) {
                    pos++;
                }
                // Extract number
                size_t end = pos;
                while (end < content.length() && isdigit(content[end])) {
                    end++;
                }
                if (end > pos) {
                    std::string queueSizeStr = content.substr(pos, end - pos);
                    try {
                        size_t queueSize = std::stoull(queueSizeStr);
                        if (queueSize > 0) {
                            gMaxQueueSize = queueSize;
                        }
                        else {
                            SafeLog("Invalid maxQueueSize in config (must be > 0), using default: " + std::to_string(gMaxQueueSize), LogLevel::WARNING);
                        }
                    }
                    catch (...) {
                        SafeLog("Failed to parse maxQueueSize, using default: " + std::to_string(gMaxQueueSize), LogLevel::WARNING);
                    }
                }
            }
        }

        // Parse "logLevel": "ERROR"|"WARNING"|"INFO"|"DEBUG"|"NONE"
        pos = content.find("\"logLevel\"");
        if (pos != std::string::npos) {
            pos = content.find(':', pos);
            if (pos != std::string::npos) {
                pos = content.find('"', pos);
                size_t end = content.find('"', pos + 1);
                if (pos != std::string::npos && end != std::string::npos) {
                    std::string logLevelStr = content.substr(pos + 1, end - pos - 1);
                    // Convert to uppercase for comparison
                    for (auto& c : logLevelStr) c = (char)toupper(c);

                    if (logLevelStr == "NONE") {
                        gLogLevel = LogLevel::NONE;
                    } else if (logLevelStr == "ERROR" || logLevelStr == "ERR") {
                        gLogLevel = LogLevel::ERR;
                    } else if (logLevelStr == "WARNING" || logLevelStr == "WARN") {
                        gLogLevel = LogLevel::WARNING;
                    } else if (logLevelStr == "INFO") {
                        gLogLevel = LogLevel::INFO;
                    } else if (logLevelStr == "DEBUG") {
                        gLogLevel = LogLevel::DEBUG;
                    } else {
                        SafeLog("Invalid logLevel in config (\"" + logLevelStr + "\"), using default: INFO", LogLevel::WARNING);
                    }
                }
            }
        }

        // Parse "minPayloadSize": number (in bytes)
        pos = content.find("\"minPayloadSize\"");
        if (pos != std::string::npos) {
            pos = content.find(':', pos);
            if (pos != std::string::npos) {
                // Skip whitespace
                while (pos < content.length() && (content[pos] == ':' || content[pos] == ' ' || content[pos] == '\t')) {
                    pos++;
                }
                // Extract number
                size_t end = pos;
                while (end < content.length() && isdigit(content[end])) {
                    end++;
                }
                if (end > pos) {
                    std::string minSizeStr = content.substr(pos, end - pos);
                    try {
                        size_t minSize = std::stoull(minSizeStr);
                        gMinPayloadSize = minSize;
                        SafeLog("Minimum payload size set to: " + std::to_string(gMinPayloadSize) + " bytes", LogLevel::INFO);
                    }
                    catch (...) {
                        SafeLog("Failed to parse minPayloadSize, using default: " + std::to_string(gMinPayloadSize), LogLevel::WARNING);
                    }
                }
            }
        }
    }
    catch (const std::exception& ex) {
        SafeLog(std::string("Exception in LoadConfig: ") + ex.what(), LogLevel::ERR);
    }
    catch (...) {
        SafeLog("Unknown exception in LoadConfig", LogLevel::ERR);
    }
}

// ------------------- Utility -------------------
static std::string WideToUtf8(const wchar_t* w, size_t chars)
{
    if (!w || chars == 0) return {};
    int needed = ::WideCharToMultiByte(CP_UTF8, 0, w, (int)chars, NULL, 0, NULL, NULL);
    if (needed <= 0) return {};
    std::string out(needed, 0);
    ::WideCharToMultiByte(CP_UTF8, 0, w, (int)chars, &out[0], needed, NULL, NULL);
    return out;
}

static std::string CharBufToString(const char* buf, size_t len)
{
    if (!buf || len == 0) return {};
    return std::string(buf, buf + len);
}

static std::string JsonEscape(const std::string& s) {
    std::ostringstream o;
    for (unsigned char c : s) {
        switch (c) {
        case '\"': o << "\\\""; break;
        case '\\': o << "\\\\"; break;
        case '\b': o << "\\b"; break;
        case '\f': o << "\\f"; break;
        case '\n': o << "\\n"; break;
        case '\r': o << "\\r"; break;
        case '\t': o << "\\t"; break;
        default:
            if (c < 0x20) { o << "\\u" << std::hex << std::setw(4) << std::setfill('0') << (int)c; }
            else o << c;
        }
    }
    return o.str();
}

static std::string IsoNow() {
    std::time_t t = std::time(nullptr);
    std::tm tm;
    gmtime_s(&tm, &t);
    char buf[64];
    strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tm);
    return std::string(buf);
}

// ------------------- Safe Poster -------------------
class Poster {
public:
    Poster() : running_(true), worker_(&Poster::ThreadLoop, this) {}
    ~Poster() {
        {
            std::lock_guard<std::mutex> lk(mu_);
            running_ = false;
            cv_.notify_all();
        }
        if (worker_.joinable()) worker_.join();
    }

    void Enqueue(std::string json) {
        std::lock_guard<std::mutex> lk(mu_);
        if (queue_.size() >= gMaxQueueSize) {
            SafeLog("Queue full (size=" + std::to_string(queue_.size()) + "), dropping oldest message", LogLevel::WARNING);
            queue_.pop();  // Remove oldest to make room
        }
        queue_.push(std::move(json));
        cv_.notify_one();
    }

private:
    void ThreadLoop() {
        while (true) {
            std::string job;
            {
                std::unique_lock<std::mutex> lk(mu_);
                cv_.wait(lk, [&] { return !queue_.empty() || !running_; });
                if (!running_ && queue_.empty()) break;
                if (!queue_.empty()) {
                    job = std::move(queue_.front());
                    queue_.pop();
                }
            }
            if (!job.empty()) {
                PostJson(job);
            }
        }
    }

    void PostJson(const std::string& json) {
        try {
            URL_COMPONENTS comps;
            memset(&comps, 0, sizeof(comps));
            comps.dwStructSize = sizeof(comps);
            comps.dwSchemeLength = (DWORD)-1;
            comps.dwHostNameLength = (DWORD)-1;
            comps.dwUrlPathLength = (DWORD)-1;
            comps.dwExtraInfoLength = (DWORD)-1;

            if (gBackendUrl.empty()) {
                SafeLog("Backend URL not configured", LogLevel::ERR);
                return;
            }
            if (!WinHttpCrackUrl(gBackendUrl.c_str(), (DWORD)gBackendUrl.size(), 0, &comps)) {
                SafeLog("Failed to parse backendUrl", LogLevel::ERR);
                return;
            }

            std::wstring host, pathAndQuery;
            if (comps.lpszHostName && comps.dwHostNameLength)
                host.assign(comps.lpszHostName, comps.dwHostNameLength);
            if (comps.lpszUrlPath && comps.dwUrlPathLength)
                pathAndQuery.assign(comps.lpszUrlPath, comps.dwUrlPathLength);
            if (comps.lpszExtraInfo && comps.dwExtraInfoLength)
                pathAndQuery.append(comps.lpszExtraInfo, comps.dwExtraInfoLength);

            HINTERNET hSession = WinHttpOpen(L"IISCollector/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
            if (!hSession) return;

            INTERNET_PORT port = (INTERNET_PORT)(comps.nPort ? comps.nPort :
                (comps.nScheme == INTERNET_SCHEME_HTTPS ? INTERNET_DEFAULT_HTTPS_PORT : INTERNET_DEFAULT_HTTP_PORT));

            HINTERNET hConnect = WinHttpConnect(hSession, host.c_str(), port, 0);
            if (!hConnect) { WinHttpCloseHandle(hSession); return; }

            DWORD flags = (comps.nScheme == INTERNET_SCHEME_HTTPS) ? WINHTTP_FLAG_SECURE : 0;

            HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", pathAndQuery.c_str(), NULL,
                WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
            if (!hRequest) { WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession); return; }

            std::wstring hdrs = L"Content-Type: application/json\r\n";
            BOOL sent = WinHttpSendRequest(hRequest, hdrs.c_str(), (DWORD)-1,
                (LPVOID)json.data(), (DWORD)json.size(), (DWORD)json.size(), 0);

            if (sent) {
                BOOL received = WinHttpReceiveResponse(hRequest, NULL);
                if (received) {
                    DWORD statusCode = 0;
                    DWORD statusCodeSize = sizeof(statusCode);
                    WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                        NULL, &statusCode, &statusCodeSize, NULL);

                    if (statusCode >= 200 && statusCode < 300) {
                        SafeLog("Data sent to backend (HTTP " + std::to_string(statusCode) + ")", LogLevel::DEBUG);
                    }
                    else {
                        SafeLog("Backend returned HTTP " + std::to_string(statusCode), LogLevel::ERR);
                    }
                }
                else {
                    SafeLog("Failed to receive response from backend", LogLevel::ERR);
                }
            }
            else {
                DWORD error = GetLastError();
                SafeLog("Failed to send data to backend (WinHTTP error: " + std::to_string(error) + ")", LogLevel::ERR);
            }

            WinHttpCloseHandle(hRequest);
            WinHttpCloseHandle(hConnect);
            WinHttpCloseHandle(hSession);
        }
        catch (...) {
            SafeLog("Exception in PostJson", LogLevel::ERR);
        }
    }

    std::mutex mu_;
    std::condition_variable cv_;
    std::queue<std::string> queue_;
    std::thread worker_;
    std::atomic<bool> running_;
};

static std::unique_ptr<Poster> gPoster;

// ------------------- Storage for request bodies -------------------
struct RequestBodyStorage {
    std::mutex mu;
    std::map<HTTP_REQUEST_ID, std::shared_ptr<std::string>> bodies;

    void Store(HTTP_REQUEST_ID id, std::shared_ptr<std::string> body) {
        std::lock_guard<std::mutex> lk(mu);
        bodies[id] = body;
    }

    std::string Retrieve(HTTP_REQUEST_ID id) {
        std::lock_guard<std::mutex> lk(mu);
        auto it = bodies.find(id);
        if (it != bodies.end()) {
            std::string result = *(it->second);
            bodies.erase(it);
            return result;
        }
        return "";
    }
};

static RequestBodyStorage gBodyStorage;

// ------------------- Global Module for body capture -------------------
class CollectorGlobalModule : public CGlobalModule
{
public:
    GLOBAL_NOTIFICATION_STATUS
        OnGlobalPreBeginRequest(IPreBeginRequestProvider* pProvider) override
    {
        try {
            IHttpContext* pHttpContext = pProvider->GetHttpContext();
            if (pHttpContext && pHttpContext->GetRequest()) {
                IHttpRequest* pRequest = pHttpContext->GetRequest();
                HTTP_REQUEST* pRawReq = pRequest->GetRawHttpRequest();

                // Determine if this request might have a body
                bool shouldCaptureBody = false;
                if (pRawReq) {
                    // Capture body for POST, PUT, DELETE
                    shouldCaptureBody = (pRawReq->Verb == HttpVerbPOST ||
                                        pRawReq->Verb == HttpVerbPUT ||
                                        pRawReq->Verb == HttpVerbDELETE);

                    // Also check for PATCH as unknown verb
                    if (pRawReq->Verb == HttpVerbUnknown && pRawReq->pUnknownVerb && pRawReq->UnknownVerbLength > 0) {
                        std::string verb = CharBufToString(pRawReq->pUnknownVerb, pRawReq->UnknownVerbLength);
                        if (_stricmp(verb.c_str(), "PATCH") == 0) {
                            shouldCaptureBody = true;
                        }
                    }
                }

                if (shouldCaptureBody) {
                    std::string body;

                    // Try to get from entity chunks (often available here)
                    if (pRawReq->EntityChunkCount > 0 && pRawReq->pEntityChunks) {
                        for (USHORT i = 0; i < pRawReq->EntityChunkCount; ++i) {
                            HTTP_DATA_CHUNK& chunk = pRawReq->pEntityChunks[i];
                            if (chunk.DataChunkType == HttpDataChunkFromMemory &&
                                chunk.FromMemory.pBuffer && chunk.FromMemory.BufferLength > 0) {
                                body.append((const char*)chunk.FromMemory.pBuffer, chunk.FromMemory.BufferLength);
                            }
                        }
                    }

                    // Store the body if we got it
                    if (!body.empty()) {
                        auto bodyPtr = std::make_shared<std::string>(body);
                        gBodyStorage.Store(pRawReq->RequestId, bodyPtr);
                        SafeLog("Captured request body (PreBegin) for RequestId: " +
                               std::to_string(pRawReq->RequestId) +
                               " Size: " + std::to_string(body.size()) + " bytes", LogLevel::DEBUG);
                    }
                }
            }
        }
        catch (...) {
            SafeLog("Exception in OnGlobalPreBeginRequest", LogLevel::ERR);
        }

        return GL_NOTIFICATION_CONTINUE;
    }

    void Terminate() override {
        delete this;
    }
};

static bool IsInterestingContentType(const std::string& ct)
{
    if (ct.empty()) return false;
    std::string lower = ct;
    for (auto& c : lower) c = (char)tolower(c);

    return (lower.find("json") != std::string::npos ||
        lower.find("xml") != std::string::npos ||
        lower.find("grpc") != std::string::npos ||
        lower.find("x-www-form-urlencoded") != std::string::npos ||
        lower.find("form") != std::string::npos ||   // covers multipart/form-data
        lower.find("soap") != std::string::npos);
}

// ------------------- Request Module -------------------
class CollectorModule : public CHttpModule
{
public:
    REQUEST_NOTIFICATION_STATUS
        OnBeginRequest(IHttpContext* pHttpContext, IHttpEventProvider* /*pProvider*/) override
    {
        try {
            if (!pHttpContext || !pHttpContext->GetRequest()) return RQ_NOTIFICATION_CONTINUE;

            IHttpRequest* pRequest = pHttpContext->GetRequest();
            HTTP_REQUEST* pRawReq = pRequest->GetRawHttpRequest();

            if (!pRawReq) return RQ_NOTIFICATION_CONTINUE;

            // Check if this request might have a body
            bool shouldCaptureBody = false;
            shouldCaptureBody = (pRawReq->Verb == HttpVerbPOST ||
                                pRawReq->Verb == HttpVerbPUT ||
                                pRawReq->Verb == HttpVerbDELETE);

            // Also check for PATCH as unknown verb
            if (pRawReq->Verb == HttpVerbUnknown && pRawReq->pUnknownVerb && pRawReq->UnknownVerbLength > 0) {
                std::string verb = CharBufToString(pRawReq->pUnknownVerb, pRawReq->UnknownVerbLength);
                if (_stricmp(verb.c_str(), "PATCH") == 0) {
                    shouldCaptureBody = true;
                }
            }

            if (!shouldCaptureBody) return RQ_NOTIFICATION_CONTINUE;

            auto bodyPtr = std::make_shared<std::string>();

            // Read entity body in chunks
            const DWORD CHUNK_SIZE = 4096;
            DWORD cbRead = 0;
            BOOL fMoreData = TRUE;

            while (fMoreData) {
                BYTE buffer[CHUNK_SIZE];
                cbRead = 0;

                HRESULT hr = pRequest->ReadEntityBody(buffer, CHUNK_SIZE, FALSE, &cbRead, &fMoreData);

                if (FAILED(hr)) {
                    // Handle specific errors
                    if (hr == ERROR_HANDLE_EOF || hr == HRESULT_FROM_WIN32(ERROR_HANDLE_EOF)) {
                        // No more data to read
                        break;
                    }
                    SafeLog("ReadEntityBody failed with HRESULT: 0x" +
                           std::to_string(hr) + " for RequestId: " +
                           std::to_string(pRawReq->RequestId), LogLevel::WARNING);
                    break;
                }

                if (cbRead > 0) {
                    bodyPtr->append((const char*)buffer, cbRead);
                }

                if (!fMoreData || cbRead == 0) {
                    break;
                }

                // Safety limit: don't read more than 10MB
                if (bodyPtr->size() > 10 * 1024 * 1024) {
                    SafeLog("Request body exceeds 10MB, truncating", LogLevel::WARNING);
                    break;
                }
            }

            // Store the captured body and re-insert it
            if (!bodyPtr->empty()) {
                SafeLog("Captured request body (BeginRequest) for RequestId: " +
                       std::to_string(pRawReq->RequestId) +
                       " Size: " + std::to_string(bodyPtr->size()) + " bytes", LogLevel::DEBUG);

                // Store for later retrieval
                gBodyStorage.Store(pRawReq->RequestId, bodyPtr);

                // Re-insert the body so the application can still read it
                pRequest->InsertEntityBody((void*)bodyPtr->data(), (DWORD)bodyPtr->size());
            }
        }
        catch (const std::exception& ex) {
            SafeLog(std::string("Exception in OnBeginRequest: ") + ex.what(), LogLevel::ERR);
        }
        catch (...) {
            SafeLog("Unknown exception in OnBeginRequest", LogLevel::ERR);
        }

        return RQ_NOTIFICATION_CONTINUE;
    }

    REQUEST_NOTIFICATION_STATUS
        OnSendResponse(IHttpContext* pHttpContext, ISendResponseProvider* /*pProvider*/) override
    {
        try {
            if (!pHttpContext || !pHttpContext->GetRequest() || !pHttpContext->GetResponse()) return RQ_NOTIFICATION_CONTINUE;

            IHttpRequest* pReq = pHttpContext->GetRequest();
            IHttpResponse* pResp = pHttpContext->GetResponse();
            PHTTP_REQUEST pRawReq = pReq->GetRawHttpRequest();
            PHTTP_RESPONSE pRawResp = pResp->GetRawHttpResponse();

            // JSON builder
            std::ostringstream out;
            out << "{ \"batchData\": [ {";

            // Path extraction
            std::string path = "";
            std::string queryString = "";

            // Get the raw URL
            if (pRawReq && pRawReq->pRawUrl && pRawReq->RawUrlLength > 0) {
                std::string rawUrl = CharBufToString(pRawReq->pRawUrl, pRawReq->RawUrlLength);

                size_t queryPos = rawUrl.find('?');
                if (queryPos != std::string::npos) {
                    path = rawUrl.substr(0, queryPos);
                    queryString = rawUrl.substr(queryPos + 1);
                }
                else {
                    path = rawUrl;
                }
            }

            // Check for X-Original-URL or X-Rewrite-URL headers (common in reverse proxies)
            if (pRawReq && pRawReq->Headers.pUnknownHeaders) {
                for (USHORT i = 0; i < pRawReq->Headers.UnknownHeaderCount; ++i) {
                    HTTP_UNKNOWN_HEADER& uh = pRawReq->Headers.pUnknownHeaders[i];
                    if (uh.pName && uh.pRawValue) {
                        std::string headerName = CharBufToString(uh.pName, uh.NameLength);
                        // Check for headers that might contain the original URL
                        if (_stricmp(headerName.c_str(), "X-Original-URL") == 0 ||
                            _stricmp(headerName.c_str(), "X-Rewrite-URL") == 0 ||
                            _stricmp(headerName.c_str(), "X-Forwarded-Path") == 0) {
                            std::string originalPath = CharBufToString(uh.pRawValue, uh.RawValueLength);
                            if (!originalPath.empty()) {
                                path = originalPath;
                                break;
                            }
                        }
                    }
                }
            }

            // Add query string if we have one
            if (!queryString.empty()) {
                path += "?" + queryString;
            }

            out << "\"path\":\"" << JsonEscape(path) << "\",";

            // Method
            std::string method = "OTHER";
            if (pRawReq) {
                switch (pRawReq->Verb) {
                case HttpVerbGET: method = "GET"; break;
                case HttpVerbPOST: method = "POST"; break;
                case HttpVerbPUT: method = "PUT"; break;
                case HttpVerbDELETE: method = "DELETE"; break;
                case HttpVerbHEAD: method = "HEAD"; break;
                default:
                    if (pRawReq->Verb == HttpVerbUnknown && pRawReq->pUnknownVerb && pRawReq->UnknownVerbLength)
                        method = CharBufToString(pRawReq->pUnknownVerb, pRawReq->UnknownVerbLength);
                }
            }
            out << "\"method\":\"" << JsonEscape(method) << "\",";

            // ---------------- Request headers ----------------
            std::ostringstream reqHdrs;
            reqHdrs << "{";
            bool firstReqHdr = true;

            // Known headers
            if (pRawReq) {
                struct { HTTP_HEADER_ID id; const char* name; } knownHeaders[] = {
                    {HttpHeaderContentType, "Content-Type"},
                    {HttpHeaderContentLength, "Content-Length"},
                    {HttpHeaderHost, "Host"},
                    {HttpHeaderUserAgent, "User-Agent"},
                    {HttpHeaderAccept, "Accept"},
                    {HttpHeaderAcceptEncoding, "Accept-Encoding"},
                    {HttpHeaderAcceptLanguage, "Accept-Language"},
                    {HttpHeaderAuthorization, "Authorization"},
                    {HttpHeaderCookie, "Cookie"},
                    {HttpHeaderReferer, "Referer"},
                    {HttpHeaderConnection, "Connection"},
                    {HttpHeaderCacheControl, "Cache-Control"}
                };

                for (auto& hdr : knownHeaders) {
                    if (pRawReq->Headers.KnownHeaders[hdr.id].RawValueLength > 0) {
                        if (!firstReqHdr) reqHdrs << ",";
                        std::string value = CharBufToString(
                            pRawReq->Headers.KnownHeaders[hdr.id].pRawValue,
                            pRawReq->Headers.KnownHeaders[hdr.id].RawValueLength
                        );
                        reqHdrs << "\"" << hdr.name << "\":\"" << JsonEscape(value) << "\"";
                        firstReqHdr = false;
                    }
                }
            }

            // Unknown headers
            if (pRawReq && pRawReq->Headers.pUnknownHeaders && pRawReq->Headers.UnknownHeaderCount > 0) {
                for (USHORT i = 0; i < pRawReq->Headers.UnknownHeaderCount; ++i) {
                    HTTP_UNKNOWN_HEADER& uh = pRawReq->Headers.pUnknownHeaders[i];
                    if (uh.pName && uh.NameLength > 0 && uh.pRawValue && uh.RawValueLength > 0) {
                        if (!firstReqHdr) reqHdrs << ",";
                        std::string name = CharBufToString(uh.pName, uh.NameLength);
                        std::string value = CharBufToString(uh.pRawValue, uh.RawValueLength);
                        reqHdrs << "\"" << JsonEscape(name) << "\":\"" << JsonEscape(value) << "\"";
                        firstReqHdr = false;
                    }
                }
            }
            reqHdrs << "}";

            // Insert as escaped string
            out << "\"requestHeaders\":\"" << JsonEscape(reqHdrs.str()) << "\",";


            // ---------------- Response headers ----------------
            std::ostringstream respHdrs;
            respHdrs << "{";
            bool firstRespHdr = true;

            if (pRawResp) {
                struct { HTTP_HEADER_ID id; const char* name; } knownHeaders[] = {
                    {HttpHeaderContentType, "Content-Type"},
                    {HttpHeaderContentLength, "Content-Length"},
                    {HttpHeaderServer, "Server"},
                    {HttpHeaderDate, "Date"},
                    {HttpHeaderConnection, "Connection"},
                    {HttpHeaderCacheControl, "Cache-Control"},
                    {HttpHeaderSetCookie, "Set-Cookie"},
                    {HttpHeaderLocation, "Location"},
                    {HttpHeaderContentEncoding, "Content-Encoding"},
                    {HttpHeaderExpires, "Expires"},
                    {HttpHeaderLastModified, "Last-Modified"},
                    {HttpHeaderEtag, "ETag"},
                    {HttpHeaderVary, "Vary"},
                    {HttpHeaderWwwAuthenticate, "WWW-Authenticate"}
                };

                for (auto& hdr : knownHeaders) {
                    if (pRawResp->Headers.KnownHeaders[hdr.id].RawValueLength > 0) {
                        if (!firstRespHdr) respHdrs << ",";
                        std::string value = CharBufToString(
                            pRawResp->Headers.KnownHeaders[hdr.id].pRawValue,
                            pRawResp->Headers.KnownHeaders[hdr.id].RawValueLength
                        );
                        respHdrs << "\"" << hdr.name << "\":\"" << JsonEscape(value) << "\"";
                        firstRespHdr = false;
                    }
                }
            }

            // Unknown headers
            if (pRawResp && pRawResp->Headers.pUnknownHeaders && pRawResp->Headers.UnknownHeaderCount > 0) {
                for (USHORT i = 0; i < pRawResp->Headers.UnknownHeaderCount; ++i) {
                    HTTP_UNKNOWN_HEADER& uh = pRawResp->Headers.pUnknownHeaders[i];
                    if (uh.pName && uh.NameLength > 0 && uh.pRawValue && uh.RawValueLength > 0) {
                        if (!firstRespHdr) respHdrs << ",";
                        std::string name = CharBufToString(uh.pName, uh.NameLength);
                        std::string value = CharBufToString(uh.pRawValue, uh.RawValueLength);
                        respHdrs << "\"" << JsonEscape(name) << "\":\"" << JsonEscape(value) << "\"";
                        firstRespHdr = false;
                    }
                }
            }
            respHdrs << "}";

            // Insert as escaped string
            out << "\"responseHeaders\":\"" << JsonEscape(respHdrs.str()) << "\",";

            std::string reqContentType = "";
            if (pRawReq && pRawReq->Headers.KnownHeaders[HttpHeaderContentType].RawValueLength > 0) {
                reqContentType = CharBufToString(
                    pRawReq->Headers.KnownHeaders[HttpHeaderContentType].pRawValue,
                    pRawReq->Headers.KnownHeaders[HttpHeaderContentType].RawValueLength
                );
            }

            std::string respContentType = "";
            if (pRawResp && pRawResp->Headers.KnownHeaders[HttpHeaderContentType].RawValueLength > 0) {
                respContentType = CharBufToString(
                    pRawResp->Headers.KnownHeaders[HttpHeaderContentType].pRawValue,
                    pRawResp->Headers.KnownHeaders[HttpHeaderContentType].RawValueLength
                );
            }

            // Request payload - retrieve from our storage (captured in OnBeginRequest)
            std::string reqBody = "";
            if (pRawReq) {
                reqBody = gBodyStorage.Retrieve(pRawReq->RequestId);
            }

            out << "\"requestPayload\":\"" << JsonEscape(reqBody) << "\",";

            // Response payload (memory chunks)
            std::string respBody = "";
            if (pRawResp && pRawResp->EntityChunkCount && pRawResp->pEntityChunks) {
                for (USHORT i = 0; i < pRawResp->EntityChunkCount; ++i) {
                    HTTP_DATA_CHUNK& chunk = pRawResp->pEntityChunks[i];
                    if (chunk.DataChunkType == HttpDataChunkFromMemory && chunk.FromMemory.pBuffer) {
                        respBody += CharBufToString((const char*)chunk.FromMemory.pBuffer, chunk.FromMemory.BufferLength);
                    }
                }
            }
            out << "\"responsePayload\":\"" << JsonEscape(respBody) << "\",";

            // Get client IP address safely
            std::string clientIp = "127.0.0.1";
            try {
                PSOCKADDR pClientAddr = pHttpContext->GetRequest()->GetRemoteAddress();
                if (pClientAddr) {
                    if (pClientAddr->sa_family == AF_INET) {
                        struct sockaddr_in* addr_in = (struct sockaddr_in*)pClientAddr;
                        char ipStr[INET_ADDRSTRLEN];
                        if (inet_ntop(AF_INET, &(addr_in->sin_addr), ipStr, INET_ADDRSTRLEN)) {
                            clientIp = ipStr;
                        }
                    }
                }
            }
            catch (...) {
                // Keep default IP if error
            }

            // Additional fields
            out << "\"ip\":\"" << JsonEscape(clientIp) << "\",";
            out << "\"time\":\"" << std::to_string(std::time(nullptr)) << "\",";

            // Status code and status text
            std::string statusCode = pRawResp ? std::to_string(pRawResp->StatusCode) : "0";
            int code = pRawResp ? pRawResp->StatusCode : 0;

            std::string reason = "Unknown";
            switch (code) {
            case 100: reason = "Continue"; break;
            case 101: reason = "Switching Protocols"; break;
            case 102: reason = "Processing"; break;
            case 103: reason = "Early Hints"; break;

            case 200: reason = "OK"; break;
            case 201: reason = "Created"; break;
            case 202: reason = "Accepted"; break;
            case 203: reason = "Non-Authoritative Information"; break;
            case 204: reason = "No Content"; break;
            case 205: reason = "Reset Content"; break;
            case 206: reason = "Partial Content"; break;
            case 207: reason = "Multi-Status"; break;
            case 208: reason = "Already Reported"; break;
            case 226: reason = "IM Used"; break;

            case 300: reason = "Multiple Choices"; break;
            case 301: reason = "Moved Permanently"; break;
            case 302: reason = "Found"; break;
            case 303: reason = "See Other"; break;
            case 304: reason = "Not Modified"; break;
            case 305: reason = "Use Proxy"; break;
            case 307: reason = "Temporary Redirect"; break;
            case 308: reason = "Permanent Redirect"; break;

            case 400: reason = "Bad Request"; break;
            case 401: reason = "Unauthorized"; break;
            case 402: reason = "Payment Required"; break;
            case 403: reason = "Forbidden"; break;
            case 404: reason = "Not Found"; break;
            case 405: reason = "Method Not Allowed"; break;
            case 406: reason = "Not Acceptable"; break;
            case 407: reason = "Proxy Authentication Required"; break;
            case 408: reason = "Request Timeout"; break;
            case 409: reason = "Conflict"; break;
            case 410: reason = "Gone"; break;
            case 411: reason = "Length Required"; break;
            case 412: reason = "Precondition Failed"; break;
            case 413: reason = "Content Too Large"; break;
            case 414: reason = "URI Too Long"; break;
            case 415: reason = "Unsupported Media Type"; break;
            case 416: reason = "Range Not Satisfiable"; break;
            case 417: reason = "Expectation Failed"; break;
            case 418: reason = "I'm a teapot"; break;
            case 421: reason = "Misdirected Request"; break;
            case 422: reason = "Unprocessable Content"; break;
            case 423: reason = "Locked"; break;
            case 424: reason = "Failed Dependency"; break;
            case 425: reason = "Too Early"; break;
            case 426: reason = "Upgrade Required"; break;
            case 428: reason = "Precondition Required"; break;
            case 429: reason = "Too Many Requests"; break;
            case 431: reason = "Request Header Fields Too Large"; break;
            case 451: reason = "Unavailable For Legal Reasons"; break;

            case 500: reason = "Internal Server Error"; break;
            case 501: reason = "Not Implemented"; break;
            case 502: reason = "Bad Gateway"; break;
            case 503: reason = "Service Unavailable"; break;
            case 504: reason = "Gateway Timeout"; break;
            case 505: reason = "HTTP Version Not Supported"; break;
            case 506: reason = "Variant Also Negotiates"; break;
            case 507: reason = "Insufficient Storage"; break;
            case 508: reason = "Loop Detected"; break;
            case 510: reason = "Not Extended"; break;
            case 511: reason = "Network Authentication Required"; break;

            default:
                if (pRawResp && pRawResp->pReason && pRawResp->ReasonLength > 0) {
                    reason = CharBufToString(pRawResp->pReason, pRawResp->ReasonLength);
                }
                break;
            }

            out << "\"statusCode\":\"" << statusCode << "\",";
            out << "\"type\":\"HTTP/1.1\",";
            out << "\"status\":\"" << JsonEscape(reason) << "\",";

            out << "\"akto_account_id\":\"1000000\",";
            out << "\"akto_vxlan_id\":\"0\",";
            out << "\"is_pending\":\"false\",";
            out << "\"source\":\"MIRRORING\"";

            out << "} ] }";

            // Calculate total payload size (request + response)
            size_t totalPayloadSize = reqBody.size() + respBody.size();

            // Check if payload size meets minimum threshold
            if (gMinPayloadSize > 0 && totalPayloadSize < gMinPayloadSize) {
                SafeLog("Skipping traffic for " + path + " - payload size " +
                       std::to_string(totalPayloadSize) + " bytes is below minimum " +
                       std::to_string(gMinPayloadSize) + " bytes", LogLevel::DEBUG);
                return RQ_NOTIFICATION_CONTINUE;
            }

            // Only forward if:
            //   - statusCode is 2xx or 3xx
            //   - AND request/response Content-Type matches interesting types
            // if (code >= 200 && code < 400) {
            if (IsInterestingContentType(reqContentType) || IsInterestingContentType(respContentType)) {
                SafeLog("Sending traffic to backend for " + path + " - payload size: " +
                       std::to_string(totalPayloadSize) + " bytes", LogLevel::DEBUG);
                if (gPoster) gPoster->Enqueue(out.str());
            }
            // }

        }
        catch (const std::exception& ex) {
            SafeLog(std::string("Exception in OnSendResponse: ") + ex.what(), LogLevel::ERR);
        }
        catch (...) {
            SafeLog("Unknown exception in OnSendResponse", LogLevel::ERR);
        }

        return RQ_NOTIFICATION_CONTINUE;
    }
};

// ------------------- Factory & registration -------------------
class CollectorFactory : public IHttpModuleFactory
{
public:
    virtual HRESULT GetHttpModule(CHttpModule** ppModule, IModuleAllocator* /*pAlloc*/) {
        if (!ppModule) return E_POINTER;
        *ppModule = new CollectorModule();
        return S_OK;
    }
    virtual void Terminate() { delete this; }
};

extern "C" HRESULT __stdcall RegisterModule(DWORD, IHttpModuleRegistrationInfo * pModuleInfo, IHttpServer * pGlobalInfo) {
    if (!pModuleInfo || !pGlobalInfo) return E_POINTER;
    try {
        // Force initial log to verify logging is working
        SafeLog("=== IIS Traffic Collector Module Starting ===", LogLevel::INFO);

        LoadConfig();

        SafeLog("Config loaded. Backend URL configured: " + std::string(gBackendUrl.empty() ? "NO" : "YES"), LogLevel::INFO);
        SafeLog("Log level: " + std::to_string((int)gLogLevel), LogLevel::INFO);

        if (!gPoster) gPoster.reset(new Poster());

        // Register global module
        CollectorGlobalModule* pGlobalModule = new CollectorGlobalModule();
        HRESULT hr = pModuleInfo->SetGlobalNotifications(pGlobalModule, GL_PRE_BEGIN_REQUEST);
        if (FAILED(hr)) {
            delete pGlobalModule;
            return hr;
        }

        // Register request module for both BEGIN_REQUEST and SEND_RESPONSE
        CollectorFactory* pFactory = new CollectorFactory();
        hr = pModuleInfo->SetRequestNotifications(pFactory, RQ_BEGIN_REQUEST | RQ_SEND_RESPONSE, 0);
        if (FAILED(hr)) {
            delete pFactory;
        }
        return hr;
    }
    catch (const std::exception& ex) {
        SafeLog(std::string("Exception in RegisterModule: ") + ex.what(), LogLevel::ERR);
        return E_FAIL;
    }
    catch (...) {
        SafeLog("Unknown exception in RegisterModule", LogLevel::ERR);
        return E_FAIL;
    }
}