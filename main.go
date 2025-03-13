package main

import (
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/gorilla/mux"
)

const (
	s3Endpoint = "https://s3.bitiful.net"
	region     = "cn-east-1"
	port       = ":8080"
	s3Prefix   = "API/" // 添加S3路径前缀
)

// 公告数据结构
type Announcement struct {
	Delta       json.RawMessage `json:"delta"`
	HTML        string          `json:"html"`
	LastUpdated string          `json:"lastUpdated"`
}

var (
	accessKey  = ""			// 从配置文件获取
	secretKey  = ""			// 请替换为实际的密钥
	bucketName = ""			// 需要设置为您的存储桶名称
	s3Client   *s3.Client
	templates  = template.Must(template.New("").Funcs(template.FuncMap{
		"formatSize":    formatFileSize,
		"formatTime":    formatTime,
		"fileIcon":      getFileIcon,
		"isPreviewable": isFilePreviewable,
	}).ParseGlob("templates/*.html"))

	// 公告相关变量
	announcement      Announcement
	announcementFile  = "data/announcement.json"
	announcementMutex sync.RWMutex
)

// 格式化文件大小的函数
func formatFileSize(size int64) string {
	const unit = 1024
	if size < unit {
		return fmt.Sprintf("%d B", size)
	}
	div, exp := int64(unit), 0
	for n := size / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(size)/float64(div), "KMGTPE"[exp])
}

// 格式化时间的函数
func formatTime(t time.Time) string {
	return t.Format("2006-01-02 15:04:05")
}

// 根据文件扩展名获取对应的图标类名
func getFileIcon(filename string) string {
	// 获取文件扩展名（转为小写）
	ext := strings.ToLower(filepath.Ext(filename))

	// 移除扩展名前的点号
	if len(ext) > 0 && ext[0] == '.' {
		ext = ext[1:]
	}

	// 根据扩展名返回适当的图标类
	switch ext {
	// 文档类型
	case "pdf":
		return "bi bi-file-earmark-pdf"
	case "doc", "docx":
		return "bi bi-file-earmark-word"
	case "xls", "xlsx":
		return "bi bi-file-earmark-excel"
	case "ppt", "pptx":
		return "bi bi-file-earmark-ppt"
	case "txt", "md", "log":
		return "bi bi-file-earmark-text"

	// 图片类型
	case "jpg", "jpeg", "png", "gif", "bmp", "svg", "webp":
		return "bi bi-file-earmark-image"

	// 音视频类型
	case "mp3", "wav", "ogg", "flac", "aac":
		return "bi bi-file-earmark-music"
	case "mp4", "avi", "mov", "wmv", "flv", "mkv", "webm":
		return "bi bi-file-earmark-play"

	// 压缩文件
	case "zip", "rar", "7z", "tar", "gz":
		return "bi bi-file-earmark-zip"

	// HTML/CSS/XML文件
	case "html", "htm":
		return "bi bi-filetype-html"
	case "css":
		return "bi bi-filetype-css"
	case "xml":
		return "bi bi-filetype-xml"

	// 程序代码文件 - 使用统一的代码图标
	case "go", "py", "java", "js", "php", "c", "cpp", "cs", "ts", "rb", "swift", "kt",
		"rs", "scala", "dart", "lua", "pl", "r", "m", "h", "vb", "jsx", "tsx", "asm",
		"groovy", "clj", "lisp", "fs", "f", "d", "jl", "ex", "elm", "hs", "erl", "coffee":
		return "bi bi-file-earmark-code"

	// 脚本和配置文件
	case "sh", "bash", "zsh", "cmd", "bat", "ps1":
		return "bi bi-terminal"
	case "json", "yaml", "yml", "toml", "ini", "conf", "config", "properties", "env":
		return "bi bi-gear-fill"

	// 字体文件
	case "ttf", "otf", "woff", "woff2", "eot":
		return "bi bi-file-earmark-font"

	// 3D模型文件
	case "obj", "fbx", "3ds", "blend", "stl", "dae":
		return "bi bi-box"

	// 数据库文件
	case "sql", "db", "sqlite", "mdb", "accdb":
		return "bi bi-database-fill"

	// 电子书文件
	case "epub", "mobi", "azw", "azw3":
		return "bi bi-book"

	// 默认图标
	default:
		return "bi bi-file-earmark"
	}
}

// 初始化S3客户端
func getS3Client(key, secret string) (*s3.Client, error) {
	customResolver := aws.EndpointResolverWithOptionsFunc(func(service, region string, options ...interface{}) (aws.Endpoint, error) {
		if service == s3.ServiceID {
			return aws.Endpoint{URL: s3Endpoint}, nil
		}
		return aws.Endpoint{}, fmt.Errorf("未知的服务请求")
	})

	// 如果secretKey为空，使用accessKey作为secretKey
	// 这是一个猜测，具体取决于Bitiful的实现
	if secret == "" {
		secret = key // 尝试使用accessKey作为secretKey
		log.Println("警告: 使用accessKey作为secretKey")
	}

	customProvider := credentials.NewStaticCredentialsProvider(key, secret, "")
	cfg, err := config.LoadDefaultConfig(context.TODO(),
		config.WithCredentialsProvider(customProvider),
		config.WithEndpointResolverWithOptions(customResolver))

	if err != nil {
		return nil, err
	}

	cfg.Region = region
	return s3.NewFromConfig(cfg), nil
}

// 初始化函数
func init() {
	var err error

	// 设置日志格式和输出
	setupLogger()

	// 从环境变量获取密钥（如果有）
	if envSecret := os.Getenv("S3_SECRET_KEY"); envSecret != "" {
		secretKey = envSecret
	}

	if envBucket := os.Getenv("S3_BUCKET_NAME"); envBucket != "" {
		bucketName = envBucket
	}

	// 确保有必要的密钥
	if secretKey == "" {
		log.Println("警告: S3_SECRET_KEY 未设置，将使用空密钥")
	}

	if bucketName == "" {
		log.Println("警告: S3_BUCKET_NAME 未设置，请设置存储桶名称")
	}

	// 初始化 S3 客户端
	if accessKey != "" {
		s3Client, err = getS3Client(accessKey, secretKey)
		if err != nil {
			log.Fatalf("初始化 S3 客户端失败: %v", err)
		}
	}

	// 确保模板目录存在
	if _, err := os.Stat("templates"); os.IsNotExist(err) {
		err = os.Mkdir("templates", 0755)
		if err != nil {
			log.Fatalf("创建模板目录失败: %v", err)
		}
	}

	// 确保数据目录存在
	if _, err := os.Stat("data"); os.IsNotExist(err) {
		err = os.Mkdir("data", 0755)
		if err != nil {
			log.Fatalf("创建数据目录失败: %v", err)
		}
	}

	// 加载公告内容
	loadAnnouncement()
}

// 设置日志记录器
func setupLogger() {
	// 确保logs目录存在
	if _, err := os.Stat("logs"); os.IsNotExist(err) {
		err = os.Mkdir("logs", 0755)
		if err != nil {
			log.Printf("创建日志目录失败: %v", err)
			return
		}
	}

	// 创建日志文件
	logFileName := fmt.Sprintf("logs/server_%s.log", time.Now().Format("2006-01-02"))
	logFile, err := os.OpenFile(logFileName, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		log.Printf("打开日志文件失败: %v", err)
		return
	}

	// 设置日志输出到文件和控制台
	// 创建多重输出器
	multiWriter := io.MultiWriter(os.Stdout, logFile)
	log.SetOutput(multiWriter)

	// 设置日志前缀和标志
	log.SetPrefix("[云存储系统] ")
	log.SetFlags(log.Ldate | log.Ltime)

	log.Println("日志系统初始化完成，输出到控制台和日志文件:", logFileName)
}

// 请求日志中间件
type responseWriter struct {
	http.ResponseWriter
	statusCode int
	size       int
}

func (rw *responseWriter) WriteHeader(statusCode int) {
	rw.statusCode = statusCode
	rw.ResponseWriter.WriteHeader(statusCode)
}

func (rw *responseWriter) Write(b []byte) (int, error) {
	size, err := rw.ResponseWriter.Write(b)
	rw.size += size
	return size, err
}

func loggerMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// 封装响应写入器
		rw := &responseWriter{
			ResponseWriter: w,
			statusCode:     http.StatusOK, // 默认状态码
		}

		// 获取客户端IP
		clientIP := r.RemoteAddr
		if forwardedFor := r.Header.Get("X-Forwarded-For"); forwardedFor != "" {
			clientIP = strings.Split(forwardedFor, ",")[0]
		} else if realIP := r.Header.Get("X-Real-IP"); realIP != "" {
			clientIP = realIP
		}

		// 获取请求参数
		err := r.ParseForm()
		if err != nil {
			log.Printf("解析请求参数失败: %v", err)
		}

		// 获取请求头信息
		headers := make(map[string]string)
		for key, values := range r.Header {
			headers[key] = strings.Join(values, ", ")
		}

		// 获取Cookie信息
		cookies := make([]string, 0)
		for _, cookie := range r.Cookies() {
			cookies = append(cookies, cookie.Name)
		}

		// 请求开始时的详细日志
		log.Printf(`
请求开始 =====================================
时间: %s
方法: %s
路径: %s
协议: %s
客户端: %s
User-Agent: %s
Referer: %s
Content-Type: %s
Content-Length: %d
Cookie: %s
查询参数: %s
表单参数: %s
=====================================`,
			start.Format("2006-01-02 15:04:05.000"),
			r.Method,
			r.URL.Path,
			r.Proto,
			clientIP,
			r.UserAgent(),
			r.Referer(),
			r.Header.Get("Content-Type"),
			r.ContentLength,
			strings.Join(cookies, ", "),
			r.URL.RawQuery,
			r.Form.Encode(),
		)

		// 处理请求
		next.ServeHTTP(rw, r)

		// 计算处理时间
		duration := time.Since(start)

		// 获取响应状态描述
		statusText := http.StatusText(rw.statusCode)

		// 请求结束时的详细日志
		log.Printf(`
请求结束 =====================================
时间: %s
路径: %s
状态: %d %s
响应大小: %d 字节
处理时间: %v
=====================================`,
			time.Now().Format("2006-01-02 15:04:05.000"),
			r.URL.Path,
			rw.statusCode,
			statusText,
			rw.size,
			duration,
		)

		// 如果状态码不是2xx，记录错误日志
		if rw.statusCode < 200 || rw.statusCode >= 300 {
			log.Printf("警告: 请求 %s 返回非2xx状态码: %d %s", r.URL.Path, rw.statusCode, statusText)
		}

		// 记录慢请求（超过1秒）
		if duration > time.Second {
			log.Printf("警告: 慢请求 - %s 耗时 %v", r.URL.Path, duration)
		}
	})
}

func main() {
	r := mux.NewRouter()

	// 静态文件服务
	fs := http.FileServer(http.Dir("./static"))
	r.PathPrefix("/static/").Handler(http.StripPrefix("/static/", fs))

	// 路由设置
	r.HandleFunc("/", homeHandler).Methods("GET")
	r.HandleFunc("/upload", uploadHandler).Methods("POST")
	r.HandleFunc("/files", listFilesHandler).Methods("GET")
	r.HandleFunc("/download/{key:.+}", downloadHandler).Methods("GET")
	r.HandleFunc("/delete/{key:.+}", deleteHandler).Methods("GET")
	r.HandleFunc("/preview/{key:.+}", previewHandler).Methods("GET")
	r.HandleFunc("/save-announcement", saveAnnouncementHandler).Methods("POST")

	// 应用中间件
	loggedRouter := loggerMiddleware(r)

	// 启动服务器
	log.Printf("服务器启动在 http://localhost%s", port)
	log.Fatal(http.ListenAndServe(port, loggedRouter))
}

// 首页处理器
func homeHandler(w http.ResponseWriter, r *http.Request) {
	// 读取公告内容
	announcementMutex.RLock()
	data := map[string]interface{}{
		"AnnouncementDelta": template.JS(announcement.Delta),
		"LastUpdated":       announcement.LastUpdated,
	}
	announcementMutex.RUnlock()

	templates.ExecuteTemplate(w, "index.html", data)
}

// 上传文件处理器
func uploadHandler(w http.ResponseWriter, r *http.Request) {
	log.Println("收到上传请求")

	if s3Client == nil {
		log.Println("错误: S3 客户端未初始化")
		http.Error(w, "S3 客户端未初始化", http.StatusInternalServerError)
		return
	}

	if bucketName == "" {
		log.Println("错误: 存储桶名称未设置")
		http.Error(w, "存储桶名称未设置", http.StatusInternalServerError)
		return
	}

	// 解析表单，获取文件
	err := r.ParseMultipartForm(32 << 20) // 32MB
	if err != nil {
		log.Printf("解析表单失败: %v", err)
		http.Error(w, "解析表单失败: "+err.Error(), http.StatusBadRequest)
		return
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		log.Printf("获取文件失败: %v", err)
		http.Error(w, "获取文件失败: "+err.Error(), http.StatusBadRequest)
		return
	}
	defer file.Close()

	// 生成文件名（使用原始文件名），添加API/前缀
	filename := s3Prefix + header.Filename
	log.Printf("准备上传文件: %s 到存储桶: %s", filename, bucketName)

	// 将文件上传到S3
	_, err = s3Client.PutObject(context.TODO(), &s3.PutObjectInput{
		Bucket: aws.String(bucketName),
		Key:    aws.String(filename),
		Body:   file,
	})

	if err != nil {
		log.Printf("上传文件失败: %v", err)
		http.Error(w, "上传文件失败: "+err.Error(), http.StatusInternalServerError)
		return
	}

	log.Printf("文件 %s 上传成功", filename)
	// 重定向到文件列表页面
	http.Redirect(w, r, "/files", http.StatusSeeOther)
}

// 文件列表处理器
func listFilesHandler(w http.ResponseWriter, r *http.Request) {
	if s3Client == nil {
		http.Error(w, "S3 客户端未初始化", http.StatusInternalServerError)
		return
	}

	if bucketName == "" {
		http.Error(w, "存储桶名称未设置", http.StatusInternalServerError)
		return
	}

	// 从S3获取文件列表，只获取API/前缀的文件
	resp, err := s3Client.ListObjectsV2(context.TODO(), &s3.ListObjectsV2Input{
		Bucket: aws.String(bucketName),
		Prefix: aws.String(s3Prefix), // 只列出API/目录下的文件
	})

	if err != nil {
		http.Error(w, "获取文件列表失败: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// 准备文件信息
	type FileInfo struct {
		Name         string
		Size         int64
		LastModified time.Time
		Key          string // 添加完整的Key
	}

	var files []FileInfo
	for _, obj := range resp.Contents {
		// 跳过API/文件夹本身
		if *obj.Key == s3Prefix {
			continue
		}

		// 从完整路径中提取文件名（去掉前缀）
		name := *obj.Key
		if len(name) > len(s3Prefix) {
			name = name[len(s3Prefix):]
		}

		files = append(files, FileInfo{
			Name:         name,
			Size:         *obj.Size,
			LastModified: *obj.LastModified,
			Key:          *obj.Key, // 保存完整Key用于下载
		})
	}

	// 获取操作消息（如有）
	message := r.URL.Query().Get("message")
	messageType := r.URL.Query().Get("type")

	// 准备传递给模板的数据
	data := map[string]interface{}{
		"Files":       files,
		"Message":     message,
		"MessageType": messageType,
	}

	// 渲染模板
	templates.ExecuteTemplate(w, "files.html", data)
}

// 下载文件处理器
func downloadHandler(w http.ResponseWriter, r *http.Request) {
	if s3Client == nil {
		http.Error(w, "S3 客户端未初始化", http.StatusInternalServerError)
		return
	}

	if bucketName == "" {
		http.Error(w, "存储桶名称未设置", http.StatusInternalServerError)
		return
	}

	// 获取文件key
	vars := mux.Vars(r)
	key := vars["key"]

	// 确保key包含API/前缀
	if !strings.HasPrefix(key, s3Prefix) {
		key = s3Prefix + key
	}

	// 创建预签名URL客户端
	preSignClient := s3.NewPresignClient(s3Client)

	// 生成预签名下载链接
	preSignedRequest, err := preSignClient.PresignGetObject(context.TODO(),
		&s3.GetObjectInput{
			Bucket: aws.String(bucketName),
			Key:    aws.String(key),
		},
		func(opts *s3.PresignOptions) {
			opts.Expires = time.Hour // 设置链接有效期为1小时
		})

	if err != nil {
		http.Error(w, "生成下载链接失败: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// 重定向到预签名URL
	http.Redirect(w, r, preSignedRequest.URL, http.StatusSeeOther)
}

// 删除文件处理器
func deleteHandler(w http.ResponseWriter, r *http.Request) {
	if s3Client == nil {
		http.Error(w, "S3 客户端未初始化", http.StatusInternalServerError)
		return
	}

	if bucketName == "" {
		http.Error(w, "存储桶名称未设置", http.StatusInternalServerError)
		return
	}

	// 获取文件key
	vars := mux.Vars(r)
	key := vars["key"]

	// 确保key包含API/前缀
	if !strings.HasPrefix(key, s3Prefix) {
		key = s3Prefix + key
	}

	log.Printf("准备删除文件: %s", key)

	// 从S3删除文件
	_, err := s3Client.DeleteObject(context.TODO(), &s3.DeleteObjectInput{
		Bucket: aws.String(bucketName),
		Key:    aws.String(key),
	})

	if err != nil {
		log.Printf("删除文件失败: %v", err)
		http.Error(w, "删除文件失败: "+err.Error(), http.StatusInternalServerError)
		return
	}

	log.Printf("文件 %s 删除成功", key)

	// 重定向到文件列表页面，带上成功消息
	http.Redirect(w, r, "/files?message=文件删除成功&type=success", http.StatusSeeOther)
}

// 判断文件是否可预览
func isFilePreviewable(filename string) bool {
	ext := strings.ToLower(filepath.Ext(filename))

	// 移除扩展名前的点号
	if len(ext) > 0 && ext[0] == '.' {
		ext = ext[1:]
	}

	// 可预览的文件类型
	previewableTypes := map[string]bool{
		// 图片格式
		"jpg": true, "jpeg": true, "png": true, "gif": true, "svg": true, "webp": true, "bmp": true,

		// 文本/代码格式
		"txt": true, "md": true, "html": true, "css": true, "js": true, "json": true, "xml": true,
		"yml": true, "yaml": true, "ini": true, "conf": true, "config": true, "log": true,
		"go": true, "py": true, "java": true, "c": true, "cpp": true, "cs": true, "php": true,
		"sh": true, "bat": true, "ps1": true, "sql": true, "r": true, "rb": true, "pl": true,
		"swift": true, "kt": true, "dart": true, "ts": true, "jsx": true, "tsx": true,

		// 文档格式
		"pdf": true,
	}

	return previewableTypes[ext]
}

// 获取MIME类型
func getMimeType(filename string) string {
	ext := strings.ToLower(filepath.Ext(filename))

	// 移除扩展名前的点号
	if len(ext) > 0 && ext[0] == '.' {
		ext = ext[1:]
	}

	mimeTypes := map[string]string{
		// 图片
		"jpg": "image/jpeg", "jpeg": "image/jpeg", "png": "image/png",
		"gif": "image/gif", "svg": "image/svg+xml", "webp": "image/webp",
		"bmp": "image/bmp",

		// 文本/代码
		"txt": "text/plain", "md": "text/markdown", "html": "text/html",
		"css": "text/css", "js": "application/javascript", "json": "application/json",
		"xml": "application/xml", "yml": "application/yaml", "yaml": "application/yaml",
		"ini": "text/plain", "conf": "text/plain", "config": "text/plain",
		"log": "text/plain", "go": "text/plain", "py": "text/plain",
		"java": "text/plain", "c": "text/plain", "cpp": "text/plain",
		"cs": "text/plain", "php": "text/plain", "sh": "text/plain",
		"bat": "text/plain", "ps1": "text/plain", "sql": "text/plain",
		"r": "text/plain", "rb": "text/plain", "pl": "text/plain",
		"swift": "text/plain", "kt": "text/plain", "dart": "text/plain",
		"ts": "text/plain", "jsx": "text/plain", "tsx": "text/plain",

		// 文档
		"pdf": "application/pdf",
	}

	if mime, ok := mimeTypes[ext]; ok {
		return mime
	}
	return "application/octet-stream"
}

// 识别文件是否为文本类型
func isTextFile(filename string) bool {
	ext := strings.ToLower(filepath.Ext(filename))

	// 移除扩展名前的点号
	if len(ext) > 0 && ext[0] == '.' {
		ext = ext[1:]
	}

	// 文本类型文件
	textTypes := map[string]bool{
		"txt": true, "md": true, "html": true, "css": true, "js": true, "json": true, "xml": true,
		"yml": true, "yaml": true, "ini": true, "conf": true, "config": true, "log": true,
		"go": true, "py": true, "java": true, "c": true, "cpp": true, "cs": true, "php": true,
		"sh": true, "bat": true, "ps1": true, "sql": true, "r": true, "rb": true, "pl": true,
		"swift": true, "kt": true, "dart": true, "ts": true, "jsx": true, "tsx": true,
	}

	return textTypes[ext]
}

// 获取语法高亮的编程语言
func getHighlightLanguage(filename string) string {
	ext := strings.ToLower(filepath.Ext(filename))

	// 移除扩展名前的点号
	if len(ext) > 0 && ext[0] == '.' {
		ext = ext[1:]
	}

	// 语言映射
	langMap := map[string]string{
		"js": "javascript", "py": "python", "rb": "ruby", "php": "php",
		"java": "java", "go": "go", "cs": "csharp", "cpp": "cpp", "c": "c",
		"ts": "typescript", "html": "html", "css": "css", "xml": "xml",
		"json": "json", "md": "markdown", "yml": "yaml", "yaml": "yaml",
		"sh": "bash", "bat": "batch", "ps1": "powershell", "sql": "sql",
		"r": "r", "pl": "perl", "swift": "swift", "kt": "kotlin",
		"dart": "dart", "jsx": "jsx", "tsx": "tsx",
	}

	if lang, ok := langMap[ext]; ok {
		return lang
	}
	return "plaintext"
}

// 文件预览处理器
func previewHandler(w http.ResponseWriter, r *http.Request) {
	if s3Client == nil {
		http.Error(w, "S3 客户端未初始化", http.StatusInternalServerError)
		return
	}

	if bucketName == "" {
		http.Error(w, "存储桶名称未设置", http.StatusInternalServerError)
		return
	}

	// 获取文件key
	vars := mux.Vars(r)
	key := vars["key"]

	// 确保key包含API/前缀
	if !strings.HasPrefix(key, s3Prefix) {
		key = s3Prefix + key
	}

	log.Printf("准备预览文件: %s", key)

	// 从S3获取文件
	resp, err := s3Client.GetObject(context.TODO(), &s3.GetObjectInput{
		Bucket: aws.String(bucketName),
		Key:    aws.String(key),
	})

	if err != nil {
		log.Printf("获取文件失败: %v", err)
		http.Error(w, "获取文件失败: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	// 获取文件名
	filename := key
	if len(key) > len(s3Prefix) {
		filename = key[len(s3Prefix):]
	}

	// 确定内容类型
	contentType := getMimeType(filename)
	w.Header().Set("Content-Type", contentType)

	// 如果是图片或PDF，直接显示
	if strings.HasPrefix(contentType, "image/") || contentType == "application/pdf" {
		io.Copy(w, resp.Body)
		return
	}

	// 如果是文本文件，显示预览页面
	if isTextFile(filename) {
		// 读取文件内容
		content, err := io.ReadAll(resp.Body)
		if err != nil {
			log.Printf("读取文件内容失败: %v", err)
			http.Error(w, "读取文件内容失败: "+err.Error(), http.StatusInternalServerError)
			return
		}

		// 准备文本预览数据
		data := map[string]interface{}{
			"Filename":  filename,
			"Content":   string(content),
			"Language":  getHighlightLanguage(filename),
			"FileSize":  formatFileSize(*resp.ContentLength),
			"UpdatedAt": formatTime(time.Now()),
		}

		// 使用文本预览模板
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		templates.ExecuteTemplate(w, "preview.html", data)
		return
	}

	// 对于其他文件类型，提供下载
	w.Header().Set("Content-Disposition", "attachment; filename="+filename)
	io.Copy(w, resp.Body)
}

// 加载公告内容
func loadAnnouncement() {
	announcementMutex.Lock()
	defer announcementMutex.Unlock()

	// 检查文件是否存在
	if _, err := os.Stat(announcementFile); os.IsNotExist(err) {
		// 文件不存在，使用默认值
		announcement = Announcement{
			Delta:       json.RawMessage("[]"),
			HTML:        "",
			LastUpdated: "",
		}
		return
	}

	// 读取文件内容
	file, err := os.Open(announcementFile)
	if err != nil {
		log.Printf("打开公告文件失败: %v", err)
		return
	}
	defer file.Close()

	// 解析JSON
	err = json.NewDecoder(file).Decode(&announcement)
	if err != nil {
		log.Printf("解析公告JSON失败: %v", err)
		return
	}

	log.Println("公告内容加载成功")
}

// 保存公告内容
func saveAnnouncement(delta json.RawMessage, html string) error {
	announcementMutex.Lock()
	defer announcementMutex.Unlock()

	// 更新公告内容
	announcement = Announcement{
		Delta:       delta,
		HTML:        html,
		LastUpdated: time.Now().Format("2006-01-02 15:04:05"),
	}

	// 创建目录（如果不存在）
	dir := filepath.Dir(announcementFile)
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		err = os.MkdirAll(dir, 0755)
		if err != nil {
			return fmt.Errorf("创建目录失败: %v", err)
		}
	}

	// 创建临时文件
	tempFile := announcementFile + ".tmp"
	file, err := os.Create(tempFile)
	if err != nil {
		return fmt.Errorf("创建临时文件失败: %v", err)
	}

	// 编码为JSON并写入临时文件
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	err = encoder.Encode(announcement)
	file.Close()
	if err != nil {
		os.Remove(tempFile)
		return fmt.Errorf("写入JSON失败: %v", err)
	}

	// 重命名临时文件为目标文件
	err = os.Rename(tempFile, announcementFile)
	if err != nil {
		os.Remove(tempFile)
		return fmt.Errorf("重命名文件失败: %v", err)
	}

	log.Println("公告内容保存成功")
	return nil
}

// 保存公告处理器
func saveAnnouncementHandler(w http.ResponseWriter, r *http.Request) {
	// 解析JSON请求
	var request struct {
		Delta json.RawMessage `json:"delta"`
		HTML  string          `json:"html"`
	}

	err := json.NewDecoder(r.Body).Decode(&request)
	if err != nil {
		log.Printf("解析请求失败: %v", err)
		http.Error(w, "无效的请求格式", http.StatusBadRequest)
		return
	}

	// 保存公告内容
	err = saveAnnouncement(request.Delta, request.HTML)
	if err != nil {
		log.Printf("保存公告失败: %v", err)
		http.Error(w, "保存公告失败: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// 返回成功响应
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":      "success",
		"lastUpdated": announcement.LastUpdated,
	})
}
