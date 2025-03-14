# filesave_Bitiful 云存储文件管理系统

这是一个基于Go语言和Bootstrap开发的云存储文件管理系统，可以轻松地上传、查看、下载和删除文件。本项目使用Bitiful缤纷云对象存储服务作为后端存储。

![](https://github.com/jacksalad/filesave_Bitiful/blob/main/static/screencapture1.png)

![](https://github.com/jacksalad/filesave_Bitiful/blob/main/static/screencapture2.png)

![](https://github.com/jacksalad/filesave_Bitiful/blob/main/static/screencapture3.png)

## 功能特点

- 简洁美观的用户界面
- 拖放上传文件功能
- 文件列表查看，包含文件名、大小和上传时间
- 智能文件图标显示，支持多种文件类型
- 文件在线预览功能，支持图片、文本和代码文件
- 代码语法高亮和行号显示
- 一键下载文件
- 安全的文件删除功能，带确认对话框
- 富文本公告栏，支持编辑和保存
- 操作反馈提示
- 详细的请求日志记录
- 响应式设计，适配各种设备屏幕
- 明亮/暗色主题切换功能，支持系统主题偏好

## 技术栈

### 后端
- Go 1.16+
- gorilla/mux 路由框架
- aws-sdk-go-v2 (用于S3兼容的存储服务对接)
- 自定义中间件系统
- JSON文件持久化存储

### 前端
- Bootstrap 5.2.3
- jQuery 3.6.4
- Bootstrap Icons 1.10.4
- Highlight.js 11.7.0 (代码语法高亮)
- Quill.js 1.3.7 (富文本编辑器)
- 现代化的模态对话框
- AJAX异步操作
- 本地存储主题偏好

### 存储
- Bitiful缤纷云对象存储服务（S3兼容）

## 系统架构

### 后端架构
1. **路由层**
   - 使用gorilla/mux进行路由管理
   - RESTful API设计
   - 静态文件服务

2. **中间件层**
   - 请求日志中间件（详细的请求响应日志）
   - 错误处理中间件
   - 性能监控（慢请求检测）

3. **处理器层**
   - 文件上传处理
   - 文件列表展示
   - 文件下载处理
   - 文件删除处理

4. **存储层**
   - S3客户端封装
   - 对象存储操作
   - 预签名URL生成

### 前端架构
1. **UI层**
   - 响应式布局
   - 明亮/暗色主题支持
   - 交互式组件

2. **交互层**
   - AJAX文件上传
   - 进度条反馈
   - 主题切换逻辑

3. **持久层**
   - 本地存储用户偏好
   - 系统主题检测

### 日志系统
- 多级日志记录
- 请求追踪
- 性能监控
- 错误警告
- 日志本地持久化

## 快速开始

### 环境要求

- Go 1.16+
- 可用的S3兼容存储服务

### 安装与运行

1. 克隆项目到本地
2. 设置必要的环境变量
   ```bash
   # Windows PowerShell
   $env:S3_SECRET_KEY="your_secret_key"
   $env:S3_BUCKET_NAME="your_bucket_name"
   
   # Windows CMD
   set S3_SECRET_KEY=your_secret_key
   set S3_BUCKET_NAME=your_bucket_name
   
   # Linux/Mac
   export S3_SECRET_KEY=your_secret_key
   export S3_BUCKET_NAME=your_bucket_name
   ```
3. 运行项目
   ```bash
   go run .
   ```
4. 在浏览器中访问 http://localhost:8080

## 目录结构

```
├── main.go              # 主程序入口
├── templates/           # HTML模板目录
│   ├── index.html      # 首页（文件上传和公告栏）
│   ├── files.html      # 文件列表页面
│   └── preview.html    # 文件预览页面
├── static/             # 静态资源目录
│   └── styles.css      # 自定义样式
├── data/               # 数据存储目录
│   └── announcement.json # 公告内容存储
├── logs/               # 日志目录
│   └── server_*.log    # 按日期分割的日志文件
├── go.mod              # Go模块文件
└── go.sum              # Go模块校验文件
```

## API接口说明

### 1. 文件上传
- 路径: `/upload`
- 方法: `POST`
- 参数: 
  - `file`: 文件数据（multipart/form-data）
- 响应: 重定向到文件列表页面

### 2. 文件列表
- 路径: `/files`
- 方法: `GET`
- 响应: HTML页面，显示文件列表

### 3. 文件下载
- 路径: `/download/{key}`
- 方法: `GET`
- 参数:
  - `key`: 文件的唯一标识符
- 响应: 文件下载流或预签名URL重定向

### 4. 文件删除
- 路径: `/delete/{key}`
- 方法: `GET`
- 参数:
  - `key`: 文件的唯一标识符
- 响应: 重定向到文件列表页面

### 5. 文件预览
- 路径: `/preview/{key}`
- 方法: `GET`
- 参数:
  - `key`: 文件的唯一标识符
- 响应: 根据文件类型返回不同内容
  - 图片: 直接显示图片
  - 文本/代码: 语法高亮的预览页面
  - PDF: 浏览器内置PDF查看器
  - 其他: 提供下载

### 6. 保存公告
- 路径: `/save-announcement`
- 方法: `POST`
- 参数: JSON格式
  - `delta`: Quill编辑器的内容Delta对象
  - `html`: 编辑器内容的HTML表示
- 响应: JSON
  - `status`: 操作状态
  - `lastUpdated`: 最后更新时间

## 自定义配置

在`main.go`文件中可以修改以下常量来自定义配置：

```go
const (
    s3Endpoint = "https://s3.bitiful.net"  // S3兼容服务的端点
    region     = "cn-east-1"               // 区域
    port       = ":8080"                   // 服务器端口
    s3Prefix   = "API/"                    // S3对象前缀
)
```

## 日志配置

系统使用结构化日志记录，包含以下信息：
- 请求时间（精确到毫秒）
- HTTP方法和路径
- 客户端信息（IP、User-Agent）
- 请求头和Cookie信息
- 响应状态和处理时间
- 错误和警告信息

## 用户界面特性

### 公告栏功能
系统提供可编辑的公告栏功能：
1. **富文本编辑**：基于Quill.js实现，支持文本格式化、列表、链接和图片等
2. **即时编辑**：通过编辑按钮进入编辑模式，支持所见即所得的编辑体验
3. **内容持久化**：公告内容保存在服务器，重启后保持不变
4. **操作反馈**：编辑和保存操作都有明确的界面反馈
5. **修改记录**：显示最后更新时间，方便了解公告的时效性

### 文件预览功能
系统提供对多种类型文件的预览功能：
1. **图片预览**：直接在浏览器中显示jpg、png、gif等格式图片
2. **代码预览**：
   - 语法高亮支持超过30种编程语言
   - 可切换明亮/暗色代码主题
   - 行号显示切换
   - 文本自动换行选项
3. **文档预览**：支持PDF等常见文档格式预览

### 主题切换
系统支持明亮和暗色两种主题模式：
1. **自动检测**：首次访问时，系统会自动检测用户设备的系统主题偏好
2. **手动切换**：用户可以通过页面右上角的主题切换按钮随时切换主题
3. **记忆功能**：系统会记住用户的主题选择，下次访问时自动应用

### 响应式设计
- 移动设备友好的界面布局
- 触摸友好的交互元素
- 适应不同屏幕尺寸的流式布局

### 交互反馈
- 文件上传进度实时显示
- 操作结果即时反馈
- 错误信息清晰展示

## 前端定制

您可以通过修改CSS变量来自定义暗色主题的颜色：

```css
[data-bs-theme="dark"] {
    --bs-body-bg: #222;            /* 背景色 */
    --bs-body-color: #e0e0e0;      /* 文本色 */
    /* 其他自定义变量 */
}
```

要添加或修改主题相关的UI元素，可以编辑以下文件：
- `templates/files.html` - 文件列表页面的主题实现
- `templates/index.html` - 首页的主题实现

## 部署说明

1. 构建可执行文件
   ```bash
   go build -o filestorage
   ```

2. 准备部署环境
   - 创建必要的目录（logs、static等）
   - 确保templates目录存在并包含所有模板文件

3. 设置环境变量并运行
   ```bash
   # 设置环境变量
   export S3_SECRET_KEY=your_secret_key
   export S3_BUCKET_NAME=your_bucket_name
   
   # 运行应用
   ./filestorage
   ```

## 注意事项

1. **安全性考虑**
   - 请确保正确设置`S3_SECRET_KEY`和`S3_BUCKET_NAME`环境变量
   - 建议在生产环境中使用HTTPS
   - 注意文件上传大小限制（默认32MB）

2. **性能优化**
   - 文件上传使用分块传输
   - 下载使用预签名URL
   - 设置了慢请求监控（>1s）

3. **存储管理**
   - 文件上传使用原始文件名作为对象键
   - 所有文件存储在指定的S3前缀下
   - 注意同名文件会被覆盖

4. **日志管理**
   - 日志文件按日期自动分割
   - 建议定期清理旧日志
   - 可通过日志分析工具进行监控

## 贡献指南

欢迎提交Issue和Pull Request来改进这个项目。在提交代码前，请确保：

1. 代码符合Go的代码规范
2. 添加了必要的注释和文档
3. 通过了所有测试
4. 更新了相关文档

## 许可证

MIT License 
