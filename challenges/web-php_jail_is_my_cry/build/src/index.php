<?php
if (isset($_POST['url'])) {
    $url = $_POST['url'];
    $file_name = basename($url);
    
    $ch = curl_init($url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    $data = curl_exec($ch);
    curl_close($ch);
    
    if ($data) {
        file_put_contents('/tmp/'.$file_name, $data);
        echo "文件已下载: <a href='?down=$file_name'>$file_name</a>";
    } else {
        echo "下载失败。";
    }
}

if (isset($_GET['down'])){
    include '/tmp/' . basename($_GET['down']);
    exit;
}

// 上传文件
if (isset($_FILES['file'])) {
    $target_dir = "/tmp/";
    $target_file = $target_dir . basename($_FILES["file"]["name"]);
    $orig = $_FILES["file"]["tmp_name"];
    $ch = curl_init('file://'. $orig);
    curl_setopt($ch, CURLOPT_PROTOCOLS_STR, "all"); // secret trick to bypass, omg why will i show it to you!
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    $data = curl_exec($ch);
    curl_close($ch);
    if (stripos($data, '<?') === false && stripos($data, 'php') === false && stripos($data, 'halt') === false) {
        file_put_contents($target_file, $data);
    } else {
        echo "存在 `<?` 或者 `php` 或者 `halt` 恶意字符!";
        $data = null;
    }
}
?>

<!DOCTYPE html>
<html lang="zh-cn">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>文件下载工具</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }

        .container {
            background: white;
            padding: 40px;
            border-radius: 15px;
            box-shadow: 0 15px 35px rgba(0, 0, 0, 0.1);
            max-width: 500px;
            width: 90%;
        }

        h1 {
            text-align: center;
            color: #333;
            margin-bottom: 30px;
            font-size: 2.2em;
            font-weight: 300;
        }

        .form-group {
            margin-bottom: 25px;
        }

        label {
            display: block;
            margin-bottom: 8px;
            color: #555;
            font-weight: 500;
        }

        input[type="text"] {
            width: 100%;
            padding: 15px;
            border: 2px solid #e1e1e1;
            border-radius: 8px;
            font-size: 16px;
            transition: border-color 0.3s ease;
        }

        input[type="text"]:focus {
            outline: none;
            border-color: #667eea;
            box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
        }

        /* 选项卡样式 */
        .tabs {
            display: flex;
            margin-bottom: 30px;
            border-bottom: 2px solid #f1f1f1;
        }

        .tab-button {
            flex: 1;
            padding: 15px;
            border: none;
            background: transparent;
            color: #666;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            border-bottom: 3px solid transparent;
            transition: all 0.3s ease;
        }

        .tab-button.active {
            color: #667eea;
            border-bottom-color: #667eea;
            background: rgba(102, 126, 234, 0.05);
        }

        .tab-button:hover {
            color: #667eea;
            background: rgba(102, 126, 234, 0.05);
        }

        .tab-content {
            display: none;
        }

        .tab-content.active {
            display: block;
        }

        /* 文件上传样式 */
        .file-input-wrapper {
            position: relative;
            display: block;
        }

        input[type="file"] {
            position: absolute;
            opacity: 0;
            width: 100%;
            height: 100%;
            cursor: pointer;
        }

        .file-input-label {
            display: block;
            padding: 40px 20px;
            border: 2px dashed #e1e1e1;
            border-radius: 8px;
            text-align: center;
            cursor: pointer;
            transition: all 0.3s ease;
            background: #fafafa;
        }

        .file-input-label:hover {
            border-color: #667eea;
            background: rgba(102, 126, 234, 0.05);
        }

        .file-input-wrapper.dragover .file-input-label {
            border-color: #667eea;
            background: rgba(102, 126, 234, 0.1);
            transform: scale(1.02);
        }

        .file-input-wrapper.has-file .file-input-label {
            border-color: #28a745;
            background: rgba(40, 167, 69, 0.05);
            color: #28a745;
        }

        button {
            width: 100%;
            padding: 15px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            border-radius: 8px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: transform 0.2s ease, box-shadow 0.2s ease;
        }

        button:hover {
            transform: translateY(-2px);
            box-shadow: 0 8px 25px rgba(102, 126, 234, 0.3);
        }

        button:active {
            transform: translateY(0);
        }

        .result {
            margin-top: 25px;
            padding: 15px;
            border-radius: 8px;
            text-align: center;
        }

        .success {
            background-color: #d4edda;
            color: #155724;
            border: 1px solid #c3e6cb;
        }

        .error {
            background-color: #f8d7da;
            color: #721c24;
            border: 1px solid #f5c6cb;
        }

        .result a {
            color: #007bff;
            text-decoration: none;
            font-weight: 600;
        }

        .result a:hover {
            text-decoration: underline;
        }

        .loading {
            display: none;
            text-align: center;
            margin-top: 15px;
        }

        .spinner {
            border: 3px solid #f3f3f3;
            border-top: 3px solid #667eea;
            border-radius: 50%;
            width: 30px;
            height: 30px;
            animation: spin 1s linear infinite;
            margin: 0 auto 10px;
        }

        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }

        .tip {
            background-color: #f8f9fa;
            border: 1px solid #dee2e6;
            border-radius: 8px;
            padding: 15px;
            margin-top: 20px;
            color: #6c757d;
            font-size: 14px;
        }

        .tip strong {
            color: #495057;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🚀 文件管理工具</h1>
        <div class="tabs">
            <button class="tab-button active" onclick="switchTab('download')">📥 下载文件</button>
            <button class="tab-button" onclick="switchTab('upload')">📤 上传文件</button>
        </div>
        
        <!-- 下载表单 -->
        <div id="downloadTab" class="tab-content active">
            <form method="post" id="downloadForm">
                <div class="form-group">
                    <label for="url">📎 文件URL地址:</label>
                    <input type="text" id="url" name="url" placeholder="请输入要下载的文件URL..." required>
                </div>
                <button type="submit" id="submitBtn">
                    <span id="btnText">开始下载</span>
                </button>
                <div class="loading" id="loading">
                    <div class="spinner"></div>
                    <p>正在下载中，请稍候...</p>
                </div>
            </form>
        </div>
        
        <!-- 上传表单 -->
        <div id="uploadTab" class="tab-content">
            <form method="post" enctype="multipart/form-data" id="uploadForm">
                <div class="form-group">
                    <label for="file">📁 选择文件:</label>
                    <div class="file-input-wrapper">
                        <input type="file" id="file" name="file" required>
                        <label for="file" class="file-input-label">
                            <span id="file-label-text">点击选择文件或拖拽文件到此处</span>
                        </label>
                    </div>
                </div>
                <button type="submit" id="uploadBtn">
                    <span id="uploadBtnText">开始上传</span>
                </button>
                <div class="loading" id="uploadLoading">
                    <div class="spinner"></div>
                    <p>正在上传中，请稍候...</p>
                </div>
            </form>
        </div>
        
        <?php if (isset($_POST['url'])): ?>
            <div class="result <?php echo $data ? 'success' : 'error'; ?>">
                <?php if ($data): ?>
                    ✅ 文件下载成功！<br>
                    <a href="<?php echo ($file_name); ?>" download>📥 点击下载: <?php echo ($file_name); ?></a>
                <?php else: ?>
                    ❌ 下载失败，请检查URL是否正确或稍后再试。
                <?php endif; ?>
            </div>
        <?php endif; ?>
        
        <?php if (isset($_FILES['file'])): ?>
            <div class="result <?php echo (stripos($data, '<?') === false && stripos($data, 'halt') === false) ? 'success' : 'error'; ?>">
                <?php if (stripos($data, '<?') === false && stripos($data, 'halt') === false): ?>
                    ✅ 文件上传成功！<br>
                    <a href="?down=<?php echo (basename($_FILES["file"]["name"])); ?>">📥 点击下载: <?php echo ($target_file); ?></a>
                <?php else: ?>
                    ❌ 上传失败，文件包含恶意字符或格式不正确。
                <?php endif; ?>
            </div>
        <?php endif; ?>
    </div>

    <script>
        // 选项卡切换功能
        function switchTab(tabName) {
            // 移除所有活动状态
            document.querySelectorAll('.tab-button').forEach(btn => btn.classList.remove('active'));
            document.querySelectorAll('.tab-content').forEach(content => content.classList.remove('active'));
            
            // 添加活动状态
            document.querySelector(`[onclick="switchTab('${tabName}')"]`).classList.add('active');
            document.getElementById(tabName + 'Tab').classList.add('active');
        }

        // 下载表单处理
        document.getElementById('downloadForm').addEventListener('submit', function(e) {
            const button = document.getElementById('submitBtn');
            const loading = document.getElementById('loading');
            const btnText = document.getElementById('btnText');
            
            // 显示加载状态
            button.disabled = true;
            btnText.textContent = '下载中...';
            loading.style.display = 'block';
        });

        // 上传表单处理
        document.getElementById('uploadForm').addEventListener('submit', function(e) {
            const button = document.getElementById('uploadBtn');
            const loading = document.getElementById('uploadLoading');
            const btnText = document.getElementById('uploadBtnText');
            
            // 显示加载状态
            button.disabled = true;
            btnText.textContent = '上传中...';
            loading.style.display = 'block';
        });

        // 文件选择处理
        document.getElementById('file').addEventListener('change', function(e) {
            const wrapper = this.closest('.file-input-wrapper');
            const label = document.getElementById('file-label-text');
            
            if (e.target.files.length > 0) {
                const fileName = e.target.files[0].name;
                label.textContent = `已选择: ${fileName}`;
                wrapper.classList.add('has-file');
            } else {
                label.textContent = '点击选择文件或拖拽文件到此处';
                wrapper.classList.remove('has-file');
            }
        });

        // 拖拽上传功能
        const fileInputWrapper = document.querySelector('.file-input-wrapper');
        const fileInput = document.getElementById('file');

        ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
            fileInputWrapper.addEventListener(eventName, preventDefaults, false);
        });

        function preventDefaults(e) {
            e.preventDefault();
            e.stopPropagation();
        }

        ['dragenter', 'dragover'].forEach(eventName => {
            fileInputWrapper.addEventListener(eventName, highlight, false);
        });

        ['dragleave', 'drop'].forEach(eventName => {
            fileInputWrapper.addEventListener(eventName, unhighlight, false);
        });

        function highlight(e) {
            fileInputWrapper.classList.add('dragover');
        }

        function unhighlight(e) {
            fileInputWrapper.classList.remove('dragover');
        }

        fileInputWrapper.addEventListener('drop', handleDrop, false);

        function handleDrop(e) {
            const dt = e.dataTransfer;
            const files = dt.files;
            
            if (files.length > 0) {
                fileInput.files = files;
                // 触发 change 事件
                fileInput.dispatchEvent(new Event('change'));
            }
        }

        // 输入框焦点效果
        document.getElementById('url').addEventListener('focus', function() {
            this.style.transform = 'scale(1.02)';
        });

        document.getElementById('url').addEventListener('blur', function() {
            this.style.transform = 'scale(1)';
        });

        // 页面加载时检查是否有上传结果，如果有则切换到上传选项卡
        window.addEventListener('load', function() {
            <?php if (isset($_FILES['file'])): ?>
                switchTab('upload');
            <?php endif; ?>
        });
    </script>
</body>
</html>