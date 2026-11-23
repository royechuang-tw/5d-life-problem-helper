# 5D 生活問題小幫手（5D Life Problem Helper）

專為**家庭親子溝通、國小與國中生活教育**設計的結構化問題解決引導工具。將業界經典的「5D 問題解決法」與「5W2H / 5 Why 思考法」轉化為親和、白話的五步驟對話引導，協助孩子與家長、師長共同釐清事實、平復當下狀況、探索深層原因、提出補償改善並訂立共同生活公約。

---

## 一、 核心特色

1. **100% 離線可用，零後端依賴**：
   * 內建本機啟發式語意萃取引擎，無須連網、無須設定 API Key，下載後直接以瀏覽器開啟 `index.html` 即可完整使用。
   * 支援直接部署於 **GitHub Pages** 或任何靜態網頁伺服器。
2. **拒絕腦補，真實萃取與貼心追問引導**：
   * 系統僅忠實萃取使用者輸入的客觀事實（人、事、時、地、物與影響），絕不自行編造未提及的細節。
   * 自動診斷缺漏資訊，針對 **8 大常見生活領域**（3C 作息、外出晚歸、學業誠信、物品借用界限、手足同儕衝突、金錢消費自律、家務環境衛生、飲食與交通安全）提供專屬引導提問與一鍵參考建議。
3. **第一步即時看板回饋**：
   * 在「1. 輸入事件與小幫手」頁面內建即時 5D 摘要看板，每回答一題或點選一項建議，上方看板與頂部完整度徽章皆會立即更新並標示「剛更新」。
4. **一鍵匯出標準 Word 報告（`.doc`）與 16:9 寬螢幕簡報（`.pptx`）**：
   * 內建原生 MSO Word 排版引擎與本機 `PptxGenJS` 簡報產生器，一鍵產出適合家庭張貼、班級輔導或列印簽認的正式報告與投影片。
5. **隱私與資安防護設計（Privacy & Security by Design）**：
   * **本機儲存**：所有填寫內容僅保存在使用者自身瀏覽器的 `localStorage`，絕不傳送至任何外部伺服器。
   * **資安強化**：全站實作 `Content-Security-Policy (CSP)`、`escapeHtml()` 防 XSS 轉義、原型鏈污染（Prototype Pollution）攔截、深度 JSON 結構防禦校驗與匯出檔名安全過濾。

---

## 二、 5D 思考法五步驟架構

| 步驟代號 | 生活化步驟名稱 | 核心思考目標 |
| :--- | :--- | :--- |
| **D1** | **發生什麼事（問題定義 5W2H）** | 客觀釐清誰（Who）、何時（When）、何地（Where）、做了什麼（What）、違反什麼約定（Why）、如何發現（How）與造成的影響。 |
| **D2** | **緊急怎麼做（當下應變處置）** | 事發第一時間採取了什麼緊急處理，先讓現場安全、物品歸還或雙方情緒冷靜下來。 |
| **D3** | **為什麼會這樣（深入找原因 5 Why）** | 不貼「不乖」標籤，透過連問「為什麼」找出行為背後真實的心態動機與環境規矩漏洞。 |
| **D4** | **以後怎麼改善（好方法與補償）** | 提出誠懇道歉、實質補償或勞動服務，並調整具體的生活習慣與環境提醒機制。 |
| **D5** | **訂立生活約定（生活公約與見證）** | 將改善做法轉化為全家或班級共同遵守的生活公約，由家長或師長見證確認。 |

---

## 三、 快速開始（Quick Start）

### 方式 A：直接使用線上網頁版（GitHub Pages）
* **線上網址**：https://royechuang-tw.github.io/5d-life-problem-helper/

### 方式 B：直接離線開啟（免連網）
1. 下載本專案壓縮檔（Download ZIP）並解壓縮，或執行：
   ```bash
   git clone https://github.com/royechuang-tw/5d-life-problem-helper.git
   ```
2. 直接雙擊打開專案根目錄下的 `index.html`（支援 Chrome、Edge、Safari、Firefox 等現代瀏覽器）。

---

## 四、 進階 AI 模型設定說明（選填）

本工具預設使用「**本機內建語意解析引擎（100% 離線免連網）**」。若您希望串接大型語言模型進行輔助拆解，可點擊介面上的「進階 AI 設定（選填）」切換：

1. **Google Gemini API**：
   * 需輸入您個人的 Gemini API Key。
   * **隱私安全提醒**：API Key 僅在當前網頁記憶體中透過 `x-goog-api-key` HTTP Header 直連 Google 官方 API（`generativelanguage.googleapis.com`），系統**不會**將您的 API Key 存入 `localStorage`。若在學校或公用電腦使用，請勿勾選瀏覽器的「記住密碼」功能。
2. **本機 Ollama 離線伺服器（`http://localhost:11434`）**：
   * 需先於您的電腦安裝並啟動 [Ollama](https://ollama.com/)（例如執行 `ollama run qwen2.5`）。
   * **CORS 跨域提醒**：若您是透過 GitHub Pages 等公開 HTTPS 網址開啟本工具並連線本機 Ollama，請先在本機設定環境變數 `OLLAMA_ORIGINS="*"` 後再啟動 Ollama，以允許瀏覽器跨域連線。

---

## 五、 專案目錄結構

```text
├── index.html              # 主應用程式介面（含 CSP 安全標頭與 7 步極簡分頁）
├── css/
│   └── style.css           # 明亮模式（Light Mode）響應式與列印排版樣式表
├── js/
│   └── app.js              # 核心邏輯（離線語意解析、小幫手追問、評分檢核、Word/PPT 匯出）
├── data/
│   ├── sample-data.js      # 內建生活案例唯一資料來源（小豬弟弟拿玩偶事件）
│   └── sample-life-5d.json # 生活案例 JSON 結構參考範本
├── libs/
│   ├── jszip.min.js        # 本機離線 ZIP 打包依賴庫（MIT License）
│   └── pptxgen.min.js      # 本機離線 PowerPoint (.pptx) 產生引擎（MIT License）
├── walkthrough.md          # 系統架構演進、100 案例壓力測試與資安審計紀錄
├── LICENSE                 # MIT 開源授權條款與第三方套件聲明
└── README.md               # 專案說明文件
```

---

## 六、 開源授權（License）

本專案採用 **MIT License** 授權開源，詳見 [LICENSE](./LICENSE) 檔案。
