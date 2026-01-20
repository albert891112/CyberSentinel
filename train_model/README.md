# Lexical Model Training - Docker

可移植的惡意 URL 偵測模型訓練容器，支援每日自動重新訓練。

## 功能特點

- **自動資料載入**: 
  - PhishTank: 直接從 `http://data.staging.phishtank.com/data/online-valid.csv` 取得
  - Kaggle: 使用 kagglehub 載入 `moutasmtamimi/malicious-url-detection-dataset-enhanced-2026`
  - Tranco: 自動下載 Top 1M 良性網域
- **定時訓練**: 每日 00:00 自動執行重新訓練
- **獨立部署**: 可輕鬆移植到其他專案

## 快速開始

### 1. 設定環境變數

創建 `.env` 檔案 (Kaggle 憑證為必要):

```env
# Kaggle 憑證 (必要)
KAGGLE_USERNAME=your_kaggle_username
KAGGLE_KEY=your_kaggle_api_key

# 啟動時立即執行訓練 (預設: true)
RUN_IMMEDIATELY=true
```

> **取得 Kaggle API Key**: 前往 [Kaggle Account](https://www.kaggle.com/settings/account) → Create New Token

### 2. 啟動容器

```bash
docker compose up -d
```

### 3. 查看訓練日誌

```bash
docker compose logs -f train_model
```

## 檔案結構

```
train_model/
├── train_lexical_model.py   # 主訓練腳本
├── features.py              # 特徵提取模組
├── ngram_features.py        # N-gram 特徵模組
├── compose.yml              # Docker Compose 設定
├── Dockerfile               # 容器建置設定
├── pyproject.toml           # Python 依賴 (使用 uv)
├── README.md                # 說明文件
└── models/                  # 訓練完成的模型 (自動產生)
    ├── lexical_rf.pkl
    └── trigram_extractor.pkl
```

## 環境變數

| 變數名稱 | 說明 | 必要 |
|---------|------|------|
| `KAGGLE_USERNAME` | Kaggle 使用者名稱 | ✓ |
| `KAGGLE_KEY` | Kaggle API Key | ✓ |
| `RUN_IMMEDIATELY` | 啟動時立即訓練 | 預設 `true` |
| `TZ` | 時區 | 預設 `Asia/Taipei` |

## 資料來源

| 來源 | 類型 | 說明 |
|------|------|------|
| PhishTank | 惡意 | 自動從公開 API 取得 |
| Kaggle | 混合 | 使用 kagglehub 載入 |
| Tranco | 良性 | Top 1M 網域清單 |

## 注意事項

- 模型檔案會儲存在 `./models/` 目錄，透過 volume 掛載持久化
- **必須**設定 Kaggle 憑證才能載入 Kaggle 資料集
- PhishTank 和 Tranco 資料會自動從公開來源下載
