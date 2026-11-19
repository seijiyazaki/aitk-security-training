# AITK Security Training

Splunk AI Toolkit（AITK、旧 Machine Learning Toolkit）を、セキュリティの題材で手を動かしながら学ぶための Splunk アプリです（app id: `aitk_security_training`）。Splunk4Rookies / Splunk4Ninjas の機械学習ワークショップの内容を、1ステップずつサーチを実行して確かめるダッシュボードにしました。

## コース

| メニュー | 中身 |
|---|---|
| Summary | アプリの使い方とコースの一覧 |
| AITK Security for Primer | 機械学習の基礎。シナリオ1（ユーザーアクセスの外れ値、DensityFunction）、シナリオ2（ログイン数の異常）、シナリオ3（CPU 使用率の予測、StateSpaceForecast）、シナリオ4（ネットワークテレメトリの外れ値） |
| AITK Security for Rookies | 演習1（ユーザーの振る舞いの外れ値、MAD）、演習2（マルウェア通信の予測、LogisticRegression / RandomForest）、演習3（ML を Enterprise Security で運用） |
| AITK Security for Ninja | Lab1〜Lab4（パスワードスプレー、資格情報の利用、User-Agent の外れ値と TF-IDF / KMeans、`\| ai` コマンドで LLM による説明） |
| アルゴリズム | 外れ値・予測・分類のアルゴリズムと、AITK Experiments の画面との対応 |

各ステップでは、次のものを表示します。
- 説明と資料の図
- 実行ボタン、SPL、SPL を1行ずつ説明した表
- 結果と確認ポイント
- GUI（Experiments）での同じ操作の手順

## 動作環境

検証した環境は次のとおりです。
- Splunk Enterprise 10.6
- Splunk AI Toolkit 6.1.0
- Python for Scientific Computing 4.3.5

データ:
- **Primer**: BOTS v2（`index=botsv2`）と AITK のサンプル lookup を使います
- **Rookies**: 同梱の lookup（`logins.csv`、`firewall_traffic.csv`）を使います。演習3には Enterprise Security 8.x が必要です
- **Ninja**: ワークショップの `s4n` データを `index=main` に入れて使う前提です。Lab4 は同梱の `http_error_dataset.csv` と、AITK の Connections に登録した LLM を使います

## インストール

[Releases](../../releases) から `aitk_security_training-<version>.spl` をダウンロードし、Splunk Web の「Apps → Manage Apps → Install app from file」で入れます。

## ソースからビルド

```bash
cd _build
python3 build_app.py
```

- `_build/build_app.py` が、ビュー、ナビ、`app.conf`、CSS、画像、lookup をすべて生成し、`aitk_security_training-<VERSION>.spl` を作ります。
- 画面を変えるときは、生成された `aitk_security_training/` は直接編集しないでください。`build_app.py` を直し、`VERSION` を上げてからビルドします。
- 静的ファイルのキャッシュを切り替える build 番号は、`VERSION` から自動で決まります。

| パス | 中身 |
|---|---|
| `_build/build_app.py` | アプリの生成スクリプト（各ステップの定義もここ） |
| `_build/aitk.css` | 共通のスタイル |
| `_build/web/` | ダッシュボードで使う画像と SVG の図 |
| `_build/img/` | Primer 資料から取り出した元画像 |
| `_build/lookups/` | 同梱する lookup |
| `_build/appicon/` | アプリのアイコン（`make_icon.py` で生成） |
