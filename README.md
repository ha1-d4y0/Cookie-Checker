# ストリーミングCookieチェッカー

主要な動画配信サービスのNetscape形式のCookieファイル（`.txt`）を検査するツールです。

## 対応サービス

| オプション | サービス |
|---|---|
| `-s auto` | 自動検出（デフォルト） |
| `-s netflix` | Netflix |
| `-s disney` | Disney+ |
| `-s prime` | Prime Video |
| `-s dazn` | DAZN |
| `-s hulu` | Hulu |
| `-s paramount` | Paramount+ |

## 主な機能

- Cookieの状態判定（有効・無効・ブロック・エラー）
- 国・契約プランの検出
- Cookieの有効期限の表示
- 重複Cookieの削除
- `--delay` オプションによる処理間隔の調整
- 保存ファイルにはCookieの行のみを記録
- ファイル名の自動生成
- **1ファイルに複数のCookieセットが含まれる場合、自動で分離して1ファイル1Cookieとして処理・出力**
  （空白行またはコメント行で区切られたセットを個別に扱います）

## ファイル名の形式

`国_プラン_UUID.txt`

例：`JP_Premium_a1b2c3d4e5f6.txt`

## インストール

以下のコマンドを実行して、必要なライブラリをインストールしてください。

```bash
pip install -r requirements.txt
```