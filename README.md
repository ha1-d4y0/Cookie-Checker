[README.md](https://github.com/user-attachments/files/34736591/README.md)
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

## ファイル名の形式

`国_プラン_UUID.txt`

例：`JP_Premium_a1b2c3d4e5f6.txt`

## インストール

以下のコマンドを実行して、必要なライブラリをインストールしてください。

```bash
pip install -r requirements.txt
```
