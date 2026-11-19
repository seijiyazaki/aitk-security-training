#!/usr/bin/env python3
"""Generate the aitk_security_training Splunk app from the lesson definitions below."""
import datetime, html, os, shutil, tarfile, textwrap, urllib.parse
from xml.sax.saxutils import escape as xesc

HERE = os.path.dirname(os.path.abspath(__file__))
APP = "aitk_security_training"
OUT = os.path.join(os.path.dirname(HERE), APP)
STATIC = f"/static/app/{APP}"
VERSION = "1.3.9"
BUILD = int("".join(f"{int(x):02d}" for x in VERSION.split(".")))  # bump static cache with every version

# BOTS v2 covers 2017-08-01..2017-09-01 (UTC)
AUG1, AUG22, AUG28, SEP2 = 1501545600, 1503360000, 1503878400, 1504310400


def img(name, cls="aitk-shot"):
    return f'<img class="{cls}" src="{STATIC}/img/{name}"/>'


def fmt_day(epoch):
    d = datetime.datetime.fromtimestamp(epoch, datetime.timezone.utc)
    return f"{d.year}/{d.month}/{d.day}"


def spl_block(spl):
    return f'<pre class="aitk-spl">{html.escape(spl.strip(), quote=False)}</pre>'


def ul(items, cls=""):
    c = f' class="{cls}"' if cls else ""
    return f"<ul{c}>" + "".join(f"<li>{i}</li>" for i in items) + "</ul>"


# ---------------------------------------------------------------- panels
def chart_opts(kind, overlay=None):
    o = {
        "charting.chart": "line",
        "charting.legend.placement": "right",
        "charting.axisTitleX.visibility": "collapsed",
        "charting.chart.nullValueMode": "gaps",
    }
    if overlay:
        o["charting.chart.overlayFields"] = overlay
        o["charting.axisY2.enabled"] = "1"
        o["charting.axisY2.scale"] = "linear"
    return "".join(f'<option name="{k}">{xesc(v)}</option>' for k, v in o.items())


def search_xml(spl, tok, earliest, latest, sid=None):
    idattr = f' id="{sid}"' if sid else ""
    return (f'<search{idattr} depends="${tok}$"><query>{xesc(spl.strip())}</query>'
            f"<earliest>{earliest}</earliest><latest>{latest}</latest></search>")


def viz_xml(kind, search, title="", overlay=None, height=320):
    t = f"<title>{xesc(title)}</title>" if title else ""
    if kind == "line":
        return f'<chart>{t}{search}{chart_opts(kind, overlay)}<option name="height">{height}</option></chart>'
    if kind == "line_outlier":
        colors = '{"value": 0x5B8FB9, "outlier_value": 0xE4572E}'
        return (f'<chart>{t}{search}{chart_opts("line")}'
                f'<option name="charting.fieldColors">{xesc(colors)}</option>'
                f'<option name="charting.lineWidth">2</option><option name="height">{height}</option></chart>')
    if kind == "outliers":
        return (f'<viz type="Splunk_ML_Toolkit.OutliersViz">{t}{search}'
                f'<option name="height">{height}</option></viz>')
    if kind in ("table", "table_long", "table_wrap"):
        cnt = 40 if kind == "table_long" else 10
        wrap = "true" if kind == "table_wrap" else "false"
        return (f'<table>{t}{search}<option name="count">{cnt}</option>'
                f'<option name="drilldown">none</option><option name="wrap">{wrap}</option></table>')
    if kind == "events":
        return (f'<event>{t}{search}<option name="count">5</option>'
                f'<option name="list.drilldown">none</option><option name="type">list</option></event>')
    raise ValueError(kind)


def step_rows(s):
    """Row 1: explanation (+ reference screenshots). Row 2: run button and results."""
    tok = "run_" + s["id"].replace("-", "_")
    head = (f'<div class="aitk-step"><div class="aitk-step-head">'
            f'<span class="aitk-tag">{s["tag"]}</span><h2>{s["title"]}</h2>'
            f'</div>'
            + "".join(f"<p>{p}</p>" for p in s["body"])
            + s.get("extra_html", "")
            + (f'<div class="aitk-check"><h4>結果で確かめること</h4>{ul(s["checks"])}</div>' if s.get("checks") else "")
            + (f'<p class="aitk-note">{s["note"]}</p>' if s.get("note") else "")
            + "</div>")
    ref = ""
    if s.get("refs"):
        ref = ('<panel depends="$show_ref$"><title>資料の画面（参考）</title><html><div class="aitk-refs">'
               + "".join(img(r) for r in s["refs"]) + "</div></html></panel>")
    row1 = f"<row><panel><html>{head}</html></panel>{ref}</row>"
    if "spl" not in s:  # GUI-only step: explanation and screenshots, nothing to run
        return [divider(s["tag"]), row1]

    btn = (f'<input type="link" token="{tok}" searchWhenChanged="true"><label></label>'
           f'<choice value="1">▶ {s["tag"]} を実行</choice></input>')
    views = s["views"]
    els = []
    if len(views) == 1:
        v = views[0]
        els.append(viz_xml(v[0], search_xml(s["spl"], tok, s["earliest"], s["latest"]), v[1],
                           overlay=v[2] if len(v) > 2 else None))
    else:
        sid = "base_" + tok
        s["_base"] = search_xml(s["spl"], tok, s["earliest"], s["latest"], sid=sid)
        for v in views:
            post = v[3] if len(v) > 3 else "| fields *"
            srch = f'<search base="{sid}"><query>{xesc(post)}</query></search>'
            els.append(viz_xml(v[0], srch, v[1], overlay=v[2] if len(v) > 2 else None))
    els = [e.replace(">", f' depends="${tok}$">', 1) for e in els]
    rng = s.get("range_note") or (f'{fmt_day(s["earliest"])} 〜 {fmt_day(s["latest"] - 86400)}' if isinstance(s["earliest"], int)
           else "指定なし（inputlookup は時間範囲に関係なく 2014/4/1〜4/14 の全データを読む）")
    q = urllib.parse.urlencode({"q": s["spl"].strip() if s["spl"].lstrip().startswith("|") else "search " + s["spl"].strip(),
                                "earliest": s["earliest"], "latest": s["latest"]})
    extra_open = "".join(f'<a class="aitk-open" target="_blank" href="../{app}/search?{html.escape(q)}">{lbl} ↗</a>'
                         for app, lbl in s.get("open_apps", []))
    spl_html = ('<html><div class="aitk-run">'
                f'<div class="aitk-run-head"><b>実行するサーチ</b><span>時間範囲: {rng}</span>'
                f'<a class="aitk-open" target="_blank" href="search?{html.escape(q)}">Search で開く ↗</a>{extra_open}</div>'
                f'{spl_block(s["spl"])}'
                f'{explain_block(s["id"])}'
                f'<p class="aitk-hint">「▶ {s["tag"]} を実行」を押すと、このサーチが走って下に結果が出ます。</p>'
                '</div></html>')
    nxt = ""
    if s.get("next"):
        nxt_spl, nxt_els, nxt_btn = "", "", ""
        if s.get("next_spl"):  # runnable follow-up search inside the Next Action box
            ntok = tok + "_next"
            nq = urllib.parse.urlencode({"q": "search " + s["next_spl"].strip(),
                                         "earliest": s["earliest"], "latest": s["latest"]})
            nxt_spl = ('<div class="aitk-run-head"><b>続けて実行するサーチ</b><span>時間範囲: ' + rng + '</span>'
                       f'<a class="aitk-open" target="_blank" href="search?{html.escape(nq)}">Search で開く ↗</a></div>'
                       + spl_block(s["next_spl"]) + explain_block(s["id"] + "n")
                       + '<p class="aitk-hint">下の「▶ Next Action のサーチを実行」を押すと結果が出ます。</p>')
            nxt_btn = (f'<input type="link" token="{ntok}" searchWhenChanged="true"><label></label>'
                       '<choice value="1">▶ Next Action のサーチを実行</choice></input>')
            nxt_els = viz_xml(s.get("next_view", "table_long"),
                              search_xml(s["next_spl"], ntok, s["earliest"], s["latest"]),
                              s.get("next_title", "")).replace(">", f' depends="${ntok}$">', 1)
        nxt = (f'<html><div class="aitk-nextaction"><h4>Next Action</h4>{s["next"]}{nxt_spl}</div></html>')
        row2 = f'<row><panel>{btn}{spl_html}{"".join(els)}{nxt}</panel></row>'
        if nxt_btn:
            row2 += f'<row><panel>{nxt_btn}{nxt_els}</panel></row>'
        return [divider(s["tag"]), row1, row2]
    row2 = f'<row><panel>{btn}{spl_html}{"".join(els)}</panel></row>'
    return [divider(s["tag"]), row1, row2]


def divider(label=None):
    """Full-width separator row placed before each block."""
    if label:
        inner = (f'<div class="aitk-divider aitk-divider-step" style="border-top:6px solid #1565c0;margin:18px 0 6px;">'
                 f'<span style="display:inline-block;background:#1565c0;color:#ffffff;font-size:14px;font-weight:700;'
                 f'padding:5px 16px;border-radius:0 0 4px 0;">{label}</span></div>')
    else:
        inner = '<div class="aitk-divider" style="border-top:3px solid #1b2a33;margin:10px 0 2px;"></div>'
    return f"<row><panel><html>{inner}</html></panel></row>"


def text_row(inner, cls="aitk-step"):
    return f'<row><panel><html><div class="{cls}">{inner}</div></html></panel></row>'


def gui_panel(title, algo, intro, stages, mapping, after, extra=""):
    """GUI walkthrough (AI Toolkit Experiments) with SPL-to-GUI parameter mapping."""
    st = "".join(f'<tr><td><b>{a}</b></td><td>{b}</td></tr>' for a, b in stages)
    mp = "".join(f'<tr><td><code>{html.escape(a, quote=False)}</code></td><td>{b}</td><td>{c}</td></tr>' for a, b, c in mapping)
    return text_row(
        f'<div class="aitk-step-head"><span class="aitk-tag aitk-tag-gui" style="background:#7b3fa0;">GUI</span><h2>{title}</h2></div>'
        f'<p>{intro}</p>'
        f'<p><a class="aitk-open" target="_blank" href="../Splunk_ML_Toolkit/experiments">AI Toolkit の Experiments を開く ↗</a></p>'
        '<h4 style="margin:14px 0 4px;">手順</h4>'
        f'<table class="aitk-table"><tbody>{st}</tbody></table>'
        f'<h4 style="margin:14px 0 4px;">SPL のパラメータと GUI の項目の対応（{algo}）</h4>'
        '<table class="aitk-table"><thead><tr><th>SPL</th><th>GUI の項目</th><th>この演習で入れる値</th></tr></thead>'
        f'<tbody>{mp}</tbody></table>'
        + extra +
        f'<p class="aitk-note">{after}</p>')


def gui_fit_apply_table(field, split):
    rows = [
        ("Define で検索を実行", "貼り付けた SPL", "学習に使う入力データを作るだけ。まだ fit はしていない"),
        ("Learn の <b>Detect Outliers</b> ボタン",
         f"<code>| fit DensityFunction {field} by {split} dist=auto threshold=0.01 show_density=true show_options=\"feature_variables,split_by,params\" into _exp_draft_&lt;ID&gt;</code>",
         "<b>ここが fit</b>。下書きのモデル <code>_exp_draft_&lt;ID&gt;</code> が AI Toolkit アプリの自分の領域に保存される（ID は Experiment ごとの英数字）"),
        ("Evaluate タブでしきい値を変えて <b>適用</b>", "保存済みモデルの apply（しきい値だけ変える）", "<b>ここが apply</b>。再学習せずに、外れ値の判定だけをやり直す"),
        ("左の Outlier tolerance threshold を変えて Detect Outliers", "fit をもう一度", "再学習する。Keep Original Threshold／Update Threshold のダイアログが出たら、Update は再学習"),
        ("右上の <b>保存</b>（Save）", "―", "Experiment を保存する。モデルは下書きでなくなり <code>_exp_&lt;ID&gt;</code> の名前になる"),
        ("Operationalize の <b>Publish</b>", "―", "モデルを好きな名前で別のアプリにコピーする。SPL の <code>| apply &lt;その名前&gt;</code> で使えるようになる"),
        ("Operationalize の <b>Create Alert</b>", "保存したモデルを使う定期検索", "新しいデータを定期的に判定し、外れ値が出たら通知する（apply の定期実行）"),
        ("Operationalize の <b>Schedule Model Training</b>", "fit の定期実行", "モデルを定期的に学習し直す"),
    ]
    body = "".join(f"<tr><td>{a}</td><td>{b}</td><td>{c}</td></tr>" for a, b, c in rows)
    return ('<h4 style="margin:14px 0 4px;">GUI のどこが fit で、どこが apply か</h4>'
            '<table class="aitk-table"><thead><tr><th>GUI の操作</th><th>裏で動く SPL</th><th>何が起きるか</th></tr></thead>'
            f'<tbody>{body}</tbody></table>'
            '<p class="aitk-note">Detect Outliers が実行した SPL は、Learn 画面右上の <b>SPL</b> ボタンで確かめられます。上の fit の行は、この検証環境で実際に生成された SPL です。</p>')


def outlier_gui(sid, define_spl, field, split, model, apply_step):
    return gui_panel(
        f"{sid} を GUI でやる（Smart Outlier Detection）", "DensityFunction",
        "AI Toolkit の Smart Outlier Detection アシスタントは、裏で DensityFunction の fit を実行します。SPL を書かずに、同じモデルを画面の入力だけで作れます。",
        [("開く", "AI Toolkit アプリ → <b>Experiments</b> で <b>Smart Outlier Detection</b> を選び、右上の <b>Create New Experiment</b> を押して、"
                  f"<b>Experiment Title</b>（例：{model}_gui）を入れて <b>Create</b>"),
         ("Define", f"データソースに <b>Search</b> を選び、次の SPL を貼る。時間範囲は Date Range で 2017/08/01〜2017/09/02 にする（既定の All time のままでも同じ結果）。"
                    f"<b>Data Preview</b> と <b>Visualization</b> に結果が出たら <b>Next</b>{spl_block(define_spl)}"),
         ("Learn", f"<b>Field to analyze</b> に {field}、<b>Split by fields</b> に {split} を選ぶ。"
                   "<b>Distribution type</b> は Auto、<b>Outlier tolerance threshold</b> は 0.01 にして <b>Detect Outliers</b> を押す。"
                   "右上の <b>SPL</b> ボタンで、画面が生成した fit の SPL を見られる。上の Search と同じ形になっているか見比べる"),
         ("Review", "<b>Model Summary</b> で外れ値の数を見る。<b>Distribution Properties</b> と <b>Cardinality Histogram</b> は、"
                    "<code>| summary</code> で見た時間帯ごとの分布をグラフにしたもの（Split by fields を指定したときだけ出る）。よければ <b>Save and Next</b> → <b>Save</b>"),
         ("Operationalize", f"<b>Publish Outlier Models</b> でモデル名（例：{model}_gui）と公開先アプリ（aitk_security_training）を指定して公開する。"
                            f"公開した本人なら、{apply_step} の SPL の <code>apply {model}</code> を <code>apply {model}_gui</code> に変えればそのまま使える。"
                            "<b>Create Alert</b>（外れ値が出たら通知）と <b>Schedule Model Training</b>（定期的な再学習）もこの画面から設定できる")],
        [(f"fit DensityFunction {field}", "Field to analyze", field),
         (f'by "{split}"' if sid.endswith("1-5") else f"by {split}", "Split by fields（最大5つ）", split),
         ("dist=（省略時は auto）", "Distribution type", "Auto"),
         ("threshold=（省略時は 0.01）", "Outlier tolerance threshold", "0.01（分布の端1%を外れ値にする）"),
         (f"into {model}", "Experiment を Save → Publish したときのモデル名", f"{model}_gui"),
         ('eval HourOfDay=strftime(_time,"%H")', "Learn の <b>+Add preprocessing step</b>（時刻から atf_hour_of_day を作る）でも代わりにできる", "今回は Define の SPL で作っているので不要")],
        "Experiment で作ったモデルは、作った人の領域に保存されます。他のアプリの検索から使うには Publish が必要です。Publish は Operationalize 画面のほか、Experiments 一覧の Actions 列からもできます（モデルを学習済みの Experiment だけ）。モデル名に使えるのは英字、数字、アンダースコアだけで、先頭は英字かアンダースコアです。公開したモデルは公開先アプリの<b>公開した人の領域</b>に置かれるので、そのままでは他のユーザーからは見えません。",
        extra=gui_fit_apply_table(field, split))


def breakdown(rows):
    body = "".join(f"<tr><td><code>{html.escape(a, quote=False)}</code></td><td>{b}</td></tr>" for a, b in rows)
    return f'<table class="aitk-table"><thead><tr><th>Splunk サーチ</th><th>説明</th></tr></thead><tbody>{body}</tbody></table>'


def scenario_form(label, intro_html, items):
    parts, bases = [], []
    for it in items:
        if isinstance(it, dict):
            parts.extend(step_rows(it))
            if it.get("_base"):
                bases.append(it["_base"])
        else:
            parts.extend([divider(), it])
    fieldset = ('<fieldset submitButton="false" autoRun="true">'
                '<input type="checkbox" token="show_ref"><label>表示</label>'
                '<choice value="1">資料の画面キャプチャを横に並べる</choice><default>1</default></input></fieldset>')
    return (f'<form version="1.1" theme="light" stylesheet="aitk.css" hideEdit="false">'
            f"<label>{xesc(label)}</label>{''.join(bases)}{fieldset}"
            + text_row(intro_html, "aitk-hero") + "".join(parts) + "</form>")


def html_dashboard(label, inner):
    return (f'<dashboard version="1.1" theme="light" stylesheet="aitk.css" hideEdit="true">'
            f"<label>{xesc(label)}</label><row><panel><html>{inner}</html></panel></row></dashboard>")


# ---------------------------------------------------------------- SPL の読み方（ステップごと）
TSTATS_4625 = ('| tstats count WHERE index=botsv2 source="wineventlog:security" TERM(EventCode=4625) BY _time span=1h',
               "生イベントを読まずに、インデックスのメタデータ（.tsidx）から1時間ごとのログオン失敗（4625）件数を数える。"
               "先頭が <code>|</code> なのは、tstats がイベントを自分で生み出す生成コマンドだから")
HOUR = ('| eval HourOfDay=strftime(_time,"%H")',
        "_time から「時」だけを取り出し、\"00\"〜\"23\" の文字列にして HourOfDay に入れる。時はユーザー設定のタイムゾーンで計算される")
BOUNDS = ("| eval lower_bound=avg-2*stdev, upper_bound=avg+2*stdev",
          "平均から標準偏差2つ分を引いた値を下限、足した値を上限にする。2 を 3 にすれば外れ値と判定される点が減り、1.5 にすれば増える")
EXPLAIN = {
    "1-1": [
        ('index=botsv2 source="wineventlog:security"', "BOTS v2 の Windows セキュリティイベントログに絞る"),
        ("(EventCode=4625 OR EventCode=4624)", "4624 はログオン成功、4625 はログオン失敗。この2種類だけを残す"),
        ("| timechart span=1h count by EventCode", "1時間ごとに件数を数え、EventCode ごとに別の列（4624 と 4625）にする。_time が X 軸になる"),
    ],
    "1-3": [
        TSTATS_4625,
        ("| eventstats avg(count) as avg stdev(count) as stdev",
         "全期間の全行の count から平均（avg）と標準偏差（stdev）を求め、<b>全行に同じ値を付け足す</b>。stats と違って行がまとまらないので、各行の count と比べられる"),
        BOUNDS,
        ("| eval outlier=if(count<lower_bound OR count>upper_bound,1,0)", "count が下限より小さいか上限より大きければ 1、範囲内なら 0。ただし次の table で落とすので、チャートには使われない（Statistics で確かめる用）"),
        ("| table _time count lower_bound upper_bound",
         "Outliers Chart が読む順（時刻、値、下限、上限）に列を並べる。チャートは値と上下限を比べて外れ値の点を自分で描く"),
    ],
    "1-4": [
        TSTATS_4625, HOUR,
        ("| eventstats avg(count) as avg stdev(count) as stdev by HourOfDay",
         "<code>by HourOfDay</code> を付けたので、平均と標準偏差を時間帯ごとに別々に計算する。たとえば 03 時の行には、期間中の各日の 03 時台だけから求めた値が入る"),
        BOUNDS,
        ("| eval outlier=if(count<lower_bound OR count>upper_bound,1,0)", "Search 1-3 と同じ。範囲外なら 1。この列も次の table で落とす"),
        ("| table _time count lower_bound upper_bound", "Outliers Chart 用に列を並べる"),
    ],
    "1-5": [
        TSTATS_4625, HOUR,
        ('| fit DensityFunction count by "HourOfDay" into botsv2_df_logon',
         "count の分布（確率密度）を時間帯ごとに推定する。分布の端の、起きる確率がごく低い範囲（既定では全体の1%）に入った点を外れ値として "
         "<code>IsOutlier(count)</code>=1 にする。<code>into</code> で学習結果をモデルとして保存する"),
    ],
    "1-5m": [
        ("| listmodels", "いまのアプリから見える AI Toolkit のモデルを一覧する生成コマンド。他のアプリで作って共有していないモデルは出てこない"),
        ("| search name=botsv2_df_logon", "Search 1-5 で保存したモデルだけに絞る。この行を消せば全モデルが見える"),
        ("| spath input=options", "options 列の JSON を展開して、項目ごとの列にする。入れ子は <code>mlspl_limits.max_inputs</code> のようにドットでつながり、配列は <code>split_by{}</code> のように {} が付く"),
        ("| fields - options session_key", "展開済みの元の JSON と、学習時に記録された Splunk のセッションキーを消す。セッションキーは認証情報なので、画面や共有する結果に出さない"),
        ('| table … | rename name as "モデル名" …', "「主な設定」の表だけに付けている後処理。よく見る項目を選んで、日本語の列名に変える"),
        ('| transpose 0 column_name="設定項目" | rename "row 1" as "値"', "「すべての設定」の表だけに付けている後処理。1行のモデルを縦に倒し、項目名と値の2列にする。0 は全列を対象にする指定"),
    ],
    "1-5s": [
        ("| summary botsv2_df_logon", "モデルを読み込んで、学習した内容を表にする生成コマンド。データは検索しないので、時間範囲は関係ない。モデル名を変えれば他のモデル（Search 3-4 の予測モデルなど）も見られる"),
    ],
    "1-6": [
        TSTATS_4625, HOUR,
        ("| apply botsv2_df_logon",
         "保存したモデルの分布を使って判定だけを行う。apply では再学習しないので、新しいデータに毎回同じ基準を当てられる。スケジュール検索に向いている"),
        ('| fields _time count "IsOutlier(count)"',
         "下段のグラフ用だけに付けている絞り込み。列名に括弧が入るのでダブルクォートで囲む"),
    ],
    "1-6c": [
        TSTATS_4625, HOUR,
        ("| apply botsv2_df_logon", "Search 1-6 と同じ。BoundaryRanges 列も一緒に出る"),
        ('| eval lower_bound=tonumber(mvindex(split(mvindex(BoundaryRanges,0),":"),1))',
         "BoundaryRanges の1つ目（<code>-Infinity:22:0</code> のような下側の範囲）を <code>:</code> で区切り、2番目の値（範囲の終わり＝下限）を数値にする。mvindex は0から数える"),
        ('upper_bound=tonumber(mvindex(split(mvindex(BoundaryRanges,-1),":"),0))',
         "最後の範囲（<code>29.4474:Infinity:0.0102</code> のような上側の範囲）の1番目の値（範囲の始まり＝上限）を取り出す。-1 は最後の要素"),
        ("| table _time count lower_bound upper_bound", "Outliers Chart が読む順に列を並べる"),
    ],
    "1-6x": [
        TSTATS_4625, HOUR,
        ("| eventstats avg(count) as g_avg stdev(count) as g_sd", "全期間の平均と標準偏差（Search 1-3 と同じ）"),
        ("| eval global_2sigma=if(…,1,0)", "全体の平均±2σの外なら 1"),
        ("| eventstats avg(count) as h_avg stdev(count) as h_sd by HourOfDay", "時間帯ごとの平均と標準偏差（Search 1-4 と同じ）"),
        ("| eval hourly_2sigma=if(…,1,0)", "時間帯ごとの平均±2σの外なら 1"),
        ("| apply botsv2_df_logon | eval density='IsOutlier(count)'", "DensityFunction の判定を density 列に入れる。括弧付きの列名は eval の中ではシングルクォートで囲む"),
        ("| stats sum(…) as \"…\"", "1 の数を足して、方法ごとの外れ値の数にする。<code>sum(eval(if(…)))</code> は条件に合う行だけを数える書き方"),
    ],
    "2-1": [
        ("| inputlookup numenta_art_daily_flatmiddle.csv", "ルックアップファイルを読み込む生成コマンド。時間範囲の指定は効かない"),
        ('| eval _time=strptime(timestamp,"%Y-%m-%d %H:%M:%S")', "文字列の timestamp を時刻に変換して _time にする。これで時系列のグラフや時間帯の計算ができる"),
        ('HourOfDay=strftime(_time,"%H")', "_time から時（00〜23）を取り出す。Search 2-2 以降の by で使う"),
        ("| table _time value", "グラフに使う2列だけにする。timechart を使わないので、空の時間枠が作られない"),
    ],
    "2-2": [
        ("| inputlookup … | eval _time=…, HourOfDay=…", "Search 2-1 と同じ"),
        ("| fit DensityFunction value by HourOfDay", "時間帯ごとに value の分布を推定し、確率の低い範囲に入った点を IsOutlier(value)=1 にする。into を付けていないのでモデルは保存しない"),
        ("| eval outlier_value=if('IsOutlier(value)'=1, value, null())", "外れ値の点だけ value をコピーし、それ以外は null にする。null の点は線が描かれないので、外れ値の区間だけが別の色の線になる"),
        ("| table _time value outlier_value", "折れ線グラフに2本の線（青＝value、赤＝outlier_value）として出す"),
    ],
    "2-3": [
        ("| inputlookup … | eval _time=…, HourOfDay=…", "Search 2-1 と同じ"),
        ("| fit DensityFunction value by HourOfDay dist=norm", "分布を正規分布に固定する。これで各行の BoundaryRanges が「−Infinity:下限:…」と「上限:Infinity:…」の2つにそろう"),
        ('| eval lower_bound=tonumber(mvindex(split(mvindex(BoundaryRanges,0),":"),1))', "1つ目の範囲の終わり＝下限を取り出す（シナリオ1の Search 1-6 補足と同じ書き方）"),
        ('upper_bound=tonumber(mvindex(split(mvindex(BoundaryRanges,-1),":"),0))', "最後の範囲の始まり＝上限を取り出す"),
        ("| table _time value lower_bound upper_bound", "Outliers Chart が読む順（時刻、値、下限、上限）に並べる。チャートは値が帯の外にある点を外れ値として描く"),
    ],
    "2-4": [
        ("| fit DensityFunction value by HourOfDay | eval setting=…", "1つ目の設定で fit し、どの設定かを setting 列に書く"),
        ("| append [| inputlookup … | fit … | eval setting=…]", "同じデータに別の設定で fit した結果を下に継ぎ足す。サブサーチの中も | inputlookup から始める"),
        ("| eval o='IsOutlier(value)', day=substr(timestamp,1,10)", "外れ値フラグと日付を取り出す"),
        ('| stats sum(o) as "外れ値の数" sum(eval(if(day="2014-04-11",o,0))) as "うち 4/11" by setting', "設定ごとに外れ値を数え、そのうち 4/11 のものも数える"),
        ('| eval "他の日（誤検知）"=…', "4/11 以外の外れ値の数＝誤検知の数"),
    ],
    "2-5": [
        ("| fit DensityFunction value by HourOfDay dist=norm | eval o='IsOutlier(value)'", "Search 2-3 と同じ判定"),
        ("| sort 0 _time", "時刻の順に並べる。連続回数を数える前に必ず並べる"),
        ("| streamstats reset_on_change=true count as run_length by o", "o（0 か 1）が同じ値で続く間、1, 2, 3… と数える。値が変わったら 1 に戻る"),
        ("| where o=1 | streamstats count(eval(run_length=1)) as run_id", "外れ値の行だけ残し、連続区間の始まり（run_length=1）ごとに区間番号を振る"),
        ("| stats min(_time) as start max(_time) as end max(run_length) as points by run_id", "区間ごとに、始まり、終わり、続いた点の数をまとめる"),
        ("| where points>=12", "12点（5分×12＝1時間）以上続いた区間だけを残す。アラートの条件にするならこの数字を調整する"),
    ],
    "3-1": [
        ("index=botsv2 sourcetype=perfmon:cpu", "Windows のパフォーマンスモニター（perfmon）が取った CPU カウンターに絞る"),
        ('counter="% idle time"', "CPU が何もしていなかった時間の割合だけを残す。値が低いほど CPU が忙しい"),
    ],
    "3-2": [
        ('index=botsv2 sourcetype=perfmon:cpu counter="% idle time"', "Search 3-1 と同じ"),
        ("| table _time host Value", "後の集計に使う時刻、ホスト名、値の3列だけにする"),
        ("| timechart span=30m min(Value) as idle_cpu by host",
         "30分ごとにアイドル率の<b>最小値</b>（＝その30分でいちばん忙しかった瞬間）を取り、ホストごとの列にする。平均を使うと短いスパイクが均されて見えにくくなる"),
    ],
    "3-3": [
        ('index=botsv2 sourcetype=perfmon:cpu counter="% idle time" host=wrk-aturing', "周期的な動きをしていた wrk-aturing だけに絞る"),
        ("| table _time host Value", "Search 3-2 と同じ"),
        ("| timechart span=30m min(Value) as idle_cpu", "1ホストだけなので by host は付けない。列は idle_cpu の1本になる"),
    ],
    "3-4": [
        ('index=botsv2 … host=wrk-aturing | table … | timechart span=30m min(Value) as idle_cpu', "Search 3-3 と同じ30分刻みの時系列を作る"),
        ("| fit StateSpaceForecast idle_cpu", "状態空間モデル（カルマンフィルターを使う時系列予測）で idle_cpu を学習する。時系列なので入力は等間隔に並んでいる必要がある"),
        ("holdback=8d", "最後の8日分は学習に使わずに取っておく。予測した線と実際の値を重ねて、答え合わせができる"),
        ("forecast_k=12d", "学習に使ったデータの終わり（8/22 09:00 から holdback の8日を引いた 8/14 09:00 ごろ）から12日先、つまり 8/26 の朝まで予測する"),
        ("into wrk_aturing_cpu_forecast_model",
         "モデルを保存する。fit の出力には <code>predicted(idle_cpu)</code>（予測値）と <code>lower95(predicted(idle_cpu))</code>／<code>upper95(predicted(idle_cpu))</code>（95%予測区間）の列が増える"),
    ],
    "3-5": [
        ('index=botsv2 … host=wrk-aturing | table … | timechart span=30m min(Value) as idle_cpu', "Search 3-3 と同じ時系列。こちらは 9/1 までの全期間を使う"),
        ("| apply wrk_aturing_cpu_forecast_model", "保存した予測モデルを当てはめて予測列を出す。毎日スケジュール実行すれば予測を更新し続けられる"),
    ],
    "3-6": [
        ('index=botsv2 … host=wrk-aturing | table … | timechart span=30m min(Value) as idle_cpu', "Search 3-4 と同じ時系列（8/1〜8/21）"),
        ("| predict idle_cpu algorithm=LLP5 period=48", "Splunk 標準の予測コマンド。LLP5 は水準・傾き・周期を組み合わせる方式。period=48 で1日周期を指定"),
        ("holdback=384 future_timespan=576", "predict は点の数で指定する。384点＝8日、576点＝12日（30分刻みは1日48点）"),
    ],
    "3-7": [
        ("| fit StateSpaceForecast … | eval p=…, model=…", "各方法の予測を p 列にそろえ、どの方法かを model 列に入れる。fit に into を付けていないので、モデルは保存されない"),
        ("| append [ … ]", "同じ時系列に別の方法を当てた結果を、下に継ぎ足す。[ ] の中はサブサーチ"),
        ("| filldown idle_cpu", "ARIMA は欠損があると動かないので、空の30分を直前の値で埋める"),
        ("| streamstats current=f window=336 first(idle_cpu) as p", "336点前（7日×48点）＝1週間前の同じ時刻の値を予測値とみなす"),
        ("| where _time>=1502668800 AND _time<1503360000 …", "holdback の区間（8/14 09:00〜8/22 09:00 JST）で、実測と予測の両方がある行だけを残す"),
        ("| eval e2=… | eventstats … | eval t2=…", "e2 は予測誤差の2乗、t2 は実測と平均との差の2乗"),
        ("| stats … by model | eval RMSE=…, R2=…", "RMSE＝誤差の2乗平均の平方根。R2＝1−（誤差の2乗和÷ばらつきの2乗和）"),
    ],
    "4-1": [
        ("index=botsv2 sourcetype=stream:tcp", "Splunk Stream が DMZ で取った TCP セッションのデータに絞る"),
        ("| timechart span=1h avg(client_rtt)", "1時間ごとに、クライアント側の往復時間（client_rtt）の平均を取る。列名は avg(client_rtt) になる"),
    ],
    "4-2": [
        ("index=botsv2 sourcetype=stream:tcp", "Search 4-1 と同じ"),
        ("| timechart span=1h avg(client_rtt) as avg_rtt", "<code>as avg_rtt</code> で列名を短くし、後のコマンドで扱いやすくする"),
        HOUR,
        ("| eventstats avg(avg_rtt) as avg stdev(avg_rtt) as stdev by HourOfDay", "シナリオ1の Search 1-4 と同じ考え方で、時間帯ごとに平均と標準偏差を求める"),
        BOUNDS,
        ("| table _time avg_rtt lower_bound upper_bound", "Outliers Chart 用に列を並べる"),
    ],
    "4-3": [
        ("index=botsv2 sourcetype=stream:tcp | timechart span=1h avg(client_rtt) as avg_rtt", "Search 4-2 と同じ時系列"),
        HOUR,
        ("| fit DensityFunction avg_rtt by HourOfDay into rtt_df_model",
         "時間帯ごとに avg_rtt の分布を推定し、確率の低い範囲に入った時間を <code>IsOutlier(avg_rtt)</code>=1 にする。rtt_df_model として保存する"),
    ],
    "4-4": [
        ("index=botsv2 sourcetype=stream:tcp | timechart span=1h avg(client_rtt) as avg_rtt", "Search 4-2 と同じ時系列"),
        HOUR,
        ("| apply rtt_df_model", "保存したモデルで判定だけを行う"),
        ('| fields _time avg_rtt "IsOutlier(avg_rtt)"', "下段のグラフ用だけに付けている絞り込み"),
    ],
}


def explain_block(sid):
    rows = EXPLAIN.get(sid)
    if not rows:
        return ""
    body = "".join(f"<tr><td><code>{html.escape(a, quote=False)}</code></td><td>{b}</td></tr>" for a, b in rows)
    return ('<div class="aitk-explain"><b>この SPL の読み方</b>'
            f'<table class="aitk-table"><tbody>{body}</tbody></table></div>')


# ================================================================ Scenario 1
S1_BASE = '| tstats count WHERE index=botsv2 source="wineventlog:security" TERM(EventCode=4625) BY  _time span=1h'
s1 = [
    {"id": "1-1", "tag": "Search 1-1", "title": "認証イベントを時系列で見る", "pages": "P35-36",
     "body": ["まず Windows セキュリティイベントログからログオン成功（4624）と失敗（4625）を数え、1時間ごとの推移を折れ線で見ます。"
              "このデータはログイン時刻や場所のベースラインを作る材料になります。",
              "BOTS v2 のデータは2017年8月のものです。資料では時間範囲を All time にしていますが、このダッシュボードでは 2017/8/1〜9/1 に固定しています。"],
     "spl": 'index=botsv2 source="wineventlog:security" (EventCode=4625 OR EventCode=4624)\n| timechart span=1h count by EventCode',
     "earliest": AUG1, "latest": SEP2,
     "views": [("line", "1時間ごとのログオン成功（4624）／失敗（4625）")],
     "checks": ["8月18日〜19日に、ログオン成功が2,000件超、失敗が200件超まで跳ねている",
                "グラフ上の点にマウスを合わせると、その時間の件数が出る"],
     "refs": ["s35_0.jpg", "s36_0.jpg"]},
    text_row('<div class="aitk-step-head"><span class="aitk-tag aitk-tag-info">解説</span><h2>| tstats で検索を速くする</h2>'
             '</div>'
             '<p>次のサーチから <code>| tstats</code> を使います。<code>stats</code> は前段の生イベントを1件ずつ処理しますが、'
             '<code>tstats</code> はインデクサーのバケットにある .tsidx（インデックス化されたメタデータ）だけを読みます。'
             'そのぶん大量データでも集計が速く終わります。</p>'
             '<p><code>TERM(EventCode=4625)</code> は「EventCode=4625」という文字列をそのまま索引語として探す書き方で、tstats の WHERE 句でよく使います。</p>'
             + img("s37_0.png", "aitk-icon")),
    {"id": "1-3", "tag": "Search 1-3", "title": "平均±2σで境界を引く（手動）", "pages": "P38-40",
     "body": ["ログオン失敗（4625）の外れ値は、不正侵入やアカウント侵害の手がかりになります。まだ ML は使わず、平均と標準偏差から上限・下限を手で計算します。",
              "データが正規分布に従うと仮定すると、経験則（Empirical rule）で値のほとんどは平均から標準偏差2つ分の範囲に入ります。その外側を外れ値とみなします。",
              "可視化には AI Toolkit の Outliers Chart を使っています。"],
     "spl": S1_BASE + "\n| eventstats avg(count) as avg stdev(count) as stdev\n| eval lower_bound=avg-2*stdev, upper_bound=avg+2*stdev\n| eval outlier=if(count<lower_bound OR count>upper_bound,1,0)\n| table _time count lower_bound upper_bound",
     "earliest": AUG1, "latest": SEP2,
     "views": [("outliers", "Outliers Chart（全体の平均±2σ）")],
     "checks": ["黄色の点が外れ値。青い帯が平均±2σの範囲",
                "8月19日と8月29日のスパイクは、データ全体から見て突出したグローバルな外れ値",
                "帯の中にも、毎日の周期から外れて見える点が残っている。これがローカルな外れ値で、次のステップで拾う"],
     "refs": ["s38_0.jpg", "s39_0.jpg", "s40_0.jpg"]},
    {"id": "1-4", "tag": "Search 1-4", "title": "時間帯（HourOfDay）ごとに境界を引く", "pages": "P41",
     "body": ["前のステップで見逃したローカルな外れ値を拾うため、集計を時間帯ごとに分けます。"
              "<code>eval HourOfDay</code> で時（00〜23）を取り出し、<code>eventstats ... by HourOfDay</code> で時間帯ごとの平均と標準偏差を求めます。",
              "これでローカルな外れ値も拾えますが、SPL はかなり込み入ってきました。もっと短い SPL で精度も上がる方法が、次に使う DensityFunction です。"],
     "spl": S1_BASE + '\n| eval HourOfDay=strftime(_time, "%H")\n| eventstats avg(count) as avg stdev(count) as stdev by HourOfDay\n| eval lower_bound=avg-2*stdev, upper_bound=avg+2*stdev\n| eval outlier=if(count<lower_bound OR count>upper_bound,1,0)\n| table _time count lower_bound upper_bound',
     "earliest": AUG1, "latest": SEP2,
     "views": [("outliers", "Outliers Chart（時間帯ごとの平均±2σ）")],
     "checks": ["青い帯が一日の周期に沿って上下するようになった",
                "外れ値の数（チャート右側）が Search 1-3 より増えている。資料では27件"],
     "refs": ["s41_0.jpg"]},
    text_row('<div class="aitk-step-head"><span class="aitk-tag aitk-tag-info">解説</span><h2>fit コマンドと apply コマンド</h2>'
             '</div>'
             '<p>AI Toolkit（旧 MLTK）は ML-SPL と呼ばれる独自の検索コマンドを追加します。中心になるのが次の2つです。</p>'
             + ul(["<b>fit</b>: 検索結果からモデルを学習する。<code>into</code> を付けるとモデルに名前を付けて保存する",
                   "<b>apply</b>: 保存したモデルを、いま流れている検索結果に当てはめる"])
             + spl_block("… | fit <ALGORITHM> <TARGET> from <VARIABLES …> <PARAMETERS> into <MODEL>\n\n"
                         "例：\n… | fit LinearRegression system_temp from cpu_load fan_rpm into temp_model\n"
                         "… | fit KMeans k=10 downloads purchases posts days_active visits_per_day into user_behavior_clusters\n"
                         "… | fit LinearRegression petal_length from species")),
    {"id": "1-5", "tag": "Search 1-5", "title": "DensityFunction でモデルを学習（fit）", "pages": "P43-44",
     "body": ["時間帯ごとのログオン失敗件数に DensityFunction を当てはめ、<code>botsv2_df_logon</code> という名前で保存します。"
              "<code>by \"HourOfDay\"</code> で時間帯ごとに別々の分布を学習するので、Search 1-4 で手書きした処理がこの1行に置き換わります。",
              "意味のある学習には十分な量のデータが要ります。ここで使う1か月分はトレーニング用としては少なめです。"
              "ゴミを入れればゴミが出てくる（rubbish in, rubbish out）ので、データを何でも投げ込めば問題が解けるわけではありません。"],
     "spl": S1_BASE + '\n| eval HourOfDay=strftime(_time,"%H")\n| fit DensityFunction count by "HourOfDay" into botsv2_df_logon',
     "earliest": AUG1, "latest": SEP2,
     "views": [("table", "fit の出力")],
     "checks": ["<code>IsOutlier(count)</code> 列が増えている（1 = 外れ値、0 = 正常）",
                "モデル名にスペースは使えない。モデルはルックアップの一種として保存される"],
     "note": "保存したモデルは次の「Search 1-5 確認①②」の <code>| listmodels</code> と <code>| summary</code> で確かめられます。",
     "refs": ["s43_0.jpg"]},
    {"id": "1-5m", "tag": "Search 1-5 確認①", "title": "保存したモデルの名札を listmodels で見る", "pages": "P43-44",
     "body": ["Search 1-5 の <code>into botsv2_df_logon</code> で保存したモデルが、本当にできているかを確かめます。"
              "<code>| listmodels</code> は、いまのアプリから見えるモデルの一覧を返す AI Toolkit のコマンドです。Search 1-5 を実行してから押してください。"
              "ここで見えるのはモデルの名前、種類、学習時の設定といった<b>名札（メタデータ）</b>だけです。学習した中身は次の「確認②」で見ます。",
              "モデルの設定は <code>options</code> 列に JSON の文字列で入っています。そのままでは読みにくいので、<code>spath</code> で JSON を項目ごとの列に展開しています。"
              "下の2つの表は、展開した結果を「主な設定」と「すべての設定（縦表示）」に分けて見せたものです。"],
     "spl": "| listmodels\n| search name=botsv2_df_logon\n| spath input=options\n| fields - options session_key",
     "earliest": AUG1, "latest": SEP2,
     "views": [("table", "主な設定", None, '| table name type app sharing split_by{} feature_variables{} mlspl_limits.default_prob_threshold mlspl_limits.min_data_size_to_fit\n| rename name as "モデル名" type as "アルゴリズム" app as "保存先アプリ" sharing as "共有範囲" split_by{} as "分割キー（by）" feature_variables{} as "学習した値" mlspl_limits.default_prob_threshold as "外れ値の確率しきい値" mlspl_limits.min_data_size_to_fit as "学習に必要な最小件数"'),
               ("table_long", "すべての設定（縦表示）", None, '| transpose 0 column_name="設定項目"\n| rename "row 1" as "値"')],
     "checks": ["主な設定の表に1行出る。アルゴリズムが DensityFunction、保存先アプリが aitk_security_training、共有範囲が user（自分だけが使えるモデル）",
                "分割キーが HourOfDay、学習した値が count。Search 1-5 の <code>fit DensityFunction count by \"HourOfDay\"</code> がそのまま記録されている",
                "外れ値の確率しきい値が 0.01。分布の端1%に入った点を外れ値とする基準",
                "縦表示の <code>mlspl_limits.*</code> は、学習時に効いていた上限値（学習に使う最大件数 max_inputs、最大学習時間 max_fit_time など）",
                "行が出ないときは、Search 1-5 がまだ実行されていないか、エラーで終わっている"]},
    {"id": "1-5s", "tag": "Search 1-5 確認②", "title": "学習した中身を summary で見る", "pages": "P43-44 の補足",
     "body": ["<code>| summary &lt;モデル名&gt;</code> は、保存したモデルが学習した中身を表にする AI Toolkit のコマンドです。"
              "DensityFunction の場合は、<code>by \"HourOfDay\"</code> で分けた時間帯ごとに、どの分布をどんな値で当てはめたかが1行ずつ出ます。"
              "apply はこの表の分布を使って判定します。"],
     "spl": "| summary botsv2_df_logon",
     "earliest": AUG1, "latest": SEP2,
     "views": [("table_long", "時間帯ごとに学習した分布")],
     "checks": ["HourOfDay 00〜23 の24行が出る。時間帯ごとに別の分布を学習している",
                "<code>type</code> は DensityFunction が自動で選んだ分布の種類（Auto: Normal、Auto: Beta など）",
                "<code>min</code>／<code>max</code> は学習に使った件数の最小と最大、<code>cardinality</code> は学習に使った行数（ここでは31日分なので31）",
                "<code>mean</code>／<code>std</code> は当てはめた分布のパラメータ。Beta のように件数をそのまま扱わない分布では、元の件数の平均とは一致しない",
                "HourOfDay は JST で計算されている。BOTS v2 には毎日同じ時間帯に同じ件数の失敗が出る時間があり、その時間帯は std が 1e-06（ばらつきほぼゼロ）になる"]},
    text_row('<div class="aitk-step-head"><span class="aitk-tag aitk-tag-info">解説</span><h2>fit の結果と、保存されるモデルは別もの</h2>'
             '</div>'
             '<p>Search 1-5 の結果に出た <code>IsOutlier(count)</code> の列は、listmodels には出てきません。fit は1回の実行で2つのことをしていて、残るのは片方だけだからです。</p>'
             '<table class="aitk-table"><thead><tr><th></th><th>fit の結果（Statistics の表）</th><th>保存されるモデル（into）</th></tr></thead><tbody>'
             '<tr><td><b>中身</b></td><td>入力の各行に <code>IsOutlier(count)</code> と <code>BoundaryRanges</code> を付けた表。744行（1時間ごと×31日）</td>'
             '<td>時間帯ごとに推定した分布（種類とパラメータ）と、学習時の設定。24行ぶん（HourOfDay 00〜23）</td></tr>'
             '<tr><td><b>残るか</b></td><td>残らない。その検索の結果として表示されるだけ。残したいときは <code>| outputlookup</code> やサマリーインデックスに書き出す</td>'
             '<td>残る。ルックアップの一種（<code>__mlspl_botsv2_df_logon.mlmodel</code>）としてアプリに保存される</td></tr>'
             '<tr><td><b>見る方法</b></td><td>fit や apply を実行したときの結果</td>'
             '<td>名札は <code>| listmodels</code>（確認①）、学習した中身は <code>| summary botsv2_df_logon</code>（確認②）</td></tr>'
             '</tbody></table>'
             '<p>つまり fit は、サマリーインデックスのように検索結果のデータを貯めるものではありません。保存されるのは「この基準で判定する」というモデルだけです。結果の行を残したい場合は、fit や apply の後ろに <code>| collect index=summary</code>（サマリーインデックス）や <code>| outputlookup</code> を自分で付けます。</p>'
             '<p>テストの採点にたとえると、fit は「答案の束から採点基準を作り、ついでにその束を採点する」作業です。保存されるのは採点基準（分布）だけで、採点済みの答案（IsOutlier の付いた行）は保存されません。'
             'Search 1-6 の apply は、保存した採点基準で新しい答案を採点し直します。だから apply の結果にも同じ <code>IsOutlier(count)</code> の列が出ます。</p>'),
    {"id": "1-6", "tag": "Search 1-6", "title": "保存したモデルを適用（apply）", "pages": "P45-48",
     "body": ["学習済みのモデル <code>botsv2_df_logon</code> を apply で当てはめ、グローバルとローカル両方の外れ値を出します。"
              "Search 1-5 を先に実行しておかないと、モデルが見つからずエラーになります。",
              "下段のグラフは、資料の手順（Line Chart で Format &gt; Chart Overlay に <code>IsOutlier(count)</code> を指定し、View as Axis をオン）を再現したものです。"
              "見やすくするため、グラフ側だけ <code>| fields _time count \"IsOutlier(count)\"</code> で列を絞っています。"],
     "spl": S1_BASE + '\n| eval HourOfDay=strftime(_time,"%H")\n| apply botsv2_df_logon',
     "earliest": AUG1, "latest": SEP2,
     "views": [("table", "Statistics（IsOutlier(count) 列を確認）"),
               ("line", "Line Chart + Chart Overlay: IsOutlier(count)", "IsOutlier(count)", '| fields _time count "IsOutlier(count)"')],
     "checks": ["<code>IsOutlier(count)</code> に 1.0 / 0.0 が入り、その時間の失敗件数が外れ値かどうかを示している",
                "オーバーレイの線が 1 に立っている時間が、モデルが外れ値と判定した時間"],
     "refs": ["s46_0.jpg", "s47_0.jpg", "s48_0.jpg"]},
    {"id": "1-6c", "tag": "Search 1-6 補足", "title": "DensityFunction の結果を Outliers Chart で見る",
     "body": ["Search 1-3／1-4 の Outliers Chart は、<code>lower_bound</code> と <code>upper_bound</code> の列を読んで帯を描きます。"
              "DensityFunction の apply はこの2列を出さず、代わりに <code>BoundaryRanges</code> という列に「外れ値とする範囲」を <code>始まり:終わり:確率</code> の形で入れます。",
              "このデータでは各行の BoundaryRanges が <code>-Infinity:下限:…</code> と <code>上限:Infinity:…</code> の2つの範囲になっているので、そこから下限と上限を取り出せば Outliers Chart で表示できます。"
              "時間帯ごとに帯の幅が変わり、Search 1-4 の手動の方法と見比べられます。"],
     "spl": S1_BASE + '\n| eval HourOfDay=strftime(_time,"%H")\n| apply botsv2_df_logon\n| eval lower_bound=tonumber(mvindex(split(mvindex(BoundaryRanges,0),":"),1)), upper_bound=tonumber(mvindex(split(mvindex(BoundaryRanges,-1),":"),0))\n| table _time count lower_bound upper_bound',
     "earliest": AUG1, "latest": SEP2,
     "views": [("outliers", "Outliers Chart（DensityFunction の境界）")],
     "checks": ["チャート右側の外れ値の数が 39。Search 1-6 の <code>IsOutlier(count)</code>=1 の数と同じになる",
                "毎日同じ件数が続く時間帯は、帯がほとんど線のように細い",
                "Search 1-4（平均±2σ）より帯が時間帯の実態に沿っている。特に件数がほぼ一定の時間帯で差が出る"],
     "note": "BoundaryRanges の形は分布によって変わります。シナリオ4の RTT のように範囲が1つだけ、または端が Infinity でない行がある場合は、この取り出し方は使えません。"},
    text_row('<div class="aitk-step-head"><span class="aitk-tag aitk-tag-info">解説</span><h2>標準偏差（平均±2σ）と DensityFunction の違い</h2></div>'
             '<p>Search 1-3／1-4 の平均±2σと、Search 1-5／1-6 の DensityFunction は、どちらも「ふだんの範囲」を決めてその外を外れ値にします。違うのは、ふだんの範囲の決め方です。'
             '平均±2σは「データは左右対称の山（正規分布）になる」と決め打ちして、平均と標準偏差の2つの数字だけで範囲を引きます。DensityFunction は分布の形そのものを推定し、起きる確率がいちばん低い1%を外れ値にします。</p>'
             + img("sigma_vs_density.svg", "aitk-shot") +
             '<p>17時台の実データで比べた図です。31日のうち27日は22件ちょうどでした。平均±2σでは、44・46・74・146 という大きな値そのものが平均と標準偏差を押し上げ、上限が77.5まで広がります。'
             'その結果、ふだんの2倍以上ある 44・46・74 を見逃します。DensityFunction は22件に集中した分布を当てはめるので、上限が29.4になり、4つとも外れ値になります。</p>'
             + img("density_dists.svg", "aitk-shot") +
             '<p><code>dist=auto</code>（GUI の Distribution type = Auto）は、上の4種類をすべて当てはめて、いちばん合うものを時間帯ごとに選びます。<code>| summary botsv2_df_logon</code> の type 列に、選ばれた分布が出ます。</p>'
             '<h4 style="margin:14px 0 4px;">特徴の比較</h4>'
             '<table class="aitk-table"><thead><tr><th></th><th>平均±2σ（全体）<br/>Search 1-3</th><th>平均±2σ（時間帯ごと）<br/>Search 1-4</th><th>DensityFunction<br/>Search 1-5／1-6</th></tr></thead><tbody>'
             '<tr><td>前提</td><td>全体が1つの正規分布</td><td>時間帯ごとに正規分布</td><td>分布の形を4種類から自動で選ぶ（by で時間帯ごと）</td></tr>'
             '<tr><td>外れ値自身の影響</td><td colspan="2">大きい。大きな値が σ を押し上げ、他の外れ値が隠れる</td><td>分布の形で判断するので、このデータでは引きずられにくかった</td></tr>'
             '<tr><td>偏った分布（0 以下にならない件数など）</td><td colspan="2">苦手。Search 1-3 では下限が −24.5 という、件数としてありえない負の値になる</td><td>expon や beta で、右に裾の長い形にも合わせられる</td></tr>'
             '<tr><td>書き方</td><td>eventstats＋eval</td><td>eventstats … by＋eval</td><td>fit／apply。モデルとして保存し、同じ基準で使い回せる</td></tr>'
             '<tr><td>この演習での外れ値の数</td><td>28</td><td>27</td><td>39（Search 1-4 の27個をすべて含む）</td></tr>'
             '<tr><td>注意</td><td colspan="2">2σ の「2」を変えると結果が大きく変わる</td><td>各グループ50点以上での学習が推奨。ばらつきがほぼゼロの時間帯は、わずかな増減でも外れ値になりやすい</td></tr>'
             '</tbody></table>'
             '<h4 style="margin:14px 0 4px;">どちらがどれだけ正確か</h4>'
             '<p>「本当に攻撃だった時間」の一覧（正解ラベル）がこのデータには無いので、正解率としての精度は計算できません。言えるのは次の2点です。</p>'
             + ul(["DensityFunction は、時間帯ごとの平均±2σが見つけた27個を<b>すべて</b>見つけ、さらに12個を追加で見つけた。追加分は 8/5・8/8 の17時台（44件・46件、ふだんは22件）のように、ふだんの値から見て明らかに多いものが中心",
                   "どの方法でも、しきい値（2σ の「2」や threshold の 0.01）を変えれば外れ値の数は増減する。実運用では、正解がわかっている過去のインシデントで外れ値に入るかを確かめてしきい値を決める"]) +
             '<p class="aitk-note">次の「Search 1-6 比較」で、3つの方法の外れ値の数を実際に比べられます。</p>'),
    {"id": "1-6x", "tag": "Search 1-6 比較", "title": "3つの方法の外れ値を並べて比べる",
     "body": ["同じデータに、全体の平均±2σ、時間帯ごとの平均±2σ、DensityFunction の3つを当て、外れ値の数と重なりを数えます。Search 1-5 を実行してから押してください。"],
     "spl": S1_BASE + '\n| eval HourOfDay=strftime(_time,"%H")\n| eventstats avg(count) as g_avg stdev(count) as g_sd\n| eval global_2sigma=if(count<g_avg-2*g_sd OR count>g_avg+2*g_sd,1,0)\n| eventstats avg(count) as h_avg stdev(count) as h_sd by HourOfDay\n| eval hourly_2sigma=if(count<h_avg-2*h_sd OR count>h_avg+2*h_sd,1,0)\n| apply botsv2_df_logon\n| eval density=\'IsOutlier(count)\'\n| stats sum(global_2sigma) as "全体の平均±2σ" sum(hourly_2sigma) as "時間帯ごとの平均±2σ" sum(density) as "DensityFunction" sum(eval(if(hourly_2sigma=1 AND density=1,1,0))) as "両方で外れ値" sum(eval(if(hourly_2sigma=0 AND density=1,1,0))) as "DensityFunction だけ"',
     "earliest": AUG1, "latest": SEP2,
     "views": [("table", "外れ値の数（744時間中）")],
     "checks": ["全体の平均±2σ が 28、時間帯ごとの平均±2σ が 27、DensityFunction が 39",
                "「両方で外れ値」が 27。時間帯ごとの平均±2σ が見つけたものは、DensityFunction もすべて見つけている",
                "「DensityFunction だけ」の 12 個を見たいときは、Search で開いて最後の stats を <code>| where hourly_2sigma=0 AND density=1 | table _time HourOfDay count h_avg h_sd</code> に変える"]},
    outlier_gui("Search 1-5／1-6", S1_BASE + '\n| eval HourOfDay=strftime(_time,"%H")', "count", "HourOfDay", "botsv2_df_logon", "Search 1-6"),
    text_row('<div class="aitk-step-head"><span class="aitk-tag aitk-tag-gui" style="background:#7b3fa0;">GUI</span><h2>Smart Outlier Detection の結果画面の読み方</h2></div>'
             '<p>Learn 画面で Detect Outliers を押すと、右側に結果が出ます。この演習のデータ（しきい値 0.01）では次のように読みます。</p>'
             + img("gui_sod_result.jpg", "aitk-shot aitk-fig-wide") +
             '<p class="aitk-note">Search 1-5 と同じ条件で Detect Outliers を実行した画面（Evaluate タブ、密度表示、Top 3 groups）</p>'
             '<table class="aitk-table"><thead><tr><th>画面の場所</th><th>読み方</th></tr></thead><tbody>'
             '<tr><td>上部の1行<br/><code>Detect outliers in count, split by HourOfDay, using Auto distribution with a threshold of 0.01</code></td>'
             '<td>今回の fit の条件。count を HourOfDay ごとに分け、分布は自動選択、しきい値 0.01 で外れ値を探した</td></tr>'
             '<tr><td>タブ：<b>入力</b>／<b>出力</b>／<b>Evaluate</b></td>'
             '<td>入力は Define の検索結果。出力は fit の結果の表で、<code>IsOutlier(count)</code> 列が付いている（Search 1-5 の表と同じもの）。Evaluate はグラフで評価する画面</td></tr>'
             '<tr><td><b>Total Outliers 39</b></td>'
             '<td>744時間（24時間帯×31日）のうち、「その時間帯としてはありえない件数」と判定された時間が39個ある。Search 1-6 の apply で出る数と同じ</td></tr>'
             '<tr><td><b>表示</b>：Top 3 groups with most outliers<br/><b>グループ</b>：17, 12, 13</td>'
             '<td>外れ値が多かった時間帯の上位3つ。<b>17・12・13 は日付ではなく HourOfDay（17時台、12時台、13時台、JST）</b>。凡例の括弧の数字はその時間帯の外れ値の数（17時台は4、12時台と13時台は3）。グループのドロップダウンで他の時間帯も選べる</td></tr>'
             '<tr><td><b>Chart Type</b>：密度／時間<br/><b>Chart Mode</b>：Combined／分割</td>'
             '<td>密度は件数ごとの分布図、時間は時間軸での表示。Combined は選んだ時間帯を1枚に重ね、分割は時間帯ごとに別のグラフにする</td></tr>'
             '<tr><td>横軸 count</td><td>1時間あたりのログオン失敗件数</td></tr>'
             '<tr><td>棒（右軸 count(count)）</td><td>その件数だった日が何日あったか。17時台なら 22件のところに27日分の棒が立つ</td></tr>'
             '<tr><td>曲線（左軸 ProbabilityDensity）</td><td>モデルが当てはめた分布。左軸の 5e+26 のような値は、毎日ほぼ同じ件数でばらつきがほぼゼロのため極端に大きくなっているだけで、気にしなくてよい</td></tr>'
             '<tr><td>横軸の上の点（show outliers）</td><td>外れ値と判定された件数。17時台なら 44、46、74、146 の位置</td></tr>'
             '<tr><td>塗りの範囲（show outlier area）</td><td>「ここに入ったら外れ値」とする確率の低い領域。しきい値 0.01 なら分布の端1%</td></tr>'
             '<tr><td>左の黄色い警告<br/><code>Too few training points in some groups</code></td><td>時間帯ごとの学習データが31点（31日分）しかない、という注意。演習データが1か月分のため。実環境では数か月分で学習させたい</td></tr>'
             '</tbody></table>'
             '<h4 style="margin:14px 0 4px;">例：17時台の外れ値</h4>'
             '<table class="aitk-table"><thead><tr><th>17時台の失敗件数</th><th>日数</th><th>判定</th></tr></thead><tbody>'
             '<tr><td>22件</td><td>27日</td><td>ふだんの値</td></tr>'
             '<tr><td>44件／46件／74件／146件</td><td>各1日（8/8、8/5、8/26、8/19）</td><td>外れ値</td></tr></tbody></table>'
             '<p>12時台は 8/19 の130件と 8/24 の123件など、13時台は 8/19 の134件と 8/24・8/25 が外れ値です。<b>8/19 は3つの時間帯すべてに出てきます。</b>'
             'Search 1-1 で見た 8/18〜19 のスパイクで、JST では 8/19 の昼から夕方にあたります。調査で最初に見るべき日です。</p>'
             '<p class="aitk-note">Evaluate タブのしきい値を 0.001 に下げて「適用」すると外れ値は減り、0.05 に上げると増えます。ここでの変更は apply なので再学習しません。</p>'),
    text_row('<div class="aitk-step-head"><span class="aitk-tag aitk-tag-info">本番化</span><h2>スケジュールと再学習</h2>'
             '</div>'
             '<p>これで、新しく入ってくるデータに対して頻繁に実行できる学習済みモデルができました。apply のサーチをスケジュール検索にすれば、異常なログオンを継続して監視できます。</p>'
             '<p>モデルは定期的に再学習させる必要があります。データの分布が学習時から大きく外れると、結果が不正確になるからです。'
             '自分の環境でデータがどのくらいの頻度で変わるかを考え、apply と同じように fit もスケジュールしてください。</p>'),
    text_row('<div class="aitk-step-head"><span class="aitk-tag aitk-tag-info">ブックマーク</span><h2>検索の内訳</h2>'
             '</div>' + breakdown([
                 ('index=botsv2 source="wineventlog:security" (EventCode=4625 OR EventCode=4624)', "ログオン失敗（4625）と成功（4624）の Windows イベントログを検索する"),
                 ("… | timechart span=1h count by EventCode", "時間を X 軸、EventCode ごとの1時間あたり件数を Y 軸にしたチャートを作る"),
                 ("… | eventstats avg(count) as avg stdev(count) as stdev", "全イベント（ここでは 4625）の平均と標準偏差を求める"),
                 ("… | eval lower_bound=avg-2*stdev, upper_bound=avg+2*stdev", "平均と標準偏差から下限と上限を計算する。stdev に2を掛けて感度を調整している"),
                 ("… | eval outlier=if(count<lower_bound OR count>upper_bound,1,0)", "下限・上限を使って外れ値に印を付ける"),
                 ("… | table _time count lower_bound upper_bound", "時刻、件数、下限、上限の表を返す"),
                 ('… | eval HourOfDay=strftime(_time,"%H")', "_time から時（hour）を文字列で取り出す"),
                 ('… | fit DensityFunction count by "HourOfDay" into botsv2_df_logon', "DensityFunction モデルを学習し、botsv2_df_logon として保存する"),
                 ("… | apply botsv2_df_logon", "保存したモデルを適用する。AI Toolkit と PSC が入っている環境でのみ使える"),
             ])),
]
S1_INTRO = ('<div class="aitk-hero-text"><span class="aitk-kicker">AITK Security for Primer ／ シナリオ1</span>'
            '<h1>ユーザーアクセスの異常を検知する</h1>'
            '<p>あなたは Frothly の SOC アナリストです。社内のいくつかのアカウントがハッキングされたかもしれない、と連絡を受けました。</p>'
            '<p>侵入がどこで起きたかを遡り、侵害された可能性のあるアカウントを特定するのが任務です。'
            'そのために、ログオン／ログオフの成功・失敗などを記録した Windows セキュリティイベントログを分析します。</p>'
            '<p class="aitk-flow">時系列で眺める → 平均±2σで境界を引く → 時間帯ごとに分ける → DensityFunction で fit → apply</p></div>'
            + img("s34_0.png", "aitk-hero-icon"))

# ================================================================ Scenario 3
S3_BASE = 'index=botsv2 sourcetype=perfmon:cpu counter="% idle time"'
S3_HOST = S3_BASE + ' host=wrk-aturing\n| table _time host Value\n| timechart span=30m min(Value) as idle_cpu'
s3 = [
    {"id": "3-1", "tag": "Search 3-1", "title": "CPU カウンターの生イベントを見る", "pages": "P67",
     "body": ["まず perfmon の CPU データにどんなパターンがあるかを見るため、Buttercup Games の CPU 使用率に関する生イベントを表示します。"],
     "spl": S3_BASE, "earliest": AUG1, "latest": SEP2,
     "views": [("events", "perfmon:cpu の生イベント")],
     "checks": ["<code>counter=\"% idle time\"</code> のイベントに <code>Value</code> フィールドがある",
                "見ているのは CPU の<b>アイドル</b>時間。負荷のスパイクはこの値が<b>低く</b>なるところに出る"],
     "refs": ["s67_0.jpg"]},
    {"id": "3-2", "tag": "Search 3-2", "title": "ホストごとの CPU アイドル時間を時系列で見る", "pages": "P68-69",
     "body": ["30分ごとの最小アイドル時間をホスト別に折れ線にし、CPU 使用率が時間とともにどう変わるかを見ます。"],
     "spl": S3_BASE + "\n| table _time host Value\n| timechart span=30m min(Value) as idle_cpu by host",
     "earliest": AUG1, "latest": SEP2,
     "views": [("line", "ホスト別 idle_cpu（30分ごとの最小値）")],
     "checks": ["ほとんどのホストは平らで、時間が経ってもあまり変わらない",
                "<code>wrk-aturing</code> だけが周期的な動きをしている。凡例をクリックすると1ホストだけ強調できる"],
     "refs": ["s68_0.jpg", "s69_0.jpg"]},
    {"id": "3-3", "tag": "Search 3-3", "title": "wrk-aturing に絞り込む", "pages": "P70",
     "body": ["周期的な動きをしていた wrk-aturing について、8月1日〜8月28日の CPU の挙動をもう少し掘り下げます。"],
     "spl": S3_HOST, "earliest": AUG1, "latest": AUG28,
     "views": [("line", "wrk-aturing の idle_cpu（8/1〜8/28）")],
     "checks": ["8月18日に idle_cpu がほぼ0まで落ちている。ユーザーから報告があったクラッシュの時期と重なる"],
     "refs": ["s70_0.jpg"]},
    {"id": "3-4", "tag": "Search 3-4", "title": "StateSpaceForecast で予測モデルを学習（fit）", "pages": "P71",
     "body": ["StateSpaceForecast アルゴリズムで予測を作り、今後の負荷スパイクを予測できるかを見ます。",
              "<code>holdback=8d</code> は入力の最後の8日分を学習に使わず、予測と答え合わせするために取っておく指定です。"
              "<code>forecast_k=12d</code> は12日先まで予測する指定です。資料に合わせて時間範囲は 8/1〜8/21 にしています。"],
     "spl": S3_HOST + "\n| fit StateSpaceForecast idle_cpu holdback=8d forecast_k=12d into wrk_aturing_cpu_forecast_model",
     "earliest": AUG1, "latest": AUG22,
     "views": [("line", "idle_cpu と predicted(idle_cpu)、95%予測区間")],
     "checks": ["<code>predicted(idle_cpu)</code> と <code>lower95</code>／<code>upper95</code> の列が追加される",
                "「Field idle_cpu contains null value(s). We will try to impute them.」という警告が出ても、欠損を補完して処理は続く",
                "この設定では予測は 8/26 の朝（08:30）まで出る。holdback の8日分（8/14〜8/21）は予測と実測が重なるので、答え合わせに使える",
                "資料のノートは「8月30日・31日・9月1日の22時ごろに CPU 使用率が高くなる可能性が小さいながらある」と読み、チームに CPU 容量の追加を伝える結論にしている。その日付まで見るには、Search で開いて時間範囲を広げて実行し直す"],
     "refs": ["s71_0.jpg"]},
    text_row('<div class="aitk-step-head"><span class="aitk-tag aitk-tag-info">解説</span><h2>StateSpaceForecast のしくみとパラメータ</h2></div>'
             '<p>StateSpaceForecast は、カルマンフィルターを使う時系列予測のアルゴリズムです。データの裏に「いまの水準」や「1日の周期のパターン」といった見えない状態があると考え、'
             '1点ずつ「予測する → 実測と比べて状態を直す」を繰り返して状態を学びます。データが尽きた先は、予測だけを続けて未来の値と予測の幅を出します。</p>'
             + img("ssf_kalman.svg", "aitk-shot") +
             '<p>周期（period）を指定しなかった Search 3-4 でも、<code>| summary wrk_aturing_cpu_forecast_model</code> を実行すると <code>periodicity: 48</code> と出ます。30分刻みのデータで48点＝1日の周期を、自動で見つけています。'
             '欠けた値（timechart で空になった30分）も、警告を出したうえで予測値で補って進みます。</p>'
             + img("ssf_timeline.svg", "aitk-shot") +
             '<h4 style="margin:14px 0 4px;">パラメータ</h4>'
             '<table class="aitk-table"><thead><tr><th>パラメータ</th><th>意味</th><th>既定値</th><th>Search 3-4 では</th></tr></thead><tbody>'
             '<tr><td><code>holdback</code></td><td>入力の最後のこの期間を学習に使わずに取っておく。予測と実測を比べる答え合わせ用。<code>8d</code> のような期間か、点の数で指定</td><td>0</td><td>8d（8/14〜8/21）</td></tr>'
             '<tr><td><code>forecast_k</code></td><td>学習に使ったデータの終わりから、何点（どれだけの期間）先まで予測するか</td><td>0</td><td>12d（8/14 から 8/26 まで）</td></tr>'
             '<tr><td><code>conf_interval</code></td><td>予測区間の幅（1〜99）。95 なら「95%の確率でこの幅に入る」範囲を lower95／upper95 に出す</td><td>95</td><td>省略（95）</td></tr>'
             '<tr><td><code>period</code></td><td>周期の長さ（点の数）。省略すると自動で求める。<code>period=1</code> で周期なし</td><td>自動</td><td>省略（自動で48）</td></tr>'
             '<tr><td><code>specialdays</code></td><td>セールや祝日など、ふだんと違う日を 1 にした数値フィールド。週末のような規則的なものには使わない。apply でも同じフィールドが要る</td><td>なし</td><td>使っていない</td></tr>'
             '<tr><td><code>partial_fit</code></td><td>保存済みモデルに新しいデータだけを追加で学習させる</td><td>false</td><td>使っていない</td></tr>'
             '<tr><td><code>update_last</code></td><td>partial_fit=true のとき、先に予測してから学習するか（true）、学習してから予測するか（false）</td><td>false</td><td>使っていない</td></tr>'
             '<tr><td><code>output_fit</code></td><td>学習区間についての当てはめ結果も出力する</td><td>false</td><td>使っていない</td></tr>'
             '<tr><td><code>as</code></td><td>予測列の名前を付け替える</td><td>なし</td><td>使っていない</td></tr>'
             '</tbody></table>'
             '<p class="aitk-note">holdback と forecast_k は apply でも指定できます。複数のフィールドをまとめて予測する多変量予測もできます（GUI の Field to forecast は最大5つ）。</p>'),
    {"id": "3-5", "tag": "Search 3-5", "title": "予測モデルを適用（apply）", "pages": "P72",
     "body": ["保存した <code>wrk_aturing_cpu_forecast_model</code> を apply すれば、新しいデータに毎日実行して予測を作り直す、という本番運用ができます。"
              "Search 3-4 を先に実行しておいてください。"],
     "spl": S3_HOST + "\n| apply wrk_aturing_cpu_forecast_model",
     "earliest": AUG1, "latest": SEP2,
     "views": [("line", "apply した予測結果")],
     "checks": ["fit と同じ予測列が出る。この SPL をスケジュール検索にすれば毎日予測を更新できる"],
     "refs": ["s72_0.jpg"]},
    {"id": "3-6", "tag": "Search 3-6", "title": "Splunk 標準の predict コマンドで予測する",
     "body": ["AI Toolkit が無くても、Splunk 標準の <code>predict</code> コマンドで同じような予測ができます。モデルは保存できず、毎回その場で計算します。"
              "<code>algorithm=LLP5</code> は水準・傾き・周期を組み合わせる方式で、<code>period=48</code> で1日の周期を指定しています。holdback と future_timespan は点の数で指定します（8日×48点＝384、12日×48点＝576）。"],
     "spl": S3_HOST + "\n| predict idle_cpu algorithm=LLP5 period=48 holdback=384 future_timespan=576",
     "earliest": AUG1, "latest": AUG22,
     "views": [("line", "predict（LLP5）の予測")],
     "checks": ["<code>prediction(idle_cpu)</code> と <code>lower95</code>／<code>upper95</code> の列が出て、Search 3-4 と同じく 8/26 ごろまで予測が伸びる"]},
    {"id": "3-7", "tag": "Search 3-7", "title": "holdback の8日間で予測の当たり具合を比べる",
     "body": ["holdback に取っておいた 8/14〜8/21 の実測と、各方法の予測を比べ、誤差を数字にします。"
              "<b>RMSE</b> は予測と実測の差の大きさの平均で、0 に近いほど良い。<b>R2</b> は実測の動きをどれだけ説明できたかで、1 に近いほど良い。",
              "比べるのは StateSpaceForecast、predict（LLP5）、ARIMA（AI Toolkit）、それに「1週間前の同じ時刻の値をそのまま使う」だけの単純な方法です。"
              "最後のものは何も学習しない基準線で、凝ったモデルがこれに勝てているかを見るために入れています。"],
     "spl": S3_HOST + "\n| fit StateSpaceForecast idle_cpu holdback=8d forecast_k=12d\n| eval p='predicted(idle_cpu)', model=\"StateSpaceForecast\"\n"
            "| append [ search " + S3_HOST.replace("\n", " ") + " | predict idle_cpu algorithm=LLP5 period=48 holdback=384 future_timespan=576 | eval p='prediction(idle_cpu)', model=\"predict (LLP5)\" ]\n"
            "| append [ search " + S3_HOST.replace("\n", " ") + " | filldown idle_cpu | fit ARIMA _time idle_cpu order=2-0-1 holdback=384 forecast_k=576 | eval p='predicted(idle_cpu)', model=\"ARIMA (2-0-1)\" ]\n"
            "| append [ search " + S3_HOST.replace("\n", " ") + " | streamstats current=f window=336 first(idle_cpu) as p | eval model=\"1週間前の値\" ]\n"
            "| where _time>=1502668800 AND _time<1503360000 AND isnotnull(idle_cpu) AND isnotnull(p)\n"
            "| eval e2=pow(idle_cpu-p,2)\n| eventstats avg(idle_cpu) as m by model\n| eval t2=pow(idle_cpu-m,2)\n"
            "| stats count as points avg(e2) as mse sum(e2) as sse sum(t2) as sst by model\n"
            "| eval RMSE=round(sqrt(mse),2), R2=round(1-sse/sst,3)\n| table model points RMSE R2\n| sort RMSE",
     "earliest": AUG1, "latest": AUG22,
     "views": [("table", "holdback（8/14〜8/21）での予測の当たり具合")],
     "checks": ["StateSpaceForecast は RMSE 6.02・R2 0.935、predict（LLP5）は 7.73・0.893、ARIMA（2-0-1）は 23.45・0.003",
                "「1週間前の値」は 5.87・0.938 で、StateSpaceForecast とほぼ同じ。このホストの CPU は1週間単位でほぼ同じ動きを繰り返しているため、単純な方法でもよく当たる",
                "ARIMA が外れるのは、order=2-0-1 では1日の周期を表せないから。ARIMA は order の調整が必要で、モデルの保存（into／apply）もできない"],
     "note": "「1週間前の値」は holdback の最終日だけ、holdback 期間内の実測を使っています。予測というより比較の物差しとして見てください。"},
    text_row('<div class="aitk-step-head"><span class="aitk-tag aitk-tag-info">解説</span><h2>StateSpaceForecast 以外で予測する方法</h2></div>'
             '<table class="aitk-table"><thead><tr><th>方法</th><th>書き方</th><th>モデル保存（apply）</th><th>向いている場面・注意</th></tr></thead><tbody>'
             '<tr><td><b>StateSpaceForecast</b>（AI Toolkit）</td><td><code>| fit StateSpaceForecast …</code></td><td>できる</td><td>周期の自動検出、欠損の補完、specialdays、多変量。迷ったらまずこれ</td></tr>'
             '<tr><td><b>predict</b>（Splunk 標準）</td><td><code>| predict … algorithm=LLP5</code></td><td>できない</td><td>AI Toolkit なしで使える。LL／LLT／LLP／LLP5 などの方式を選ぶ。ダッシュボードの簡易予測向き</td></tr>'
             '<tr><td><b>ARIMA</b>（AI Toolkit）</td><td><code>| fit ARIMA _time … order=p-d-q</code></td><td>できない</td><td>order（自己回帰・差分・移動平均の次数）を自分で決める。欠損があると動かないので timechart と補完が要る。ACF／PACF で次数を探す</td></tr>'
             '<tr><td><b>回帰モデル</b>（AI Toolkit）</td><td><code>| fit RandomForestRegressor idle_cpu from …</code></td><td>できる</td><td>時刻、曜日、過去の値（streamstats で作るラグ）などを説明変数にして予測する。外部要因を入れたいとき</td></tr>'
             '<tr><td><b>SystemIdentification</b>（AI Toolkit）</td><td><code>| fit SystemIdentification … dynamics=…</code></td><td>できる</td><td>ニューラルネットで、過去の値と他のフィールドとの非線形な関係も学ぶ。複数の指標が影響し合う場合</td></tr>'
             '<tr><td><b>時系列の基盤モデル CDTSM</b>（AI Toolkit 6.1）</td><td><code>| apply CDTSM …</code>（Cisco Deep Time Series Model）</td><td>学習済み</td><td>事前学習済みなので fit なしで予測できる。自分のデータでの微調整は、6.1 の時点では一部の Splunk Cloud 向けのアルファプレビュー</td></tr>'
             '<tr><td><b>DSDL</b>（Data Science and Deep Learning）</td><td>コンテナ上の Jupyter で自作</td><td>できる</td><td>Prophet や LSTM など、AI Toolkit にないモデルを Python で使う</td></tr>'
             '</tbody></table>'),
    gui_panel("Search 3-4／3-5 を GUI でやる（Smart Forecasting）", "StateSpaceForecast",
              "AI Toolkit の Smart Forecasting アシスタントは、裏で StateSpaceForecast の fit を実行します。holdback や予測期間を画面で指定して、同じ予測モデルを作れます。",
              [("開く", "AI Toolkit アプリ → <b>Experiments</b> で <b>Smart Forecasting</b> を選び、右上の <b>Create New Experiment</b> を押して、"
                        "<b>Experiment Title</b>（例：wrk_aturing_cpu_forecast_gui）を入れて <b>Create</b>"),
               ("Define", "データソースに <b>Search</b> を選び、次の SPL を貼る。時間範囲は Search 3-4 と同じ 2017/08/01〜2017/08/22 にする。"
                          "<b>Data Preview</b> と <b>Visualization</b> に30分刻みの idle_cpu が出たら <b>Next</b>" + spl_block(S3_HOST)),
               ("Learn", "<b>Field to forecast</b> に idle_cpu、<b>Holdback period</b> に 8 日、<b>Future timespan</b> に 12 日（数値を入れ、単位はリストから選ぶ）、"
                         "<b>Confidence interval</b> に 95 を入れて <b>Forecast</b> を押す。<b>Period</b> は空欄のまま（SPL でも指定していない）。"
                         "右上の <b>SPL</b> ボタンで、画面が生成した fit の SPL を見られる"),
               ("Review", "<b>R2</b> と <b>RMSE</b> で、holdback の8日分について予測がどれだけ当たったかを見る。R2 は1に近いほど、RMSE は0に近いほど良い。"
                          "<b>Forecasted Value</b> や <b>Earliest Threshold Violation</b> で、予測がしきい値を超える最初の日時も確かめられる。よければ <b>Save and Next</b> → <b>Save</b>"),
               ("Operationalize", "<b>Publish Forecasting Models</b> でモデル名（例：wrk_aturing_cpu_forecast_gui）と公開先アプリ（aitk_security_training）を指定して公開する。"
                                  "公開した本人なら、Search 3-5 の <code>apply wrk_aturing_cpu_forecast_model</code> を公開した名前に変えれば使える。"
                                  "<b>Create Alert</b> と <b>Schedule Model Training</b> もここから設定できる")],
              [("fit StateSpaceForecast idle_cpu", "Field to forecast（最大5つで多変量予測）", "idle_cpu"),
               ("holdback=8d", "Holdback period", "8 days"),
               ("forecast_k=12d", "Future timespan", "12 days"),
               ("conf_interval=（省略時は 95）", "Confidence interval（0〜99）", "95（lower95／upper95 の列になる）"),
               ("period=（省略時は自動）", "Period", "空欄。30分刻みで1日周期を明示するなら 48"),
               ("into wrk_aturing_cpu_forecast_model", "Experiment を Save → Publish したときのモデル名", "wrk_aturing_cpu_forecast_gui")],
              "Experiment で作ったモデルは、作った人の領域に保存されます。他のアプリの検索から使うには Publish が必要です。Publish は Operationalize 画面のほか、Experiments 一覧の Actions 列からもできます（モデルを学習済みの Experiment だけ）。モデル名に使えるのは英字、数字、アンダースコアだけで、先頭は英字かアンダースコアです。公開したモデルは公開先アプリの<b>公開した人の領域</b>に置かれるので、そのままでは他のユーザーからは見えません。"),
    text_row('<div class="aitk-step-head"><span class="aitk-tag aitk-tag-info">ブックマーク</span><h2>検索の内訳</h2>'
             '</div>' + breakdown([
                 (S3_BASE, "botsv2 の perfmon:cpu ログから CPU のアイドル時間を検索する"),
                 ("… | table _time host Value", "時刻、ホスト、CPU アイドル値の表を作る"),
                 ("… | timechart span=30m min(Value) as idle_cpu by host", "ホストごとに、30分ごとの最小アイドル時間を求める"),
                 ("… | fit StateSpaceForecast idle_cpu holdback=8d forecast_k=12d into wrk_aturing_cpu_forecast_model",
                  "StateSpaceForecast モデルを学習する。最後の8日分を除いたデータで学習し、12日先まで予測する"),
                 ("… | apply wrk_aturing_cpu_forecast_model", "保存した wrk_aturing_cpu_forecast_model をデータに適用する"),
             ])),
]
S3_INTRO = ('<div class="aitk-hero-text"><span class="aitk-kicker">AITK Security for Primer ／ シナリオ3</span>'
            '<h1>CPU 使用率を予測する</h1>'
            '<p>あなたは Frothly の IT オペレーションアナリストです。CPU 使用率が次にいつ跳ね上がるかを予測できないか調べてほしい、と頼まれました。インシデントが起きる前に手を打つためです。</p>'
            '<p>Buttercup Games では「ゲームが固まってから突然落ちる」という報告が何件も来ています。根本原因を調べると、クラッシュ時にいくつかのサーバーで CPU 使用率がかなり高くなっていました。</p>'
            '<p class="aitk-flow">生イベント → ホスト別の時系列 → wrk-aturing に絞る → StateSpaceForecast で fit → apply</p>'
            '<p class="aitk-note">この演習は .conf19 のセッション FN1137 を大まかに下敷きにしています。</p></div>'
            + img("s66_0.png", "aitk-hero-icon"))

# ================================================================ Scenario 4
S4_BASE = "index=botsv2 sourcetype=stream:tcp"
s4 = [
    {"id": "4-1", "tag": "Search 4-1", "title": "1時間あたりの平均 RTT を見る", "pages": "P77-78",
     "body": ["まず1時間ごとの平均クライアント RTT をプロファイリングします。"],
     "spl": S4_BASE + "\n| timechart span=1h avg(client_rtt)",
     "earliest": AUG1, "latest": SEP2,
     "views": [("line", "1時間ごとの avg(client_rtt)")],
     "checks": ["日ごとの周期的なパターンがある",
                "いくつかの日に、そのパターンに沿わない大きなスパイクや急落がある"],
     "refs": ["s77_0.jpg", "s78_0.jpg"]},
    {"id": "4-2", "tag": "Search 4-2", "title": "時間帯ごとの平均±2σで外れ値を探す", "pages": "P79-80",
     "body": ["シナリオ1と同じ考え方で、時間帯ごとの平均と標準偏差から上限・下限を引き、その外側を外れ値とみなします。"],
     "spl": S4_BASE + '\n| timechart span=1h avg(client_rtt) as avg_rtt\n| eval HourOfDay=strftime(_time,"%H")\n| eventstats avg(avg_rtt) as avg stdev(avg_rtt) as stdev by HourOfDay\n| eval lower_bound=avg-2*stdev, upper_bound=avg+2*stdev\n| table _time avg_rtt lower_bound upper_bound',
     "earliest": AUG1, "latest": SEP2,
     "views": [("outliers", "Outliers Chart（時間帯ごとの平均±2σ）")],
     "checks": ["目で見て明らかな異常点は、この手動の方法でもすべて拾えている",
                "一日の周期に沿わない点が他にもあり、それも外れ値として拾いたくなる。ここで ML の出番"],
     "refs": ["s79_0.jpg", "s80_0.jpg"]},
    {"id": "4-3", "tag": "Search 4-3", "title": "DensityFunction でモデルを学習（fit）", "pages": "P81",
     "body": ["時間帯ごとの平均 RTT に DensityFunction を学習させ、<code>rtt_df_model</code> として保存します。結果は Statistics（表）で確認します。"],
     "spl": S4_BASE + '\n| timechart span=1h avg(client_rtt) as avg_rtt\n| eval HourOfDay=strftime(_time,"%H")\n| fit DensityFunction avg_rtt by HourOfDay into rtt_df_model',
     "earliest": AUG1, "latest": SEP2,
     "views": [("table", "fit の出力")],
     "checks": ["<code>IsOutlier(avg_rtt)</code> 列が追加されている"],
     "refs": ["s81_0.jpg"]},
    {"id": "4-4", "tag": "Search 4-4", "title": "保存したモデルを適用（apply）", "pages": "P82",
     "body": ["<code>rtt_df_model</code> を apply して、ある時間の平均 RTT が異常かどうかを判定します。Search 4-3 を先に実行しておいてください。",
              "下段のグラフはシナリオ1の Search 1-6 と同じく、<code>IsOutlier(avg_rtt)</code> を Chart Overlay で重ねたものです。"],
     "spl": S4_BASE + '\n| timechart span=1h avg(client_rtt) as avg_rtt\n| eval HourOfDay=strftime(_time,"%H")\n| apply rtt_df_model',
     "earliest": AUG1, "latest": SEP2,
     "views": [("table", "Statistics（IsOutlier(avg_rtt) 列を確認）"),
               ("line", "Line Chart + Chart Overlay: IsOutlier(avg_rtt)", "IsOutlier(avg_rtt)", '| fields _time avg_rtt "IsOutlier(avg_rtt)"')],
     "checks": ["<code>IsOutlier(avg_rtt)</code> に 1.0 / 0.0 が入る",
                "このモデルを stream:tcp データへのスケジュール検索にすれば、ネットワーク遅延の異常な変化を継続して検知できる"],
     "refs": ["s82_0.jpg"]},
    outlier_gui("Search 4-3／4-4", S4_BASE + '\n| timechart span=1h avg(client_rtt) as avg_rtt\n| eval HourOfDay=strftime(_time,"%H")', "avg_rtt", "HourOfDay", "rtt_df_model", "Search 4-4"),
    text_row('<div class="aitk-step-head"><span class="aitk-tag aitk-tag-info">ブックマーク</span><h2>検索の内訳</h2>'
             '</div>' + breakdown([
                 (S4_BASE, "botsv2 の stream:tcp ログを検索する"),
                 ("… | timechart span=1h avg(client_rtt) as avg_rtt", "1時間ごとの平均クライアント RTT を求め、avg_rtt とする"),
                 ('… | eval HourOfDay=strftime(_time,"%H")', "_time から時（hour）を取り出し、HourOfDay とする"),
                 ("… | eventstats avg(avg_rtt) as avg stdev(avg_rtt) as stdev by HourOfDay", "時間帯ごとに平均 RTT の平均と標準偏差を求める"),
                 ("… | eval lower_bound=avg-2*stdev, upper_bound=avg+2*stdev", "平均と標準偏差から下限と上限を計算する"),
                 ("… | table _time avg_rtt lower_bound upper_bound", "時刻、平均 RTT、下限、上限の表を返す"),
                 ("… | fit DensityFunction avg_rtt by HourOfDay into rtt_df_model", "時間帯ごとの平均 RTT に DensityFunction を学習させ、rtt_df_model として保存する"),
                 ("… | apply rtt_df_model", "保存した rtt_df_model をデータに適用する"),
             ])),
    text_row('<div class="aitk-step-head"><span class="aitk-tag aitk-tag-info">振り返り</span><h2>Primer で使った手法</h2>'
             '</div>'
             '<div class="aitk-goals">'
             '<div><b>インサイダー脅威</b><span>ユーザーアクセスの異常</span><em>DensityFunction</em></div>'
             '<div><b>IT オペレーション</b><span>異常なログイン数</span><em>DensityFunction（元の資料では Anomaly Detection アプリ）</em></div>'
             '<div><b>インフラストラクチャ</b><span>CPU 使用率の予測</span><em>StateSpaceForecast</em></div>'
             '<div><b>すべて</b><span>使用率テレメトリの外れ値</span><em>DensityFunction</em></div>'
             '</div>'),
]
S4_INTRO = ('<div class="aitk-hero-text"><span class="aitk-kicker">AITK Security for Primer ／ シナリオ4</span>'
            '<h1>ネットワーク使用率テレメトリの外れ値を検知する</h1>'
            '<p>あなたは Frothly のアプリ開発者です。CPU 使用率の問題は片付いたのに、「アプリがときどき入力に反応しなくなる」という苦情が顧客から届いています。</p>'
            '<p>サービス間のラグの兆候を探すため、ネットワークを分析します。使うのは往復時間（RTT）、つまりリクエストが送信元から宛先へ行って戻ってくるまでの時間です。平均クライアント RTT を見れば、ネットワークの遅延がわかります。</p>'
            '<p class="aitk-flow">平均 RTT の推移 → 時間帯ごとの平均±2σ → DensityFunction で fit → apply</p></div>'
            + img("s75_0.png", "aitk-hero-icon"))

# ================================================================ Scenario 2 (AITK version)
S2_BASE = '| inputlookup numenta_art_daily_flatmiddle.csv\n| eval _time=strptime(timestamp,"%Y-%m-%d %H:%M:%S"), HourOfDay=strftime(_time,"%H")'
S2_ALL = 0  # inputlookup ignores the time range; table keeps 2014 rows only
s2 = [
    {"id": "2-1", "tag": "Search 2-1", "title": "データを時系列で見る",
     "body": ["シナリオ2で使うのは、Anomaly Detection アプリに入っているサンプルデータ <code>numenta_art_daily_flatmiddle.csv</code> です。2014/4/1〜4/14 の5分刻み、4,032点の数値が入っています。",
              "このルックアップには <code>_time</code> が無く、時刻は文字列の <code>timestamp</code> 列にあります。そこで <code>strptime</code> で <code>_time</code> を作ってから、時系列として扱います。",
              "最後を <code>timechart</code> ではなく <code>table</code> にしているのは、timechart が時間範囲の終わり（今日）まで空の枠を作り、2014年のデータがグラフの左端に潰れてしまうからです。"],
     "spl": S2_BASE + "\n| table _time value",
     "earliest": "-24h", "latest": "now",
     "views": [("line", "value の推移（5分刻み）")],
     "checks": ["毎日ほぼ同じ形で、−22 前後と 88 前後の間を上下している",
                "<b>4/11 だけ</b>、丸一日ほぼ 40 のまま平らになっている。これが今回見つけたい異常"]},
    {"id": "2-2", "tag": "Search 2-2", "title": "DensityFunction の外れ値を折れ線グラフで目立たせる",
     "body": ["時間帯（HourOfDay）ごとに DensityFunction を当て、外れ値と判定された点だけを <code>outlier_value</code> という別の列に入れます。"
              "外れ値でない点は null にするので、折れ線グラフでは外れ値の区間だけが赤い線になります（null の扱いを「ギャップ」にしています）。",
              "時間帯で分けるのが大事です。40 という値は、ふだんの波の範囲（−22〜88）にふつうに入っているので、時間帯で分けずに fit すると外れ値は1つも出ません。"
              "「値の大きさは普通でも、その時間帯に出るはずのない値」を探すために <code>by HourOfDay</code> を付けます。"],
     "spl": S2_BASE + "\n| fit DensityFunction value by HourOfDay\n| eval outlier_value=if('IsOutlier(value)'=1, value, null())\n| table _time value outlier_value",
     "earliest": "-24h", "latest": "now",
     "views": [("line_outlier", "value（青）と outlier_value（赤）")],
     "checks": ["赤い線が出るのは 4/11 だけ。他の日には外れ値が出ない",
                "ただし赤くなるのは 4/11 の<b>一部</b>だけ（検証では 60〜84点、平らな区間は288点）。実行するたびに数が少し変わる",
                "一部しか赤くならないのは、<code>dist=auto</code> が時間帯によって山が2つある分布などを選び、その中に 40 が収まってしまう時間帯があるから。次の Search 2-3 で直す"]},
    {"id": "2-3", "tag": "Search 2-3", "title": "dist=norm にして Outliers Chart で見る",
     "body": ["分布を正規分布に固定（<code>dist=norm</code>）すると、各時間帯の「ふだんの範囲」が1本の帯になります。"
              "DensityFunction が出す <code>BoundaryRanges</code>（外れ値とする範囲）も必ず「−Infinity〜下限」と「上限〜Infinity」の2つになるので、そこから下限と上限を取り出せば Outliers Chart で表示できます。"],
     "spl": S2_BASE + '\n| fit DensityFunction value by HourOfDay dist=norm\n| eval lower_bound=tonumber(mvindex(split(mvindex(BoundaryRanges,0),":"),1)), upper_bound=tonumber(mvindex(split(mvindex(BoundaryRanges,-1),":"),0))\n| table _time value lower_bound upper_bound',
     "earliest": "-24h", "latest": "now",
     "views": [("outliers", "Outliers Chart（時間帯ごとの正規分布の境界）")],
     "checks": ["外れ値の数（チャート右側）が 288。4/11 の丸一日分（5分×288）とちょうど一致し、他の日は0",
                "4/11 の帯は 40 から大きく外れた位置にある（例：0時台は −55.7〜24.2）",
                "Search 2-2（dist=auto）と違い、何度実行しても同じ結果になる"]},
    text_row('<div class="aitk-step-head"><span class="aitk-tag aitk-tag-info">解説</span><h2>チューニングの方法</h2></div>'
             '<p>DensityFunction で「ちょうどよく」外れ値を拾うために調整できるのは、主に次の5つです。上から順に効き目が大きいと考えてください。</p>'
             '<table class="aitk-table"><thead><tr><th>何を変えるか</th><th>書き方</th><th>効果と目安</th></tr></thead><tbody>'
             '<tr><td><b>1. 分け方（by）</b></td><td><code>by HourOfDay</code>、<code>by Slot</code>（5分ごと）、<code>by DayOfWeek</code> など</td>'
             '<td>「ふだん」をどの単位で決めるか。周期のあるデータでは最も効く。細かく分けるほど敏感になるが、1グループの点が減る（推奨は50点以上。HourOfDay は1グループ168点、5分ごとは14点）</td></tr>'
             '<tr><td><b>2. 分布の形（dist）</b></td><td><code>dist=auto</code>（既定）／<code>norm</code>／<code>expon</code>／<code>gaussian_kde</code>／<code>beta</code>、<code>exclude_dist=…</code></td>'
             '<td>auto はグループごとに最も合う形を選ぶが、山が2つある時間帯では異常値まで「ありうる」と判断することがある。範囲を1本の帯で見たいときや結果を安定させたいときは norm。auto のまま特定の形だけ外すなら exclude_dist</td></tr>'
             '<tr><td><b>3. しきい値（threshold）</b></td><td><code>threshold=0.01</code>（既定）、<code>lower_threshold</code>／<code>upper_threshold</code></td>'
             '<td>分布の端の何割を外れ値にするか。小さくすると外れ値が減り、大きくすると増える。下がる異常だけ見たいなら lower_threshold、上がる異常だけなら upper_threshold</td></tr>'
             '<tr><td><b>4. 集計の粒度</b></td><td>fit の前に <code>| timechart span=1h avg(value)</code> など</td>'
             '<td>5分ごとの細かい揺れを均して、1時間単位の傾向で判定する。ノイズは減るが、短い異常は見えにくくなり、学習に使える点も減る</td></tr>'
             '<tr><td><b>5. 判定後のルール</b></td><td><code>| streamstats</code> で連続回数を数える</td>'
             '<td>「12点（1時間）以上続いたら通知」のように、単発の外れ値を無視する。アラートの誤報を減らすのに効く</td></tr>'
             '</tbody></table>'
             '<h4 style="margin:14px 0 4px;">このデータで試した結果</h4>'
             '<table class="aitk-table"><thead><tr><th>分け方</th><th>dist</th><th>threshold</th><th>外れ値の数</th><th>うち 4/11</th><th>他の日</th></tr></thead><tbody>'
             '<tr><td>なし</td><td>auto</td><td>0.01</td><td>0</td><td>0</td><td>0</td></tr>'
             '<tr><td>HourOfDay</td><td>auto</td><td>0.01</td><td>60（実行ごとに変わる）</td><td>60</td><td>0</td></tr>'
             '<tr><td>HourOfDay</td><td>norm</td><td>0.01</td><td><b>288</b></td><td>288</td><td>0</td></tr>'
             '<tr><td>HourOfDay</td><td>norm</td><td>0.001</td><td>264</td><td>264</td><td>0</td></tr>'
             '<tr><td>HourOfDay</td><td>norm</td><td>0.05</td><td>288</td><td>288</td><td>0</td></tr>'
             '<tr><td>5分ごと（Slot）</td><td>norm</td><td>0.01</td><td>288</td><td>288</td><td>0</td></tr>'
             '<tr><td>5分ごと（Slot）</td><td>auto</td><td>0.01</td><td>182</td><td>182</td><td>0</td></tr>'
             '</tbody></table>'
             + ul(["分け方を入れない限り、何をしても見つからない。<b>まず by を決める</b>のが最初の一手",
                   "このデータは異常がはっきりしているので、norm にすれば threshold を 0.001〜0.05 の間で動かしても誤検知（他の日の外れ値）は出なかった。実データでは threshold を上げると誤検知が増えるので、過去のインシデントで確かめながら決める",
                   "連続回数のルールを入れると、HourOfDay＋auto では外れ値が4つの塊に分かれ（最長24点）、HourOfDay＋norm では288点の1つの塊になった。どちらも「12点以上続く」条件で 4/11 を拾える"]) +
             '<p class="aitk-note">次の Search 2-4 で、表の設定を自分で変えて試せます。</p>'),
    {"id": "2-4", "tag": "Search 2-4", "title": "設定を変えて外れ値の数を比べる",
     "body": ["分け方・dist・threshold を変えた fit を並べて実行し、外れ値の数と、そのうち 4/11 以外（誤検知）の数を比べます。"
              "Search で開いて、<code>fit</code> の行の引数を書き換えれば、自分で別の設定も試せます。"],
     "spl": '| inputlookup numenta_art_daily_flatmiddle.csv\n| eval _time=strptime(timestamp,"%Y-%m-%d %H:%M:%S"), HourOfDay=strftime(_time,"%H")\n'
            '| fit DensityFunction value by HourOfDay | eval setting="by HourOfDay dist=auto threshold=0.01"\n'
            '| append [| inputlookup numenta_art_daily_flatmiddle.csv | eval _time=strptime(timestamp,"%Y-%m-%d %H:%M:%S"), HourOfDay=strftime(_time,"%H") | fit DensityFunction value by HourOfDay dist=norm | eval setting="by HourOfDay dist=norm threshold=0.01"]\n'
            '| append [| inputlookup numenta_art_daily_flatmiddle.csv | eval _time=strptime(timestamp,"%Y-%m-%d %H:%M:%S"), HourOfDay=strftime(_time,"%H") | fit DensityFunction value by HourOfDay dist=norm threshold=0.001 | eval setting="by HourOfDay dist=norm threshold=0.001"]\n'
            '| append [| inputlookup numenta_art_daily_flatmiddle.csv | eval _time=strptime(timestamp,"%Y-%m-%d %H:%M:%S") | fit DensityFunction value | eval setting="分けない dist=auto threshold=0.01"]\n'
            '| eval o=\'IsOutlier(value)\', day=substr(timestamp,1,10)\n'
            '| stats sum(o) as "外れ値の数" sum(eval(if(day="2014-04-11",o,0))) as "うち 4/11" by setting\n'
            '| eval "他の日（誤検知）"=\'外れ値の数\'-\'うち 4/11\'',
     "earliest": "-24h", "latest": "now",
     "views": [("table", "設定ごとの外れ値の数")],
     "checks": ["dist=norm（threshold=0.01）は 288 で、すべて 4/11",
                "分けない設定は 0。by の効き目がいちばん大きい",
                "threshold=0.001 は 264 に減る。異常の始まりと終わりの一部が「ありうる範囲」に入るため"]},
    {"id": "2-5", "tag": "Search 2-5", "title": "連続して外れた区間だけを拾う（アラート向け）",
     "body": ["実際にアラートにするときは、単発の外れ値で毎回通知すると誤報が増えます。"
              "外れ値が何点続いたかを数え、12点（1時間）以上続いた区間だけを「異常な区間」として取り出します。"],
     "spl": S2_BASE + "\n| fit DensityFunction value by HourOfDay dist=norm\n| eval o='IsOutlier(value)'\n| sort 0 _time\n"
            "| streamstats reset_on_change=true count as run_length by o\n| where o=1\n"
            "| streamstats count(eval(run_length=1)) as run_id\n"
            '| stats min(_time) as start max(_time) as end max(run_length) as points by run_id\n'
            '| where points>=12\n| eval start=strftime(start,"%Y-%m-%d %H:%M"), end=strftime(end,"%Y-%m-%d %H:%M"), minutes=points*5\n'
            "| table run_id start end points minutes",
     "earliest": "-24h", "latest": "now",
     "views": [("table", "12点以上続いた異常な区間")],
     "checks": ["2014-04-11 00:00〜23:55 の288点（1440分）が1つの区間として出る",
                "fit の行を <code>by HourOfDay</code>（dist=auto）に戻すと、4/11 の中で区間が4つに分かれ、最長は24点になる"]},
]
S2_INTRO = ('<div class="aitk-hero-text"><span class="aitk-kicker">AITK Security for Primer ／ シナリオ2</span>'
            '<h1>ユーザーログイン数の異常を検知する</h1>'
            '<p>あなたは Frothly の IT 管理者です。ふだんと違うユーザーログインを見つけて調べるよう任されました。'
            'ふだんの動きからの大きなずれは、新しいシステム障害や IT インフラのエラー、あるいはセキュリティ上の脅威が原因かもしれません。</p>'
            '<p>元の資料では、このシナリオを Splunk App for Anomaly Detection で行っています。ただしこのアプリは 2025年6月でサポートが終わり、Splunk 10 では古い検索 API（v1）を使う部分が動きません。'
            'そこでここでは、同じデータを AI Toolkit の DensityFunction で調べます。</p>'
            '<p class="aitk-flow">データを見る → 外れ値を折れ線で目立たせる → dist=norm で Outliers Chart → チューニング → 連続区間でアラート</p></div>'
            + img("s34_0.png", "aitk-hero-icon"))


# ================================================================ Primer summary (P20-30)
PRIMER_SUMMARY = f'''
<div class="aitk-doc">
<header class="aitk-doc-hero">
  <span class="aitk-kicker">AITK Security for Primer ／ Summary</span>
  <h1>機械学習の前に知っておくこと</h1>
  <p>Splunk4Rookies Machine Learning Workshop の導入部分をまとめたページです。ハンズオンに入る前に、ML とは何か、なぜデータ準備が大事か、今日使う環境とデータを確認します。</p>
</header>

<section>
  <h2>機械学習とは</h2>
  <p class="aitk-lead">パターンを抽出することで、システムが自ら知識を獲得する能力。</p>
  <div class="aitk-cols3">
    <div class="aitk-card"><b>パターンを見つける</b><p>複雑な統計モデルや確率モデルを使い、情報の中のパターンを特定する。</p></div>
    <div class="aitk-card"><b>パターンを蓄える</b><p>見つけたパターンをカタログ化する。新しいデータを受け取るたびに繰り返し更新することもある。</p></div>
    <div class="aitk-card"><b>パターンを使う</b><p>学習したパターンを使って、新しいデータを理解・解釈したり、予測したりする。</p></div>
  </div>
  <p>説明の仕方は他にもいくらでもありますが、どれにも共通する前提が1つあります。良いデータがなければ、そこから導いた答えは間違っているかもしれない、ということです。</p>
</section>

<section>
  <h2>データサイエンティストが実際にやっていること</h2>
  <div class="aitk-split">
    <div>{img("s22_0.png", "aitk-fig")}</div>
    <div>
      <p class="aitk-big">約80%</p>
      <p>データサイエンティストの作業時間のおよそ8割は、検索や分析を始める前の段階、つまりデータの収集と並べ替え、クレンジング、整形に使われています。</p>
      <p>Forbes の調査（2023年3月）でも、ビッグデータのクレンジングは「いちばん時間がかかり、いちばん楽しくない」作業として挙がっています。それでも彼らは、この工程を飛ばせないことを知っています。</p>
      <ul class="aitk-legend">
        <li><i style="background:#004660"></i>データのクレンジングと整理</li>
        <li><i style="background:#ff7033"></i>データセットの収集</li>
        <li><i style="background:#1e7684"></i>パターンを探すデータマイニング</li>
        <li><i style="background:#0f42a8"></i>アルゴリズムの改良</li>
        <li><i style="background:#5390ab"></i>トレーニングセットの作成</li>
      </ul>
    </div>
  </div>
</section>

<section>
  <h2>今日の環境</h2>
  <p>今日はその準備をこちらで済ませてあります。持ち帰ってすぐ使えるクイックウィンに集中してください。データ準備の重要な工程は、AI Toolkit を本格的に掘り下げる後続のワークショップ（Rookies／Ninja）で扱います。</p>
</section>

<section>
  <h2>ハンズオンで使うツールとデータ</h2>
  <p>このワークショップ用に、Splunk インスタンスへ次のアプリとデータを入れてあります。自分の環境で同じ演習をする場合も、これらを揃えてください。アプリとアドオンは Splunkbase、BOTS v2 データセットは Splunk の Git リポジトリから無料で入手できます。</p>
  <div class="aitk-tools">
    <div>{img("s27_0.png", "aitk-tool-ic")}<b>AI Toolkit（旧 Machine Learning Toolkit / MLTK）</b><span>fit / apply などの ML-SPL コマンドと可視化</span></div>
    <div>{img("s27_1.png", "aitk-tool-ic")}<b>Python for Scientific Computing（PSC）</b><span>AI Toolkit が使う Python ライブラリ群</span></div>
    <div>{img("s27_2.png", "aitk-tool-ic")}<b>Splunk App for Anomaly Detection</b><span>ML の知識なしで異常検知ジョブを作れるアプリ</span></div>
    <div>{img("s27_4.png", "aitk-tool-ic")}<b>BOTS v2 データセット（フル）</b><span>index=botsv2。2017年8月のデータ</span></div>
    <div>{img("s27_3.png", "aitk-tool-ic")}<b>Splunk Add-on for Microsoft Windows</b><span>Windows イベントログのフィールド抽出</span></div>
  </div>
</section>

<section>
  <h2>Splunk インスタンスにログインする</h2>
  <div class="aitk-split">
    <div>{img("s28_0.png", "aitk-fig")}</div>
    <div>
      <p>インスタンスの URL と認証情報は、Splunk Show のイベントページ（show.splunk.com）の Instances information に表示されます。講師が用意した環境を使う場合は、案内された URL とアカウントでログインしてください。</p>
      {img("s28_1.png", "aitk-fig aitk-fig-sm")}
    </div>
  </div>
</section>

<section>
  <h2>舞台設定：Frothly</h2>
  <div class="aitk-split">
    <div>
      <p class="aitk-lead">ただの「いななき（a neigh）」じゃない古いビール ― A Buttercup Company</p>
      <p>今日扱うデータはすべて、Splunk のセキュリティスタッフが設計・構築した実在のネットワークから取ったものです。性能やセキュリティの問題が起きうる経路について仮説を立て、それが実際に起きる状況を作っています。作り物の中では、実際の企業ネットワークにいちばん近いデータです。</p>
      <p>舞台はクラフトビール会社 Frothly（Buttercup Games のグループ会社）です。</p>
    </div>
    <div class="aitk-frothly">{img("s29_2.png", "aitk-logo")}{img("s29_3.png", "aitk-fig")}</div>
  </div>
  {img("s29_1.png", "aitk-fig aitk-fig-wide")}
</section>

<section>
  <h2>Frothly のネットワーク</h2>
  <div class="aitk-net">
    <div class="aitk-net-zone aitk-net-inet">インターネット</div>
    <div class="aitk-net-arrow">⇅</div>
    <div class="aitk-net-zone aitk-net-dmz"><b>DMZ</b>
      <div class="aitk-net-nodes"><span>Suricata NIDS</span><span>Web サーバー（IIS）</span><span>SMTP</span></div>
      <small>Splunk Stream で DMZ セグメントのトラフィックを取得</small></div>
    <div class="aitk-net-arrow">⇅ FortiGate ファイアウォール</div>
    <div class="aitk-net-zone aitk-net-int"><b>内部ネットワーク</b>
      <div class="aitk-net-nodes"><span>Active Directory</span><span>クライアントワークステーション</span><span>ファイルサーバー</span><span>汎用サーバー（Linux）×2</span><span>MySQL DB サーバー</span><span>Splunk インデクサー（IDX）</span></div></div>
  </div>
  <h3>主な sourcetype と収集方法</h3>
  <table class="aitk-table">
    <thead><tr><th>データ</th><th>収集方法</th><th>使うシナリオ</th></tr></thead>
    <tbody>
      <tr><td>IIS サーバーの Sysmon と <code>wineventlog:security</code></td><td>Universal Forwarder で転送</td><td>シナリオ1</td></tr>
      <tr><td>FortiGate のファイアウォールトラフィックログ</td><td>Splunk が syslog を受信</td><td>―</td></tr>
      <tr><td>Suricata の IDS アラートログ</td><td>Linux の Forwarder で転送</td><td>―</td></tr>
      <tr><td>DMZ のネットワークトラフィック（<code>stream:tcp</code> など）</td><td>Splunk Stream</td><td>シナリオ4</td></tr>
      <tr><td>Windows の性能カウンター（<code>perfmon:cpu</code>）</td><td>Universal Forwarder で転送</td><td>シナリオ3</td></tr>
    </tbody>
  </table>
  <p>エンドポイントのデータがあると、ネットワーク側のログだけでは見えない「その端末で何が動いたか」まで追えます。</p>
  {img("s30_0.png", "aitk-fig aitk-fig-chars")}
</section>

<footer class="aitk-next">
  <b>次はハンズオン</b>
  <a href="primer_s1">シナリオ1 ユーザーアクセスの異常 →</a>
  <a href="primer_s2">シナリオ2 ログイン数の異常 →</a>
  <a href="primer_s3">シナリオ3 CPU 使用率の予測 →</a>
  <a href="primer_s4">シナリオ4 ネットワークテレメトリの外れ値 →</a>
</footer>
</div>
'''

# ================================================================ Rookies
RK_ALL = {"earliest": "0", "latest": "now"}
RK_RANGE_LOGINS = "指定なし（inputlookup は時間範囲に関係なく logins.csv の全データ、2015/11/1〜12/1 の1時間ごと708行を読む）"
RK_RANGE_FW = "指定なし（inputlookup は時間範囲に関係なく firewall_traffic.csv を読む）"
RK_MAD = ("| inputlookup logins.csv\n| eventstats median(logins) as median\n| eval absDev=abs(logins-median)\n"
          "| eventstats median(absDev) as medianAbsDev\n")
RK_FEATS = "bytes_received bytes_sent dest_port dst_ip has_known_vulnerability packets_received packets_sent"
RK_TRAIN = "| inputlookup firewall_traffic.csv\n| head 50000\n| sample partitions=100 seed=1234\n| where partition_number<70\n"
RK_TEST = "| inputlookup firewall_traffic.csv\n| head 50000\n| sample partitions=100 seed=1234\n| where partition_number>=70\n| apply example_malware"
RK_PRED = '"predicted(used_by_malware)"'
RK_SCORE_VIEWS = [
    ("table", "適合率・再現率・F1（重み付き平均）", None,
     f'| score precision_recall_fscore_support used_by_malware against {RK_PRED} average=weighted | rename precision as "Precision（適合率）" recall as "Recall（再現率）" fbeta_score as "F1" | table "Precision（適合率）" "Recall（再現率）" "F1"'),
    ("table", "Accuracy（正解率）", None, f"| score accuracy_score used_by_malware against {RK_PRED} | table accuracy_score"),
    ("table", "混同行列（0＝no、1＝yes）", None, f"| score confusion_matrix used_by_malware against {RK_PRED}"),
]
RK_DETECT = ('| inputlookup firewall_traffic.csv\n| head 50000\n| apply example_malware\n'
             "| where 'predicted(used_by_malware)'=\"yes\"\n"
             "| stats count as sessions dc(src_ip) as src_count sum(bytes_sent) as bytes_sent sum(bytes_received) as bytes_received by dst_ip dest_port\n"
             "| sort - sessions\n| head 10")
EXPLAIN.update({
    "r1-1": [
        ("| inputlookup logins.csv", "AI Toolkit に入っているサンプル（このアプリにも同じものを同梱）を読む。1時間ごとのログイン数が logins 列に入っている"),
        ("| table _time logins", "折れ線グラフ用に時刻と値の2列だけにする"),
    ],
    "r1-3": [
        ("| inputlookup logins.csv", "Search 1-1 と同じ。1時間ごとのログイン数を読む"),
        ("| predict logins as prediction", "logins の予想値を計算し、列名を prediction にする。95%の予測区間 <code>upper95(prediction)</code>／<code>lower95(prediction)</code> の列も一緒に付く"),
        ("algorithm=LLP", "周期（季節性）のある時系列向けの方式で予想する。周期の長さは自動で見つける。下の表を参照"),
        ("future_timespan=150", "最後のデータ（12/1 06:00）の後に、150点（1時間刻みなので150時間、12/7 12:00 まで）先の予想の行を足す。この演習では使わず、次の where で消える"),
        ("holdback=0", "最後から何点を予想の学習に使わないか。0 なので全データを使う。たとえば holdback=24 にすると最後の1日を除いて学習し、その1日の予想と実測を見比べて答え合わせできる"),
        ('| where prediction!="" AND logins!=""', "future_timespan で足した未来の150行（logins が空）を落とし、実測と予想の両方がある708行だけにする"),
        ("| eval residual = prediction - logins", "予想−実測。0 付近ならいつもどおり。マイナスは予想より多かった、プラスは予想より少なかったことを表す"),
    ],
    "r2-2": [
        ("| inputlookup firewall_traffic.csv | head 50000", "ファイアウォールの通信記録（約9.9万行）の先頭5万行を読む。資料の Showcase と同じ範囲"),
        ("下段：| stats count by used_by_malware", "当てたいラベル used_by_malware の内訳。yes が約6割"),
        ("下段：| stats dc(…) as … | transpose", "フィールドごとに値の種類がいくつあるかを数え、縦に並べる"),
    ],
    "r2-3": [
        ("| sample partitions=100 seed=1234", "各行に 0〜99 の partition_number をランダムに振る。seed を固定すると毎回同じ振り分けになる"),
        ("| where partition_number<70", "70%を学習用に残す。残りの30%（70〜99）は Search 2-4 の答え合わせに取っておく"),
        ("| fit LogisticRegression fit_intercept=true used_by_malware from … into example_malware",
         "<code>from</code> の後ろの7項目から used_by_malware（yes/no）を当てるモデルを学習し、example_malware として保存する。fit_intercept=true は切片も推定する指定（GUI の estimate the intercept）"),
    ],
    "r2-4": [
        ("| where partition_number>=70", "学習に使わなかった30%だけを残す"),
        ("| apply example_malware", "保存したモデルで予測し、<code>predicted(used_by_malware)</code> 列を足す"),
        ('下段：| score precision_recall_fscore_support … average=weighted', "正解（used_by_malware）と予測を比べ、適合率・再現率・F1 を yes と no の件数で重み付けした平均で出す。Experiment の画面に出る数字と同じ計算"),
        ("下段：| score accuracy_score …", "全体のうち予測が当たった割合"),
        ("下段：| score confusion_matrix …", "実際（行）と予測（列）の組み合わせごとの件数。ラベルは文字の順に 0＝no、1＝yes になる"),
    ],
    "r2-5": [
        ("| fit RandomForestClassifier used_by_malware from … random_state=42 into example_malware",
         "アルゴリズムだけを RandomForestClassifier（決定木をたくさん作って多数決する方式）に変えて学習し直し、同じ名前で上書きする。random_state を固定すると毎回同じ森ができる"),
    ],
    "r2-7": [
        ("| summary example_malware", "RandomForestClassifier のモデルを読み込み、各入力がどれだけ判定に効いたか（feature importance、合計1）を出す"),
    ],
    "r2-8": [
        ("| inputlookup firewall_traffic.csv | head 50000 | apply example_malware", "資料と同じ。学習し直さずに、保存したモデルで5万行すべてを判定する"),
        (f"| stats count by used_by_malware {RK_PRED}", "実際と予測の組み合わせで数える"),
    ],
    "r3-1": [
        ("| inputlookup firewall_traffic.csv | head 50000", "演習2と同じ5万行を読む"),
        ("| apply example_malware", "演習2の Search 2-5 で保存した RandomForestClassifier のモデルを当て、predicted(used_by_malware) の列を足す"),
        ("| table *time *", "名前が time で終わる列（receive_time）を先頭に、残りのすべての列を並べる"),
    ],
    "r3-2": [
        ("| inputlookup firewall_traffic.csv | head 50000 | apply example_malware", "資料の検知サーチと同じ前半"),
        ("| where 'predicted(used_by_malware)'=\"yes\"", "マルウェアと予測した通信だけを残す。括弧付きの列名は where の中ではシングルクォートで囲む"),
        ("| stats count as sessions dc(src_ip) as src_count … by dst_ip dest_port",
         "宛先とポートの組ごとにまとめる。資料のままだと予測 yes の約3万行がそのまま3万件の Finding になってしまうので、調べる単位にまとめてから出す"),
        ("| sort - sessions | head 10", "通信の多い上位10組だけを Finding にする"),
    ],
})

r1 = [
    {"id": "r1-1", "tag": "Search 1-1", "title": "ログイン数のデータを見る",
     "body": ["演習1で使うのは、AI Toolkit のサンプル <code>logins.csv</code> です。2015/11/1〜12/1 の1時間ごとのログイン数が708行入っています。"
              "このルックアップは AI Toolkit アプリの中にしか見えないので、このアプリにも同じファイルを入れてあります。",
              "GUI では、AI Toolkit アプリのメニューの <b>Support → Showcase → Detect Outliers</b> から、<b>Detect Outliers in Number of Logins (vs. Predicted Value)</b> を選択してください。predict を使った既定の設定が入った状態で開きます（次の GUI 1-2 で設定を変えます）。ここでは先に、データそのものを折れ線で見ておきます。"],
     "spl": "| inputlookup logins.csv\n| table _time logins", **RK_ALL, "range_note": RK_RANGE_LOGINS,
     "views": [("line", "1時間ごとのログイン数")],
     "checks": ["毎日ほぼ同じ時刻に山がある。日本時間で表示すると、山は0〜6時ごろ（火〜土の1〜4時の平均は 300〜370）、谷は15〜21時ごろ（70〜90）。元のデータが別のタイムゾーンの昼間に記録されているため、日本時間では山が夜中に来る",
                "日曜（11/1、8、15、22、29）は1日中 100 以下で平ら。11/27〜28 も低い",
                "いちばん右の 12/1 には、期間でいちばん高い 540 の山がある"]},
    {"id": "r1-2", "tag": "GUI 1-2", "title": "Showcase の画面で、ログイン数に MAD を当てる（倍率を変えて試す）",
     "body": ["Search 1-1 の説明のとおり Showcase の <b>Detect Outliers in Number of Logins (vs. Predicted Value)</b> を開くと、Detect Numeric Outliers の画面になります。"
              "開いた直後は、predict でログイン数の予想値を作り、予想との差で外れ値を探す既定の設定で自動的に実行されます（外れ値 61）。",
              "資料では、ここで設定を変えて、ログイン数そのものの外れ値を探します。画面で次のとおりに変えてください。"],
     "extra_html": ('<table class="aitk-table"><thead><tr><th style="width:34%;">画面の項目</th><th>設定</th></tr></thead><tbody>'
                    '<tr><td><b>Enter a search</b>（入力欄）</td><td><code>| inputlookup logins.csv</code> より後ろを消し、右の虫眼鏡で検索し直す</td></tr>'
                    '<tr><td><b>Field to analyze</b></td><td>logins</td></tr>'
                    '<tr><td><b>Threshold method</b></td><td>Median Absolute Deviation</td></tr>'
                    '<tr><td><b>Threshold multiplier</b></td><td>9</td></tr>'
                    '<tr><td><b>Sliding window</b></td><td>空にする（全期間で1つの範囲を作る）</td></tr>'
                    '</tbody></table>'
                    '<p>設定したら <b>Detect Outliers</b> を押します。続けて <b>Threshold multiplier</b> だけを 7.7、6.5、5 と変えて、そのたびに Detect Outliers を押し、グラフ右側の外れ値の数を見ます。</p>'
                    '<table class="aitk-table aitk-table-fixed"><thead><tr><th style="width:9%;">倍率</th><th style="width:15%;">範囲（上限）</th><th style="width:10%;">外れ値</th><th>何が外れ値になるか</th></tr></thead><tbody>'
                    '<tr><td>9</td><td>−361〜557</td><td>0</td><td>どの山も上限に届かない</td></tr>'
                    '<tr><td>7.7</td><td>−295〜491</td><td>4</td><td>期間でいちばん高い山（11/3 03:00 の 493、12/1 01:00〜03:00 の 508〜540）。資料が「ちょうどよい」とした値</td></tr>'
                    '<tr><td>6.5</td><td>−233〜430</td><td>9</td><td>高めの山（11/17、11/24、12/1 など）</td></tr>'
                    '<tr><td>5</td><td>−157〜353</td><td>57</td><td>ふだんの山（日本時間の0〜6時）が、ほぼ毎日外れ値になる。資料の「多すぎ」</td></tr>'
                    '</tbody></table>'
                    '<h4 style="margin:14px 0 4px;">なぜ結局、倍率は 9 のままにするのか</h4>'
                    '<ol>'
                    '<li><b>倍率を変えても、見ているのは「山が高いかどうか」だけ</b>：倍率を下げるほど、ふだんの山が外れ値になります。上げるほど、何も出なくなります。7.7 で出る4点も、いつもの山の時間帯に、いつもより高かった点です</li>'
                    '<li><b>原因は倍率ではなく、範囲が全期間で1本しかないこと</b>：ログインの多い時間帯（日本時間の0〜6時）の値も、少ない時間帯（15〜21時）の値も、同じ上限で判定しています。ふだん 80 しかない時間帯に 400 になっても、上限を超えない限り見つかりません</li>'
                    '<li><b>だから倍率は Showcase の既定の 9 に戻し、見る対象のほうを変える</b>：predict で「その時刻ならこれくらい」という予想を作り、予想とのずれ（residual）に同じ MAD×9 を当てます。時間帯の波は予想のほうに入るので、倍率を細かく合わせ込まなくても、その時刻としておかしい点が残ります（Search 1-3、GUI 1-4）</li>'
                    '</ol>'
                    '<p>運用するときは、どの設定でも、グラフの下の <b>Open in Search</b> で SPL を開いて保存済みサーチにするか、<b>Schedule Alert</b> でアラートにできます。この画面は fit を使わないので、保存するモデルはありません。演習2では、モデルを保存して Publish してから使う点が違います。</p>'
                    '<p class="aitk-note">画面の設定に合わせて、裏で SPL が生成されます。<b>Show SPL</b> を押すと、生成された SPL を見られます。</p>'),
     "refs": ["r100_0.png", "r103_0.png", "r104_0.png", "r105_0.png", "r106_0.png"],
     "checks": ["倍率 9 で外れ値は <b>0</b>。帯（ふだんの範囲）は −361〜557 で、どの山も上限に届かない",
                "倍率を 7.7、6.5、5 にすると、外れ値が 4、9、57 と増える",
                "全期間の中央値は 98、MAD は 51。ログインの少ない時間帯が1日の半分以上あるので、中央値は山よりずっと低い"]},
    {"id": "r1-3", "tag": "Search 1-3", "title": "Showcase の既定の SPL：predict で予想を作り、ずれを見る",
     "body": ["Showcase を開いたときに入力欄に入っている、既定の SPL です。GUI 1-2 で消した部分を戻したものにあたります。",
              "<b>なぜこうするのか。</b>GUI 1-2 のようにログイン数そのものに1本の範囲を当てると、ログインの多い時間帯の 400 も、少ない時間帯の 400 も、同じ上限で判定します。"
              "でも本当に怪しいのは、ふだんは 70〜90 しかない時間帯に 400 あるような「その時刻としてはおかしい」値です。"
              "そこで <code>predict</code> で「この時刻ならこれくらい」という予想値を作り、予想と実測の差（<code>residual</code>）を見ます。"
              "1日や1週間の波は予想に含まれるので、residual には波を差し引いた「いつもとのずれ」だけが残ります。周期を考えた予想が1行で作れるのが predict の便利なところです。"],
     "extra_html": ('<h4 style="margin:14px 0 4px;">algorithm の選択肢</h4>'
                    '<table class="aitk-table aitk-table-fixed"><thead><tr><th style="width:12%;">algorithm</th><th>どんなモデルか</th><th style="width:30%;">この演習のデータで試すと</th></tr></thead><tbody>'
                    '<tr><td><code>LL</code></td><td>ローカルレベル。傾き（トレンド）も周期も考えない、いちばん単純な1系列のモデル。2点以上あれば使える</td><td>予想が実測とほぼ同じになり、residual がほぼ 0（平均のずれ 0）。外れ値を探す材料にならない</td></tr>'
                    '<tr><td><code>LLT</code></td><td>ローカルレベル＋トレンド。傾きは考えるが、周期は考えない</td><td>平均のずれ 0.23。LL と同じく residual がほぼ 0</td></tr>'
                    '<tr><td><code>LLP</code></td><td>周期のあるローカルレベル（季節性モデル）。周期の長さは period= で指定するか、自動で見つける。周期が見つからないデータでは data is not periodic のエラーになる</td><td><b>この演習で使う。</b>平均のずれ 8.3。1日と1週間の波から予想するので、いつもとのずれが residual に残る</td></tr>'
                    '<tr><td><code>LLP5</code>（既定）</td><td>LLT と LLP を組み合わせる。周期があれば両方の予想の重み付き平均を取る。algorithm を省略するとこれになる</td><td>平均のずれ 0.48。この使い方では residual がほぼ 0 になった</td></tr>'
                    '<tr><td><code>LLB</code></td><td>2系列のモデル。片方の系列を使って、もう片方を予想する（correlate= が必要）</td><td>ログイン数の1系列だけなので使えない</td></tr>'
                    '<tr><td><code>BiLL</code></td><td>2系列のモデル。2つの系列を、互いの関係を考えながら同時に予想する</td><td>同上</td></tr>'
                    '</tbody></table>'
                    '<p class="aitk-note">「平均のずれ」は、708行の |residual| の平均です。この環境で algorithm だけを変えて測りました。LLP 以外では、すでに起きた点の予想が実測とほぼ同じ値になり、residual がほぼ 0 になりました。いつもの波と比べるという目的には LLP が合っています。</p>'
                    '<p>実行したら、Showcase の画面（Detect Numeric Outliers）の <b>Enter a search</b> にこの SPL を入れて検索し、<b>Detect Outliers</b> をクリックして結果を確認します。画面の各項目の設定は、次の GUI 1-4 で説明します。</p>'),
     "spl": ("| inputlookup logins.csv\n| predict logins as prediction algorithm=LLP future_timespan=150 holdback=0\n"
             '| where prediction!="" AND logins!=""\n| eval residual = prediction - logins'),
     **RK_ALL, "range_note": RK_RANGE_LOGINS,
     "views": [("line", "logins（実測）と prediction（予想）", None, "| table _time logins prediction"),
               ("line", "residual（予想−実測）", None, "| table _time residual")],
     "refs": ["r99_0.png"],
     "checks": ["結果は708行。predict は未来の150行を足して858行を返すが、where で実測のある行だけになる",
                "最初の1週間（11/1 19:00〜11/8 18:00 の168点）は prediction が logins と同じで、residual は 0。LLP が周期を学ぶのに、少なくとも1周期分のデータが要るため",
                "それ以降の prediction は、日本時間の0〜6時に高く、15〜21時と日曜・月曜の朝に低い、いつもの波をなぞる",
                "residual がいちばん大きくマイナスになるのは 12/1 03:00（実測 527、予想 446、residual −80.8）。予想より 81 多かった"]},
    {"id": "r1-4", "tag": "GUI 1-4", "title": "residual に MAD を当てる（Showcase の既定の設定）",
     "body": ["Search 1-3 の SPL を入力欄に入れて検索したら、画面の項目を次のとおりにして <b>Detect Outliers</b> をクリックします。Showcase を開いた直後の既定の設定と同じです。"],
     "extra_html": ('<table class="aitk-table"><thead><tr><th style="width:24%;">画面の項目</th><th style="width:16%;">設定</th><th>意味</th></tr></thead><tbody>'
                    '<tr><td><b>Field to analyze</b></td><td>residual</td><td>外れ値を探す項目。予想とのずれ（residual）を見る。logins を選ぶと GUI 1-2 と同じく、時刻の波を考えない判定に戻る</td></tr>'
                    '<tr><td><b>Threshold method</b></td><td>Median Absolute Deviation</td><td>中央値と、中央値からのずれの中央値（MAD）で範囲を決める。平均と標準偏差より、極端な値に引っぱられにくい。ほかに Standard Deviation（平均±標準偏差×倍率）と Interquartile Range（四分位範囲）を選べる</td></tr>'
                    '<tr><td><b>Threshold multiplier</b></td><td>9</td><td>範囲を「中央値±MAD×9」にする。小さくすると範囲が狭くなり、外れ値が増える</td></tr>'
                    '<tr><td><b>Sliding window (# of values)</b></td><td>72</td><td>範囲を、直近72点（1時間刻みなので72時間＝3日）だけから計算し、1点ずつずらしていく。ずれの大きさが時期によって変わっても、範囲がついていく。空にすると全期間で1つの範囲（GUI 1-2）</td></tr>'
                    '<tr><td><b>Include current point</b></td><td>チェックあり</td><td>範囲の計算に、いま判定する点そのものも含める。Sliding window を使うときだけ選べる</td></tr>'
                    '<tr><td><b>Fields to split by</b></td><td>空</td><td>グループに分けずに判定する。ユーザーやホストの列があれば、ここで指定してグループごとの範囲にできる</td></tr>'
                    '</tbody></table>'
                    '<p class="aitk-note">画面の設定に合わせて、裏で SPL が生成されます。<b>Show SPL</b> を押すと、生成された SPL（streamstats で中央値と MAD を求める部分）を見られます。</p>'),
     "refs": ["r99_0.png"],
     "checks": ["外れ値は <b>61</b>（グラフ右側）。資料と同じ数",
                "61のうち40は 11/8〜11/10 に固まっている。直前の3日間（Sliding window の72点）は residual が 0 の期間なので MAD もほぼ 0 になり、少しのずれでも外れ値になるため。予想が育つ前の期間は、判定から外して考える",
                "12/1 の 00:00、03:00、05:00、06:00 の4点が外れ値になる。どれも予想より 57〜81 多かった点で、GUI 1-2 の倍率 9 では1つも出なかった。11/3 03:00 は予想が育つ前の期間なので、こちらでは出ない",
                "グラフの縦軸は logins ではなく residual。何に対して外れ値を探しているかを意識する"]},
]
R1_INTRO = ('<div class="aitk-hero-text"><span class="aitk-kicker">AITK Security for Rookies ／ 演習1</span>'
            '<h1>ユーザーの振る舞いの外れ値を検知する</h1>'
            '<p>企業へのサイバー攻撃の多くは、盗まれた認証情報から始まります。ふだんのユーザーの動きが分かっていなければ、乗っ取られたアカウントには気づけません。'
            '部署や拠点によって働き方が違えば、ベースラインを作るのはなおさら難しくなります。</p>'
            '<p>ここでは AI Toolkit のサンプル logins.csv を使い、ログイン数の外れ値を Median Absolute Deviation（MAD）で探します。'
            'まずログイン数そのものに MAD を当てて倍率を変えて試し、次に predict で作った予想とのずれ（residual）に MAD を当てます。</p>'
            '<p class="aitk-flow">データを見る → logins に MAD（倍率 9→7.7→6.5→5） → predict で予想を作る → residual に MAD（倍率 9）</p></div>'
            + img("r25_0.png", "aitk-hero-icon"))

r2 = [
    {"id": "r2-1", "tag": "GUI 2-1", "title": "Showcase の Predict the Presence of Malware を開く",
     "body": ["AI Toolkit アプリのメニューの <b>Support → Showcase</b> を開き、<b>Industry → Security</b> を選んで、<b>Predict the Presence of Malware</b> をクリックします。",
              "Predict Categorical Fields の画面が、設定が入った状態で開きます。画面の各項目がどう設定されているかを確かめます。"],
     "extra_html": ('<table class="aitk-table aitk-table-fixed"><thead><tr><th style="width:28%;">画面の項目</th><th style="width:30%;">Showcase の設定</th><th>意味</th></tr></thead><tbody>'
                    '<tr><td><b>Enter a search</b></td><td><code>| inputlookup firewall_traffic.csv | head 50000</code></td><td>ファイアウォールの通信記録の先頭5万行を使う</td></tr>'
                    '<tr><td><b>Preprocessing Steps</b></td><td>なし</td><td>前処理（StandardScaler など）は入れていない</td></tr>'
                    '<tr><td><b>Algorithm</b></td><td>LogisticRegression</td><td>yes／no の確率を線形のモデルで求める。Predict Categorical Fields の既定</td></tr>'
                    '<tr><td><b>Field to predict</b></td><td>used_by_malware</td><td>当てたい項目。その通信が過去にマルウェアに使われたか（yes／no）</td></tr>'
                    '<tr><td><b>Fields to use for predicting</b></td><td>bytes_received、bytes_sent、dest_port、has_known_vulnerability、packets_received、packets_sent、src_port（7項目）</td><td>予測の手がかりにする項目。資料で、この選び方を控えておく</td></tr>'
                    '<tr><td><b>Split for training / test</b></td><td>70 / 30</td><td>70%で学習し、残りの30%で答え合わせをする</td></tr>'
                    '<tr><td><b>Fit Intercept</b></td><td>estimate the intercept にチェック</td><td>切片も推定する（LogisticRegression の設定）</td></tr>'
                    '<tr><td><b>Save the model as</b></td><td>example_malware</td><td>学習したモデルの保存名</td></tr>'
                    '</tbody></table>'
                    '<p>画面を下にたどると、<b>Prediction Results</b>（実際の used_by_malware と予測 predicted(used_by_malware) を並べた表）と、'
                    '<b>Precision／Recall／Accuracy／F1</b>、<b>Classification Results（Confusion Matrix）</b>が出ます。資料の画面では Precision 0.82、Recall 0.81、Accuracy 0.81、F1 0.81 です。'
                    '70/30 の分け方は実行ごとにランダムなので、数字は少し変わります。</p>'
                    '<p>資料では、この結果はいまひとつだとして、同じデータで自分の Experiment を作り直し、アルゴリズムを変えて改善していきます。'
                    'この演習では、その流れを Search 2-2 以降で SPL を使って追います。</p>'
                    '<p class="aitk-note">Showcase の画面で Fit Model を押すと、AI Toolkit アプリの自分の領域に example_malware というモデルが保存されます。'
                    'Search 2-3 以降で作る example_malware は、このアプリ（AITK Security Training）の中に別に保存されるので、ぶつかりません。'
                    'また Showcase は src_port を使いますが、資料で作り直す Experiment は src_port の代わりに dst_ip を選んでいるので、Search 2-3 以降もそちらに合わせています。</p>'),
     "refs": ["r133_0.png", "r135_0.png", "r136_0.png"],
     "checks": ["画面の設定が上の表と同じになっている",
                "Precision、Recall、Accuracy、F1 が 0.8 前後",
                "Confusion Matrix で、本当は yes なのに no と予測した（見逃した）割合が2割前後ある"]},
    {"id": "r2-2", "tag": "Search 2-2", "title": "ファイアウォールのデータを見る",
     "body": ["演習2で使うのは、AI Toolkit のサンプル <code>firewall_traffic.csv</code> です。送信元と宛先、ポート、バイト数、パケット数に加えて、"
              "その通信が過去にマルウェアに使われたか（<code>used_by_malware</code>）と、宛先に既知の脆弱性があるか（<code>has_known_vulnerability</code>）が入っています。",
              "used_by_malware のような「正解のラベル」が付いたデータで学習する方法を、<b>教師あり学習</b>と呼びます。資料の Showcase と同じく先頭5万行を使います。"],
     "spl": "| inputlookup firewall_traffic.csv\n| head 50000", **RK_ALL, "range_note": RK_RANGE_FW,
     "views": [("table", "先頭の10行"),
               ("table", "ラベルの内訳", None, "| stats count by used_by_malware"),
               ("table", "フィールドごとの値の種類", None,
                '| stats dc(dest_port) as dest_port dc(dst_ip) as dst_ip dc(src_port) as src_port dc(src_ip) as src_ip dc(has_known_vulnerability) as has_known_vulnerability | transpose 0 column_name="フィールド" | rename "row 1" as "値の種類"')],
     "refs": ["r134_0.png"],
     "checks": ["used_by_malware は yes 30,295、no 19,705",
                "dest_port は <code>p_53</code> のような文字列なので、数値ではなく<b>カテゴリ</b>として扱われる",
                "dst_ip と dest_port は値の種類が100を超える。これが次の Search 2-3 で効いてくる"]},
    {"id": "r2-3", "tag": "Search 2-3", "title": "LogisticRegression で学習する（70%）",
     "body": ["Predict Categorical Fields と同じ処理を SPL で行います。データを 70% と 30% に分け、70% で学習してモデル <code>example_malware</code> を保存します。",
              "入力に使うのは、資料の7項目（バイト数、ポート、宛先、パケット数、脆弱性の有無）です。"
              "文字のフィールドは、値ごとに 0／1 の列に分けてから学習に使われます（<b>One-hot エンコーディング</b>）。"],
     "spl": RK_TRAIN + f"| fit LogisticRegression fit_intercept=true used_by_malware from {RK_FEATS} into example_malware",
     **RK_ALL, "range_note": RK_RANGE_FW,
     "views": [("table", "学習データへの予測（先頭10行）", None,
                f"| table used_by_malware {RK_PRED} {RK_FEATS}"),
               ("table", "学習データで当たった数", None,
                "| eval 判定=if(used_by_malware='predicted(used_by_malware)',\"当たり\",\"はずれ\") | stats count by 判定")],
     "refs": ["r139_0.png"],
     "checks": ["学習に使われるのは5万行のうち約3.5万行（70%）",
                "学習データで当たったのは 27752 行、はずれは 7263 行（約79%）",
                "Search で開いてジョブの注意を見ると「Dropping field(s) with too many distinct values: dest_port, dst_ip」と出る。値が100種類を超えるカテゴリは、既定では学習から外される（AI Toolkit の Settings の max_distinct_cat_values）",
                "つまり実際に効いている入力は5項目。注意メッセージは必ず読む"],
     "extra_html": ('<h4 style="margin:14px 0 4px;">ここに出る predicted(used_by_malware) は何か</h4>'
                    '<p><code>fit</code> は、渡されたデータ（ここでは70%）でモデルを学習して保存したあと、<b>そのモデルを同じ70%のデータにその場で当て</b>、'
                    '予測を <code>predicted(used_by_malware)</code> 列として足して返します。'
                    'つまりこの表の予測は、学習に使ったデータへの予測です。30%で検証した結果ではありません（それは次の Search 2-4）。</p>'
                    '<p>1行ずつ見ると、<code>used_by_malware</code>（実際）と <code>predicted(used_by_malware)</code>（予測）が同じなら当たり、違えばはずれです。'
                    '下段の「学習データで当たった数」は、その当たりとはずれを数えたものです。</p>'),
     "note": "モデルは、このアプリの中の自分の領域に保存されます。Search 2-4 以降と演習3はこのモデルを使います。"},
    {"id": "r2-4", "tag": "Search 2-4", "title": "残りの30%で答え合わせをする",
     "body": ["学習に使わなかった30%（14985行）に、Search 2-3 で70%から学習したモデルを <code>apply</code> で当て、予測がどれだけ当たるかを測ります。"
              "学習に使ったデータで測ると、覚えただけでも高い点が出てしまうからです。ここで出る <code>predicted(used_by_malware)</code> が、70%で学習したモデルを30%で確かめた予測です。",
              "Experiment の画面（GUI 2-1）に出る Prediction Results の表と Precision などの数字も、裏ではこの30%側の結果から計算されています（検証環境の監査ログで確認）。"],
     "extra_html": ('<h4 style="margin:14px 0 4px;">混同行列の読み方（LogisticRegression、この環境の結果）</h4>'
                    '<table class="aitk-table aitk-table-fixed"><thead><tr><th style="width:26%;"></th><th>予測 no</th><th>予測 yes</th></tr></thead><tbody>'
                    '<tr><td><b>実際 no</b>（5943行）</td><td>4643（当たり）</td><td>1300（誤検知：マルウェアでないのに yes）</td></tr>'
                    '<tr><td><b>実際 yes</b>（9042行）</td><td>1895（見逃し：マルウェアなのに no）</td><td>7147（当たり）</td></tr>'
                    '</tbody></table>'
                    '<p class="aitk-note">score confusion_matrix の表では、ラベルが文字の順に 0＝no、1＝yes で出ます。</p>'
                    '<h4 style="margin:14px 0 4px;">4つの数字の意味</h4>'
                    '<table class="aitk-table aitk-table-fixed"><thead><tr><th style="width:20%;">指標</th><th style="width:38%;">意味</th><th>この結果での計算</th></tr></thead><tbody>'
                    '<tr><td><b>Accuracy</b>（正解率）</td><td>全体のうち、予測が当たった割合。「何割当たっているか」はこの数字</td><td>(4643 ＋ 7147) ÷ 14985 ＝ <b>0.79</b></td></tr>'
                    '<tr><td><b>Precision</b>（適合率）</td><td>yes と予測したうち、本当に yes だった割合。低いほど誤検知が多い</td><td>yes：7147 ÷ (7147 ＋ 1300) ＝ 0.85（yes と判定した通信の15%は誤検知）<br/>no：4643 ÷ (4643 ＋ 1895) ＝ 0.71</td></tr>'
                    '<tr><td><b>Recall</b>（再現率）</td><td>本当の yes のうち、yes と予測できた割合。低いほど見逃しが多い</td><td>yes：7147 ÷ 9042 ＝ 0.79（マルウェアの通信の約2割を見逃し）<br/>no：4643 ÷ 5943 ＝ 0.78</td></tr>'
                    '<tr><td><b>F1</b></td><td>Precision と Recall の調和平均。片方だけ高くても F1 は上がらないので、両方のつり合いを1つの数字で見られる</td><td>yes：2 × 0.85 × 0.79 ÷ (0.85 ＋ 0.79) ＝ 0.82</td></tr>'
                    '</tbody></table>'
                    '<p>下段の表の Precision、Recall、F1 は、yes と no それぞれの値を件数（yes 9042、no 5943）で重み付けして平均したもの（<code>average=weighted</code>）です。'
                    'Precision は (0.71 × 5943 ＋ 0.85 × 9042) ÷ 14985 ＝ 0.79 になります。重み付けした Recall は、計算上いつも Accuracy と同じ値になります。'
                    'Experiment の画面の4つの数字も同じ計算です。</p>'
                    '<p>セキュリティの検知では、Accuracy に加えて、<b>見逃し</b>（yes の Recall）と<b>誤検知</b>（yes の Precision）を分けて見ます。'
                    'どちらを重く見るかは、見逃したときの被害と、誤検知を調べる手間で決めます。</p>'
                    '<p>学習に使った70%での当たりの割合（Search 2-3 の約79%）と、30%での Accuracy（0.79）がほぼ同じです。'
                    'LogisticRegression は学習データだけに合わせ込みすぎてはいない（過学習していない）ことも読み取れます。差が大きく開いたら過学習を疑います。</p>'),
     "spl": RK_TEST, **RK_ALL, "range_note": RK_RANGE_FW,
     "views": RK_SCORE_VIEWS,
     "refs": ["r140_0.png"],
     "checks": ["Precision・Recall・F1 は 0.79 前後、Accuracy も 0.79 前後。資料（0.82／0.81）と近い値",
                "混同行列が上の表と同じ 4643／1300／1895／7147 になっている",
                "見逃し（実際 1 なのに予測 0）が 1895 件、誤検知（実際 0 なのに予測 1）が 1300 件"]},
    text_row('<div class="aitk-step-head"><span class="aitk-tag aitk-tag-info">解説</span><h2>アルゴリズムを変えてみる</h2></div>'
             '<p>資料では LogisticRegression の結果がいまひとつだったので、SVM、RandomForestClassifier の順に試しています。'
             'データサイエンティストでも、同じデータにいくつかのアルゴリズムを当てて比べるのはふつうのことです。'
             'この検証環境で、同じ 70/30 の分け方（seed=1234）で試した結果は次のとおりです。</p>'
             '<table class="aitk-table"><thead><tr><th>アルゴリズム</th><th>Precision</th><th>Recall</th><th>F1</th><th>メモ</th></tr></thead><tbody>'
             '<tr><td>LogisticRegression</td><td>0.79</td><td>0.79</td><td>0.79</td><td>線形の境界しか引けない</td></tr>'
             '<tr><td>SVM</td><td>0.68</td><td>0.51</td><td>0.46</td><td>ほぼ全部を一方に倒してしまう。学習は1万行に間引かれる</td></tr>'
             '<tr><td>GaussianNB</td><td>0.68</td><td>0.50</td><td>0.44</td><td>バイト数の分布が正規分布から遠い</td></tr>'
             '<tr><td>DecisionTreeClassifier</td><td>0.99</td><td>0.99</td><td>0.99</td><td>しきい値の組み合わせで分けられるデータに強い</td></tr>'
             '<tr><td><b>RandomForestClassifier</b></td><td><b>0.99</b></td><td><b>0.99</b></td><td><b>0.99</b></td><td>資料で採用。決定木の多数決なので、1本の木より安定する</td></tr>'
             '</tbody></table>'
             + ul(["0.99 でも 1.00 ではないことが大事です。1.00 になったら、学習と評価に同じデータを使っている（過学習を見逃している）か、データの幅が足りないことを疑います",
                   "ほかのアルゴリズムを試すには、Search 2-3 を Search で開き、<code>fit</code> の後ろのアルゴリズム名を変えて実行し、続けて Search 2-4 を実行します"]) +
             '<p class="aitk-note">次の Search 2-5 で、モデルを RandomForestClassifier で作り直します。</p>'),
    {"id": "r2-5", "tag": "Search 2-5", "title": "RandomForestClassifier で学習し直す",
     "body": ["Search 2-3 とアルゴリズムだけを変えて、同じ名前 <code>example_malware</code> で上書き保存します。",
              "RandomForestClassifier は、データと項目をランダムに少しずつ変えながら決定木をたくさん作り、その多数決で判定します。1本の決定木より安定し、数値とカテゴリが混ざった表のデータでよく使われます。"],
     "spl": RK_TRAIN + f"| fit RandomForestClassifier used_by_malware from {RK_FEATS} random_state=42 into example_malware",
     **RK_ALL, "range_note": RK_RANGE_FW,
     "views": [("table", "学習データで当たった数", None,
                "| eval 判定=if(used_by_malware='predicted(used_by_malware)',\"当たり\",\"はずれ\") | stats count by 判定")],
     "refs": ["r144_0.png"],
     "checks": ["学習データではほぼすべて当たる。木を使う方法は学習データにはよく合うので、ここの数字は信用しない。次の Search 2-6 で確かめる"]},
    text_row('<div class="aitk-step-head"><span class="aitk-tag aitk-tag-info">解説</span><h2>RandomForestClassifier の解説（Search 2-5 の補足）</h2></div>'
             + '<h4 style="margin:14px 0 4px;">パラメータ</h4>'
                      '<p>AI Toolkit の RandomForestClassifier で指定できるのは、次の7つです。既定値は scikit-learn の既定です（n_estimators の 100 は、指定なしと 100 が同じ結果になることをこの環境で確かめました）。'
                      '右の列は、この SPL のほかの条件はそのまま（random_state=42）で、パラメータを1つだけ変えたときの30%での結果（Search 2-6 と同じ測り方）です。既定のままでは Accuracy 0.989、見逃し 87、誤検知 72 です。</p>'
                      '<table class="aitk-table aitk-table-fixed"><thead><tr><th style="width:15%;">パラメータ</th><th style="width:27%;">何を決めるか（既定）</th><th style="width:28%;">この環境で変えると</th><th>どんなときに変えるか</th></tr></thead><tbody>'
                      '<tr><td><code>n_estimators</code></td><td>作る木の本数（100）</td><td>10：0.988（見逃し 108）<br/>50：0.989<br/>200：0.990<br/>300：モデルが約41MBになり、保存の上限（30MB）を超えて失敗</td><td>結果が実行ごとにぶれるときに増やす。増やすほど学習が重く、モデルも大きくなる。ある程度から先はほとんど良くならない</td></tr>'
                      '<tr><td><code>max_depth</code></td><td>1本の木の深さの上限（なし＝伸ばしきる）</td><td>2：0.867（誤検知 1712）<br/>5：0.919<br/>10：0.979</td><td>学習データでは当たるのに30%で下がる（過学習）とき、またはモデルを小さく、判定を単純にしたいときに制限する</td></tr>'
                      '<tr><td><code>max_leaf_nodes</code></td><td>1本の木の葉（最後の分かれ先）の数の上限（なし）</td><td>8：0.879</td><td>max_depth と同じく木を小さくする別の方法。深さではなく、分かれ先の総数で抑えたいとき</td></tr>'
                      '<tr><td><code>min_samples_split</code></td><td>枝を分けるのに必要な最小の行数（2）</td><td>200：0.969</td><td>ごく少数の行だけに合わせた細かすぎる分岐を防ぎたいとき。ノイズの多いデータで効く</td></tr>'
                      '<tr><td><code>max_features</code></td><td>枝を分けるたびに候補にする項目の数（項目数の平方根）</td><td>1：0.990<br/>None（全項目）：0.990</td><td>項目が多いデータで調整する。小さくすると木どうしが似なくなり、多数決が安定しやすい。大きくすると強い項目に頼る</td></tr>'
                      '<tr><td><code>criterion</code></td><td>分け方の良さの測り方。<code>gini</code> か <code>entropy</code>（gini）</td><td>entropy：0.989（ほぼ同じ）</td><td>結果にほとんど差が出ないことが多い。ほかを調整したあと、最後に試す程度</td></tr>'
                      '<tr><td><code>random_state</code></td><td>乱数の種（なし＝毎回変わる）</td><td>この SPL では 42 に固定</td><td>演習や比較のために、同じ結果を再現したいとき。運用では固定しなくてもよい</td></tr>'
                      '</tbody></table>'
                      '<h4 style="margin:14px 0 4px;">どんなときに RandomForestClassifier を使うか</h4>'
                      + ul(["<b>向いている</b>：数値とカテゴリが混ざった表のデータで、項目と答えの関係が直線的でないとき（このデータでは LogisticRegression の 0.79 が 0.99 になった）。外れ値や桁の違いに比較的強く、StandardScaler などでそろえなくても使える",
                            "<b>説明がほしいとき</b>：<code>| summary</code> で、どの項目が判定に効いたか（feature importance）を見られる（Search 2-7）",
                            "<b>苦手なこと</b>：木が多く深いほど学習が重く、モデルも大きくなる（この環境では保存の上限が30MB）。1本の決定木のように、判定の理由をルールとして読むことはできない",
                            "<b>まず既定で試す</b>：既定のままで十分なことが多い。過学習が見えたら max_depth か min_samples_split で木を小さくし、結果がぶれるなら n_estimators を増やす"])),
    text_row('<div class="aitk-step-head"><span class="aitk-tag aitk-tag-info">解説</span><h2>apply の解説（Search 2-5 の補足）</h2></div>'
             '<p>Search 2-5 で保存したモデルは、次の Search 2-6 から <code>| apply example_malware</code> で使います。fit と apply の役割は次のとおりです。</p>'
             '<table class="aitk-table aitk-table-fixed"><thead><tr><th style="width:16%;">コマンド</th><th>何をするか</th><th style="width:36%;">この演習では</th></tr></thead><tbody>'
             '<tr><td><code>| fit</code></td><td>データからモデルを学習し、<code>into</code> で保存する。学習したモデルを同じ入力データにもその場で当てる</td><td>Search 2-3（LogisticRegression）、Search 2-5（RandomForestClassifier）</td></tr>'
             '<tr><td><code>| apply</code></td><td>保存したモデルを読み込み、渡されたデータに当てて <code>predicted(…)</code> の列を足す。学習はし直さないので、新しいデータに毎回同じ基準で判定できる。fit より軽い</td><td>Search 2-4、2-6（30%での答え合わせ）、Search 2-8（5万行すべての判定）、演習3の検知</td></tr>'
             '</tbody></table>'
             '<h4 style="margin:14px 0 4px;">apply は通常のサーチから実行する</h4>'
             '<p>AI Toolkit の画面に、apply を実行するボタンはありません。運用で使うときは、<b>通常のサーチの中に <code>| apply モデル名</code> を書きます</b>。'
             'AI Toolkit の Search タブでも、Search &amp; Reporting など他のアプリのサーチでも同じです。そのため、次のような場所にそのまま置けます。</p>'
             + ul(["保存済みサーチやアラート（定期的に新しいデータを判定し、予測が yes なら通知する）",
                   "ダッシュボードのパネル",
                   "Enterprise Security の検知（演習3の Search 3-2 と Detection）"]) +
             '<p>Experiment の画面の中でも apply は使われていますが、それは画面が裏で自動的に流しているものです。Fit Model を押すと、学習のあとに30%のデータへ apply して、Precision などの数字を出しています（検証環境の監査ログで確認）。'
             'Smart Outlier Detection の Create Alert のように、apply を使う定期サーチを画面が作ってくれる機能もありますが、作られるのは通常の保存済みサーチです。'
             'なお Schedule Training は apply ではなく、fit（学習のし直し）を定期的に実行する機能です。</p>'
             '<h4 style="margin:14px 0 4px;">apply を使うときの注意</h4>'
             + ul(["<b>前処理をそろえる</b>：apply の前の行（データの絞り込みや項目の作り方）は、学習したときと同じにする。項目の名前や作り方が違うと、正しく判定できない",
                   "<b>モデルが見える場所で動かす</b>：モデルは、作ったアプリの作った人の領域に保存される。ほかのアプリやユーザーのサーチから apply するには、共有範囲を広げる必要がある（演習3の「モデルを全アプリに共有する」）",
                   "<b>同じ名前で上書きされる</b>：Search 2-5 は Search 2-3 と同じ example_malware に保存するので、以後の apply は RandomForestClassifier のモデルを使う。保存に失敗したとき（上の n_estimators=300 の例）は、前のモデルが残ったままになる"]) +
             '<p class="aitk-note">次の Search 2-6 で、このモデルを30%のデータに apply して答え合わせをします。</p>'),
    {"id": "r2-6", "tag": "Search 2-6", "title": "もう一度30%で答え合わせをする",
     "body": ["Search 2-4 と同じ SPL です。モデルの中身だけが RandomForestClassifier に変わっています。"],
     "spl": RK_TEST, **RK_ALL, "range_note": RK_RANGE_FW,
     "views": RK_SCORE_VIEWS,
     "refs": ["r146_0.png"],
     "checks": ["Precision・Recall・F1・Accuracy がそろって 0.99 前後に上がる",
                "混同行列で、見逃し（実際 1 なのに予測 0）が 8,958 件中 100 件以下になっている"]},
    {"id": "r2-7", "tag": "Search 2-7", "title": "どの入力が効いているかを見る",
     "body": ["RandomForestClassifier のモデルは、各入力が判定にどれだけ効いたか（feature importance）を持っています。<code>| summary</code> で見られます。"],
     "spl": "| summary example_malware", **RK_ALL, "range_note": "なし（モデルを読むだけ）",
     "views": [("table", "feature importance")],
     "checks": ["bytes_received（約0.42）と bytes_sent（約0.30）がいちばん効いている",
                "has_known_vulnerability は <code>=no</code> と <code>=yes</code> の2つに分かれている。これが One-hot エンコーディングの結果",
                "dest_port と dst_ip は出てこない。Search 2-3 の注意のとおり学習から外されたから"]},
    {"id": "r2-8", "tag": "Search 2-8", "title": "保存したモデルを apply する",
     "body": ["資料のとおり、モデルを使う方法は、演習1のような SPL だけの方法と違い、モデルを保存して <code>| apply</code> で呼び出します。"
              "学習し直さずに、新しいデータへ同じ判定を当てられます。"],
     "spl": f"| inputlookup firewall_traffic.csv\n| head 50000\n| apply example_malware\n| stats count by used_by_malware {RK_PRED}",
     **RK_ALL, "range_note": RK_RANGE_FW,
     "views": [("table", "実際と予測の組み合わせ")],
     "refs": ["r149_1.png"],
     "checks": ["yes→yes と no→no がほとんどを占める",
                "予測が yes の行は約3万。演習3では、この結果を ES の検知に使う"]},
    gui_panel("演習2を GUI でやる（Predict Categorical Fields）", "LogisticRegression ／ RandomForestClassifier",
              "資料では Showcase の「Predict the Presence of Malware」で中身を確かめてから、自分の Experiment を作り直しています。",
              [("Showcase を見る", "<b>Support → Showcase</b> → <b>Industry</b> → <b>Security</b> → <b>Predict the Presence of Malware</b>。入力の SPL（<code>| inputlookup firewall_traffic.csv | head 50000</code>）と、使っている項目を控える"),
               ("Experiment を作る", "<b>Experiments</b> → <b>Create New Experiment</b> で <b>Predict Categorical Fields</b> を選び、Experiment Title（例：example_malware_gui）を入れて Create"),
               ("学習する", "SPL を貼って検索し、Algorithm は LogisticRegression、<b>Field to predict</b> は used_by_malware、<b>Fields to use for predicting</b> は控えた7項目、<b>Split for training / test</b> は 70/30 にして <b>Fit Model</b>"),
               ("比べる", "Algorithm を SVM、RandomForestClassifier に変えて Fit Model を繰り返す。<b>Experiment History</b> タブにすべての実行が残り、Load Settings で前の設定に戻せる"),
               ("保存して公開する", "右上の <b>Save</b> → Experiments の一覧で <b>Publish</b>。モデル名（例：example_malware_gui）と公開先アプリを指定すると、<code>| apply example_malware_gui</code> で使える")],
              [("fit LogisticRegression", "Algorithm", "LogisticRegression → RandomForestClassifier"),
               ("used_by_malware", "Field to predict", "used_by_malware"),
               ("from bytes_received … packets_sent", "Fields to use for predicting", "7項目"),
               ("sample partitions=100 | where partition_number&lt;70", "Split for training / test", "70 / 30"),
               ("fit_intercept=true", "Fit Intercept（estimate the intercept）", "オン（LogisticRegression のとき）"),
               ("score precision_recall_fscore_support など", "Precision／Recall／Accuracy／F1 と Confusion Matrix の表示", "―")],
              "GUI で作ったモデルは、Save と Publish をして初めて別のアプリから使えます。Search 2-3 の名前（example_malware）と同じ名前で同じアプリに公開すると上書きになるので、別の名前にしてください。"
              "GUI の分け方は実行ごとにランダムなので、数字は上の表と少しずれます。"),
]
R2_INTRO = ('<div class="aitk-hero-text"><span class="aitk-kicker">AITK Security for Rookies ／ 演習2</span>'
            '<h1>マルウェアの通信を予測する</h1>'
            '<p>SOC にとってネットワークの監視は、侵入、持ち出し、横展開を見つけるための大事な仕事です。ただ、何千もの端末と API 呼び出しが出すノイズの中で、ふだんの通信を見極めるのは簡単ではありません。'
            'Siemens は Splunk と組んで、プロキシの通信のベースラインから外れたものを機械学習で見つけ、SSH を HTTP でトンネルするマルウェアの通信を検知しています。</p>'
            '<p>ここでは、過去の通信に「マルウェアに使われたか」のラベルが付いた firewall_traffic.csv で、そのラベルを当てる分類モデル（Categorical Prediction）を作ります。</p>'
            '<p class="aitk-flow">Showcase を開く → データを見る → LogisticRegression で学習 → 30%で評価 → アルゴリズムを比べる → RandomForest で作り直し → apply</p></div>'
            + img("r23_0.png", "aitk-hero-icon"))

r3 = [
    {"id": "r3-1", "tag": "Search 3-1", "title": "演習2のモデルを apply できることを確かめる",
     "body": ["演習2で作成した RandomForestClassifier のモデル（example_malware）を apply するサーチを利用しますので、サーチが実行できることを再度確認してください。"],
     "spl": "| inputlookup firewall_traffic.csv\n| head 50000\n| apply example_malware\n| table *time *",
     **RK_ALL, "range_note": RK_RANGE_FW,
     "views": [("table", "apply の結果（先頭10行）")],
     "refs": ["r158_0.png"],
     "checks": ["5万行が返り、predicted(used_by_malware) の列がある",
                "「Model does not exist」などのエラーが出たら、演習2の Search 2-5 を実行してから、もう一度実行する"]},
    text_row('<div class="aitk-step-head"><span class="aitk-tag aitk-tag-gui" style="background:#7b3fa0;">GUI</span><h2>モデルを全アプリに共有する</h2></div>'
             '<p>資料では AI Toolkit の Models 画面から共有していますが、そこに出るのは AI Toolkit アプリから見えるモデルだけです。'
             'このアプリで作ったモデルは、Splunk の設定画面から共有します。</p>'
             '<table class="aitk-table"><tbody>'
             '<tr><td><b>開く</b></td><td><b>Settings → Lookups → Lookup table files</b> を開き、App を <b>AITK Security Training</b>、Owner を自分にして '
             '<code>__mlspl_example_malware.mlmodel</code> を探す</td></tr>'
             '<tr><td><b>共有する</b></td><td>その行の <b>Permissions</b> を押し、Object should appear in を <b>All apps (system)</b> にする。Read は Everyone にして Save</td></tr>'
             '<tr><td><b>確かめる</b></td><td>次の Search 3-2 の <b>ES の Search で開く</b> で、ES の中から実行して結果が出ることを見る</td></tr>'
             '</tbody></table>'
             '<p class="aitk-note">本番では、Read を Everyone にせず、検知を動かすロール（ES の ess_analyst など）だけに絞ってください。'
             'GUI の Experiment で作って Publish したモデルなら、AI Toolkit の <b>Models</b> 画面の Sharing 列からも同じ設定ができます。'
             '検知サーチが読む firewall_traffic.csv は、このアプリが全アプリに公開しているので、追加の設定は要りません。</p>'),
    {"id": "r3-2", "tag": "Search 3-2", "title": "検知サーチを作って試す",
     "body": ["ES の検知にするサーチを、まずここで試します。資料の検知サーチは、マルウェアと予測した通信を1行ずつそのまま出します。"
              "これを ES に入れると、予測 yes の約3万行がそれぞれ1件の Finding（ES 7 の Notable）になり、アナリストのキューが埋まってしまいます。",
              "ここでは宛先とポートの組ごとにまとめ、通信の多い上位10組だけを出すようにしています。Finding は「調べる単位」で出すのが基本です。",
              "モデルの共有ができたら、右上の <b>ES の Search で開く</b> で ES アプリの中から同じサーチを実行してみてください。結果が出れば、ES からモデルが見えています。"],
     "spl": RK_DETECT, **RK_ALL, "range_note": RK_RANGE_FW,
     "open_apps": [("SplunkEnterpriseSecuritySuite", "ES の Search で開く")],
     "views": [("table", "Finding になる10行")],
     "refs": ["r159_2.png"],
     "checks": ["10行出る。いちばん上は 73.147.88.91 の p_53（DNS）で、約7,000セッション、送信元は約200",
                "ES の Search で開いて「Model does not exist」などのエラーが出たら、モデルがまだ共有されていない"]},
    text_row('<div class="aitk-step-head"><span class="aitk-tag aitk-tag-gui" style="background:#7b3fa0;">GUI</span><h2>ES 8 で検知（Detection）を作る</h2></div>'
             '<p>資料の ES 8 の手順を、この環境の ES 8.7 のメニューに合わせて書いています。画面の文言は ES のバージョンで少し変わります。</p>'
             '<table class="aitk-table"><tbody>'
             '<tr><td><b>開く</b></td><td><a class="aitk-open" target="_blank" href="../SplunkEnterpriseSecuritySuite/ess_content_management">ES の Content management を開く ↗</a>'
             '（ES のメニューでは <b>Security content → Content management</b>）。<b>Create new content</b> から <b>Event-based detection</b> を選ぶ</td></tr>'
             '<tr><td><b>名前</b></td><td>example_malware</td></tr>'
             '<tr><td><b>サーチ</b></td><td>上の Search 3-2 の SPL を貼る。inputlookup は時間範囲に関係なく全行を読むので、時間範囲は既定のままでよい</td></tr>'
             '<tr><td><b>スケジュール</b></td><td>演習では1時間ごとなど長めにする。実行のたびに同じ10件が出るので、確かめたら無効にする</td></tr>'
             '<tr><td><b>出力</b></td><td><b>Finding</b> を出す設定にし、タイトル（例：<code>マルウェアの疑い $dst_ip$:$dest_port$</code>）、セキュリティドメイン（Threat）、重大度（Medium など）を入れる</td></tr>'
             '<tr><td><b>保存</b></td><td>保存して有効にする。ES 7 では Configure → Content → Content Management → Create New Content → Correlation Search で同じことをし、Adaptive Response で Notable を足す</td></tr>'
             '</tbody></table>'
             '<h4 style="margin:14px 0 4px;">結果を確かめる</h4>'
             + ul(["次のスケジュール実行のあと、ES の <b>Mission Control</b> のキューで example_malware を探す。数分かかることがある（資料は ES 7 の Incident Review の画面）",
                   "Finding を開き、dst_ip、dest_port、sessions などの列が載っていることを確かめる",
                   "ES の <b>Audit → Machine learning audit</b> で、ES の中から使われた AI Toolkit のモデルの状況を見られる",
                   "演習が終わったら、Content management で example_malware の検知を<b>無効</b>にする"]) +
             '<p class="aitk-note">本番の検知では、<code>| inputlookup</code> の代わりに、直近の時間帯のファイアウォールログ（CIM の Network_Traffic データモデルなど）を入れます。'
             'モデルの学習（Search 2-5）は別のスケジュールで定期的にやり直し、検知のほうは apply だけを行います。</p>'),
]
R3_INTRO = ('<div class="aitk-hero-text"><span class="aitk-kicker">AITK Security for Rookies ／ 演習3</span>'
            '<h1>ML を ES で運用する</h1>'
            '<p>モデルを作っただけでは、SOC の仕事は楽になりません。演習2で作ったマルウェア予測モデルを Enterprise Security の検知に組み込み、'
            '予測の結果をアナリストが調べる Finding として出します。</p>'
            '<p>流れは、データを入れる → 前処理する → モデルを学習する → 検知として動かす、の4段階です。前の3つは演習2で済んでいます。</p>'
            '<p class="aitk-flow">モデルの共有範囲を確かめる → 全アプリに共有 → 検知サーチを試す → ES で Detection を作る → Mission Control で確かめる</p></div>'
            + img("r54_0.png", "aitk-hero-icon"))

def _slide(n, cls="aitk-fig aitk-slide"):
    return img(f"rk_p{n:03d}.jpg", cls)


def _pg(p):
    return f'<span class="aitk-pages">資料 {p}</span>'


def _layer(color, label):
    return (f'<div class="aitk-layer-head" style="border-left:8px solid {color};padding:4px 0 4px 12px;margin:26px 0 10px;">'
            f'<span style="font-size:12px;color:#5b6b75;">ピラミッドの層</span><br/><b style="font-size:18px;">{label}</b></div>')


ROOKIES_SUMMARY = f'''
<div class="aitk-doc">
<header class="aitk-doc-hero">
  <span class="aitk-kicker">AITK Security for Rookies ／ Summary</span>
  <h1>セキュリティの機械学習を始める前に</h1>
  <p>Splunk4Rookies Machine Learning for Security の講義部分を、資料の順にまとめたページです。どんな種類の機械学習があり、Splunk のどこで使えて、データの何に気をつけ、SPL でどう準備して fit と apply で回すかを確認してから、3つの演習に進みます。</p>
</header>

<section>
  <h2>AI・機械学習・ディープラーニング</h2>
  <p>AI はコンピューターにデータを処理させ、判断させる研究分野の全体です。その一部が機械学習（ML）で、人がほとんど手を入れずにデータから予測や洞察を得ます。さらにその一部で、ニューラルネットワークを使うのがディープラーニングです。</p>
  <p>この講座で扱うのは、AI Toolkit（旧 MLTK）で使える機械学習です。目的によって使い方が分かれます。</p>
  <table class="aitk-table">
    <thead><tr><th>使い方</th><th>何に使うか</th><th>主な方法</th></tr></thead>
    <tbody>
      <tr><td><b>予測</b></td><td>これから起きそうな問題に先回りする</td><td>数値の回帰、カテゴリの予測（分類）、時系列の予測</td></tr>
      <tr><td><b>分類</b></td><td>データの中身を知って、いま起きていることにすばやく対応する</td><td>カテゴリの予測、クラスタリング</td></tr>
      <tr><td><b>外れ値の検知</b></td><td>ふだんと違う振る舞いを見つけて調べる</td><td>クラスタリング、外れ値検知</td></tr>
    </tbody>
  </table>
</section>

<section>
  <h2>検索のたびに ML を使える</h2>
  {_slide(26)}
  <p>左から、工場の設備（Industrial Assets）、PC やスマートフォン、OT、IT のデータがリアルタイムに Splunk へ入ってきます。ML はその上の<b>サーチの1ステップ</b>として動くので、特別な仕組みを別に用意しなくても、どのサーチにも組み込めます。</p>
  <ul>
    <li><b>Search → Alert</b>：ML を含むサーチを保存し、条件を満たしたらアラートにする</li>
    <li><b>アラートの行き先</b>：Webhook、メール、チケット起票、プロセスの起動（他のアプリケーション）、スマートフォンへの通知</li>
    <li><b>見せ方と自動化</b>：結果は Dashboard Studio で可視化してチームで共有できる。アラートを SOAR に渡し、用意済みのプレイブックで対応を自動化することもできる</li>
  </ul>
</section>

<section>
  <h2>一度学習したモデルを使い続ける</h2>
  {_slide(27)}
  <p>前の図の流れに、モデルの学習と保存が加わった図です。</p>
  <ul>
    <li><code>| fit y from x* into "model"</code> を実行すると、計算は Python for Scientific Computing（Pandas、NumPy、SciPy、StatsModels、scikit-learn）が行い、結果は <b>persisted model</b>（保存されたモデル）として Splunk に残る</li>
    <li>以後のサーチは <code>| apply "model"</code> でそのモデルを呼び出すだけ。学習をやり直さずに、毎回同じ基準で新しいデータを判定できる</li>
    <li>判定の結果は、前の図と同じくアラートや可視化につなげる。モデルは定期的に学習し直して更新できる</li>
  </ul>
  <p class="aitk-note">演習2の <code>fit … into example_malware</code> と <code>apply example_malware</code> がこの形です。</p>
</section>

<section>
  <h2>Splunk の ML の全体像</h2>
  <div class="aitk-split">
    <div>{_slide(30)}</div>
    <div>
      <p>Splunk では、アプリを何も入れなくても使える統計コマンドから、外部のコンテナで深層学習を動かす DSDL まで、5つの層で ML を使えます。下ほど手軽で、上ほど高度です。</p>
      <table class="aitk-table">
        <tbody>
          <tr><td><b>DSDL</b></td><td>外部のコンテナで、深層学習や GPU を使う</td></tr>
          <tr><td><b>MLTK</b></td><td>自分でモデルを作る。今日の主役</td></tr>
          <tr><td><b>Premium Apps</b></td><td>ES、ITSI などに組み込まれた ML</td></tr>
          <tr><td><b>Splunkbase Apps</b></td><td>無料のアプリやアシスタント</td></tr>
          <tr><td><b>Splunk Enterprise &amp; Cloud</b></td><td>どの環境にもある統計コマンド</td></tr>
        </tbody>
      </table>
      <p>上の層に進む前に、下の層で答えが出ないかを試すのが近道です。下の層で足りるなら、そのほうが早く、管理者にアプリを入れてもらう必要もありません。</p>
    </div>
  </div>

  {_layer("#2f6fb7", "Splunk Enterprise &amp; Cloud")}
  <p>次の4つは Splunk Enterprise にも Splunk Cloud にも最初から入っているコマンドです。管理者の作業もアプリのインストールも要りません。例のサーチは、このアプリに同梱している firewall_traffic.csv（先頭5万行）で実際に動かした結果です。</p>
  <table class="aitk-table aitk-table-fixed">
    <thead><tr><th style="width:16%;">コマンド</th><th style="width:40%;">何をするか</th><th>例と、この環境での結果</th></tr></thead>
    <tbody>
      <tr><td><code>| anomalydetection</code></td>
          <td>イベントごとに「この値の組み合わせがどれくらい起きやすいか」の確率を計算し、確率がとても小さいイベントを異常として取り出す変換コマンド。カテゴリの値は出現頻度から、数値はヒストグラムから確率を求める。<code>action=filter</code>（既定）は異常だけを残し、<code>annotate</code> は全行に印を付け、<code>summary</code> は件数をまとめる</td>
          <td><code>| inputlookup firewall_traffic.csv | head 50000 | anomalydetection dest_port bytes_sent</code><br/>5万行のうち3行が残った（宛先ポート p_5989 で2万バイト超を送った通信など）。<code>action=annotate</code> にすると、どの項目が原因かが <code>probable_cause</code> 列に入る</td></tr>
      <tr><td><code>| cluster</code></td>
          <td>イベントの文面がどれだけ似ているかで、イベントをグループにまとめる。<code>t=</code>（0〜1、既定 0.8）を大きくするほど、よく似たものだけがまとまる。グループ番号が <code>cluster_label</code>、グループの件数が <code>cluster_count</code> に入る</td>
          <td><code>index=&lt;インデックス&gt; | cluster showcount=true t=0.8 | sort - cluster_count</code><br/>件数の多いグループから並べると、ログの種類ごとの典型的な1行と件数が分かる。件数が極端に少ないグループは、めったに出ないログとして調べる候補になる</td></tr>
      <tr><td><code>| outlier</code></td>
          <td>名前と違い、外れ値を<b>見つける</b>のではなく、数値の外れ値を<b>取り除く</b>か<b>切り詰める</b>コマンド。四分位範囲（IQR）の <code>param</code> 倍（既定 2.5）を超えた値が対象。ML の学習の前に極端な値を抑える前処理に使う</td>
          <td><code>… | outlier action=transform bytes_received</code> で最大値 667004 が上限の 2081.5 に切り詰められた。<code>action=remove</code> では行は残ったまま、外れた 7906 行の bytes_received が空になった</td></tr>
      <tr><td><code>| kmeans</code></td>
          <td>数値の項目を使って、イベントを k 個のグループに分ける。各グループは、その平均（中心）で表される。グループ番号は <code>CLUSTERNUM</code> 列に入る。AI Toolkit の <code>| fit KMeans</code> と違い、モデルは保存しない</td>
          <td><code>… | kmeans k=3 bytes_sent bytes_received</code><br/>48010 行のふつうの通信と、受信の多い 1437 行、受信がとても多い（平均約11万バイト）553 行の3つに分かれた</td></tr>
    </tbody>
  </table>
  <p class="aitk-note">各コマンドの詳しい書き方は Search Reference（資料のリンク先）にあります。ここに挙げたのは一部で、ほかにも <code>predict</code>、<code>trendline</code>、<code>x11</code> などの統計コマンドがあります。演習1の Search 1-3 で使う <code>predict</code> もその1つです。</p>

  {_layer("#8a3fd1", "Splunkbase Apps")}
  <p>管理者に Splunkbase からアプリを入れてもらえるなら、次の段階に進めます。ML と AI に関係するアプリは、Splunkbase の Machine Learning コレクション（splunkbase.splunk.com/collections/machine_learning）にまとまっています。</p>
  <div class="aitk-split">
    <div>{_slide(37)}</div>
    <div>
      <ul>
        <li><b>Smart Alerts Assistant for Splunk（beta）</b><br/>アナリストがアラートに付けた評価を学習し、アラートごとに優先度を計算して並べ替える。トリアージにかける時間を減らし、優先度の高いものに集中できるようにする</li>
        <li><b>Splunk AI Assistant for SPL</b><br/>ふだんの言葉で書いた質問を SPL に変換し、逆に SPL の意味を言葉で説明する。結果のサーチはそのまま実行するか、元にして書き足せる。資料の時点では Splunk Cloud 向け</li>
      </ul>
    </div>
  </div>
  <div class="aitk-split">
    <div>{_slide(38)}</div>
    <div>{_slide(39)}</div>
  </div>
  <p>AI Assistant は SPL 以外にも広がっています。資料（2025年8月）の時点で、AI Assistant for SPL と Observability Cloud の AI Assistant は提供中、Enterprise Security の AI Assistant はプライベートプレビューでした。今の提供状況は製品のドキュメントで確かめてください。</p>

  {_layer("#d6337f", "Premium Apps")}
  <p>有償のプレミアムアプリには、作り込まれた ML の機能、サーチ、モデルが最初から入っています。自分で作れば何百時間もかかるものを、そのまま使えます。</p>
  <h3>Splunk Enterprise Security と ESCU</h3>
  <div class="aitk-split">
    <div>{_slide(41)}</div>
    <div>{_slide(42)}</div>
  </div>
  <p>ES には ML が組み込まれていて、アナリストが ML を意識しなくても使える形になっています。ML の検知は Splunk の Machine Learning for Security チームが次の順に作っています。</p>
  <ol>
    <li><b>脅威を調べる</b>：新しい脅威と、その動き方を理解する</li>
    <li><b>データセットを作る</b>：データを集めて Splunk で解析し、脅威を見分けられるパターンを探す</li>
    <li><b>ML の検知を作る</b>：データから学習するモデルと、特定の攻撃を見つけるルールやサーチを作る</li>
    <li><b>検知を試す</b>：攻撃者の動きを再現したデータに当て、精度を上げて誤検知を減らす</li>
    <li><b>リリースする</b>：検知をまとめて Splunk のユーザーに届ける</li>
  </ol>
  <p>届ける手段が ESCU（Enterprise Security Content Updates）です。ほぼ隔月で更新される検知サーチの集まりで、ML を使うものも含まれます（資料の画面では machine learning で78件）。データを CIM に合わせてあれば、すぐに使えます。自分のデータでモデルを作るサーチもあれば、学習済みのモデルをそのまま当てるものもあります。中身の複雑なサーチを読むときは、AI Assistant for SPL の説明機能が役に立ちます。</p>
  <h3>Splunk ITSI と Observability</h3>
  <div class="aitk-split">
    <div>{_slide(43)}</div>
    <div>{_slide(45)}</div>
  </div>
  <ul>
    <li><b>ITSI（Splunk の AIOps）</b>：アラートのまとめと削減、季節性を考えた動的なしきい値（Adaptive Thresholds）、異常と外れ値の検知、根本原因の調査の補助、サービスの健全性の予測で、障害を先回りして防ぐ。資料の時点の新機能は、Adaptive Thresholds での外れ値の除外と、ML によるしきい値の提案（プレビュー）</li>
    <li><b>ITSI で ML 自体を監視する</b>：学習したモデルの数や精度、データ収集の欠けまでを1画面で見る MLOps のダッシュボードの例</li>
    <li><b>Observability Cloud の Autodetect</b>：すべてのサービスで性能のベースラインを作り、レイテンシー、エラー、リソース使用率の急な変化をアラートとして提案する。しきい値の調整や、サービスやチームごとの通知の設定もできる</li>
  </ul>
  {_slide(44, "aitk-fig aitk-slide aitk-slide-sm")}

  {_layer("#e8762c", "MLTK（AI Toolkit）")}
  <p>自分で時間をかけてモデルを作りたい、またはプレミアムアプリの ML をさらに進めたいときに使うのが MLTK です。今は AI Toolkit という名前になっています。</p>
  <div class="aitk-split">
    <div>{_slide(47)}</div>
    <div>{_slide(48)}</div>
  </div>
  <ul>
    <li><b>Python for Scientific Computing（PSC）</b>：AI Toolkit が必要とするアプリ。pandas、NumPy、SciPy、scikit-learn、statsmodels などのオープンソースのライブラリを Splunk の Python に足し、300を超えるアルゴリズムを使えるようにする。これらのライブラリを知っていれば、その知識がそのまま使える</li>
    <li><b>Experiments とアシスタント</b>：よくある目的ごとに、モデルの作成、テスト、運用までを画面の案内に沿って進められる。サーチヘッドの上でそのまま動く</li>
    <li><b>80を超える標準のアルゴリズム</b>：教師ありも教師なしも、追加の作業なしで使える</li>
    <li><b>広げる手段</b>：PSC のライブラリのほか、DSDL（ニューラルネットワークや GPU）と、任意のオープンソースや自作のアルゴリズムを取り込む ML-SPL API がある</li>
  </ul>
  <div class="aitk-split">
    <div>{_slide(49)}</div>
    <div>
      <p>MLTK は、データサイエンティストでない人が使うこと（シチズンデータサイエンティスト）を前提に作られています。最初は画面の案内で結果まで進み、<b>Show SPL</b> で裏で動いている SPL を見れば、次からは SPL で直接書けます。</p>
      <p>左の画面は演習1の Showcase です。SPL の各行に、何をしているかのコメントが付いています。演習ページの「この SPL の読み方」も同じ考え方です。</p>
    </div>
  </div>

  {_layer("#d9b52c", "DSDL")}
  <div class="aitk-split">
    <div>{_slide(52)}</div>
    <div>{_slide(53)}</div>
  </div>
  <p>Splunk App for Data Science and Deep Learning（DSDL、旧 Deep Learning Toolkit）は、ML の学習を Splunk のサーチヘッドの外にあるコンテナに任せるアプリです。</p>
  <ul>
    <li><b>フレームワーク</b>：PyTorch、TensorFlow、spaCy、Jupyter Notebook など、オープンソースの AI のフレームワークをそのまま使える</li>
    <li><b>コード例</b>：深層学習のモデルの作成、テスト、運用の手順が例として入っている</li>
    <li><b>GPU と Kubernetes</b>：GPU を積んだコンテナで学習を速くし、Kubernetes で規模の拡大と冗長化ができる</li>
    <li><b>Splunk との統合</b>：外部のコンテナで動いていても、使い方は MLTK と同じ <code>| fit … into "model"</code> と <code>| apply "model"</code>。Notebook の中から SPL を使うこともできる</li>
  </ul>
</section>

<section>
  <h2>機械学習の種類とどこから始めるか</h2>
  <p>ML のプロジェクトを成功させるには、データを理解し、きれいにして、運用に乗せるまでを順に進めます。最初に、どの種類の ML を使うかを決めます。</p>
  <table class="aitk-table">
    <thead><tr><th>種類</th><th>中身</th><th>この講座では</th></tr></thead>
    <tbody>
      <tr><td><b>教師あり学習</b></td><td>正解のラベルが付いたデータで学ぶ。回帰と分類</td><td>演習2のマルウェア予測</td></tr>
      <tr><td><b>教師なし学習</b></td><td>ラベルの無いデータから、まとまりや外れを見つける。クラスタリングと異常検知</td><td>演習1の外れ値検知</td></tr>
      <tr><td><b>組み合わせ</b></td><td>強化学習や人のフィードバックを取り込みながら育てる。人が判断に加わる仕組みから、自律的に動く仕組みまで</td><td>―</td></tr>
    </tbody>
  </table>
  <h3>どこから始めるか</h3>
  <table class="aitk-table">
    <thead><tr><th>分野</th><th>セキュリティでの例</th></tr></thead>
    <tbody>
      <tr><td>異常検知</td><td>過去の自分からのずれ、同じグループの仲間からのずれ（多変量の異常検知）、特徴の急な変化</td></tr>
      <tr><td>クラスタリング</td><td>似た者同士のグループ分け、イベントの相関、アラートのノイズ削減、振る舞いの分析</td></tr>
      <tr><td>予測分析</td><td>イベントの予測、傾向の予測、影響している要素の発見、早期の警告</td></tr>
    </tbody>
  </table>
</section>

<section>
  <h2>良いデータかどうか</h2>
  <p>機械のデータは複雑です。ML に答えを出させるには、先にデータを理解しておく必要があります。次の5つがどれも無ければ、そのまま ML を始められます。あれば、集め直すか、きれいにしてからです。資料の図と合わせて見ていきます。</p>

  <h3>欠けたデータ（Missing Data）</h3>
  <div class="aitk-split aitk-split-top">
    <div>{img("rk_p058.jpg", "aitk-fig aitk-fig-dark")}</div>
    <div>
      <p>ML は魔法のように見えますが、データに無いことには答えられません。</p>
      <p><b>図の見方</b>：上の表は、Web のアクセスログの <code>clientip</code> から <code>iplocation</code> で国（Country）と都市（City）を付けた結果です。位置のデータベースで場所が分からなかったアドレスは、国も都市も空のままです。下の表は、空の欄に <code>fillnull</code> で unknown を入れた後です。</p>
      <p><b>起きること</b>：学習に使えるデータが減ってモデルの性能が落ちる。項目同士の関係が崩れて、パターンを学べなくなる。欠けが特定のグループに偏っていると、予測も偏る。評価の数字もゆがむので、本当の性能が分からなくなる。</p>
    </div>
  </div>

  <h3>ノイズ（Noisy Data）</h3>
  <div class="aitk-split aitk-split-top">
    <div>{img("rk_p059.jpg", "aitk-fig")}</div>
    <div>
      <p>ノイズとは、誤った値、関係の無い値、ランダムな揺れのことです。機械が出すデータには多く含まれます。</p>
      <p><b>図の見方</b>：ディスクの SMART 値をいくつも重ねたグラフです。色の違う線がびっしり重なり、どこに意味のある動きがあるのか目では分かりません。中に価値のある情報があっても、先にノイズを減らさないと ML も同じように見失います。</p>
      <p><b>起きること</b>：本当の関係を学べず学習が混乱する。予測の精度が落ちる。ノイズそのものを覚えてしまい（過学習）、新しいデータでは外れる。</p>
    </div>
  </div>

  <h3>偏り（Bias）</h3>
  <div class="aitk-split aitk-split-top">
    <div>{img("rk_p060.jpg", "aitk-fig aitk-fig-dark")}</div>
    <div>
      <p>偏りとは、特定のパターンやグループを優遇してしまう、系統的な誤りや思い込みのことです。人と同じで、データもある出来事ばかりを多く見ていると、それが当たり前だと思い込みます。</p>
      <p><b>図の見方</b>：的の中心が正解です。左（Low Bias）は、予測の点が中心に集まっています。右（High Bias）は、点どうしはまとまっているのに、中心から外れた場所に集まっています。毎回同じ方向に外れるのが偏りで、何度やり直しても正解に近づきません。</p>
      <p><b>起きること</b>：不公平な予測や差別的な結果になる。誤った洞察を導き、モデルが信頼されなくなる。</p>
    </div>
  </div>

  <h3>重複（Duplicate Data）</h3>
  <div class="aitk-split aitk-split-top">
    <div>{img("rk_p061.jpg", "aitk-fig")}</div>
    <div>
      <p>同じ記録が何度も入っていると、その記録の重みだけが大きくなり、データの見え方がゆがみます。</p>
      <p><b>図の見方</b>：上の表は、住宅ローンのデータで Year が 1978、1978、1979、1979… と重複しています。<code>| inputlookup mortgage_loan_ny_duplicates.csv | dedup Year</code> で重複を取り除くと、下の表のように 1978、1979、1980、1981… と1年1行になります。</p>
      <p><b>起きること</b>：重複したパターンを過大に信じて学習がゆがむ。特定の種類に重複が偏ると結果も偏る。初めて見るデータに弱くなる。無駄な計算が増える。</p>
    </div>
  </div>

  <h3>外れ値（Outliers）</h3>
  <div class="aitk-split aitk-split-top">
    <div>{img("rk_p062.jpg", "aitk-fig")}</div>
    <div>
      <p>外れ値とは、大多数から大きく離れた点です。極端な値のこともあれば、単なる誤りのこともあります。</p>
      <p><b>図の見方</b>：演習1のログイン数の Showcase と同じグラフです。水色の帯がふだんの範囲で、帯を突き抜けた黄色の点が外れ値です。人なら「この点はふつうではないから計算から外そう」と判断できますが、アルゴリズムは渡されたデータを<b>すべて</b>使います。</p>
      <p><b>起きること</b>：極端な点に学習が引っぱられる。平均や分散が大きく動き、評価の数字が実際より良くも悪くも見える。前処理の手間が増える。ふだんの範囲を学ばせたいときは、先に外れ値を除いておく（<code>| outlier</code> コマンドがその道具）。</p>
    </div>
  </div>
</section>

<section>
  <h2>Splunk の上で ML の流れを完結させる</h2>
  {_slide(64)}
  <p>ML と AI を実装するには、ふつうはたくさんの道具が要ります。データを置くデータレイク、データを整える ETL、ML の計算基盤、それらをまとめて動かす仕組み、そして全体を見張る監視の仕組みです。Splunk では、これを1つのプラットフォームで行えます。</p>
  <table class="aitk-table">
    <thead><tr><th>ステップ</th><th>担当</th><th>中身</th></tr></thead>
    <tbody>
      <tr><td>データの収集</td><td>Ecosystem ＋ Splunk</td><td>Splunkbase の何千ものアドオンでデータを取り込み、構造を与える</td></tr>
      <tr><td>クレンジングと整形</td><td>Ecosystem ＋ Splunk</td><td>SPL とアドオンでデータをきれいにする</td></tr>
      <tr><td>検索と探索</td><td>Ecosystem ＋ Splunk</td><td>サーチでデータの中身を確かめる</td></tr>
      <tr><td>前処理と特徴の選択</td><td>MLTK ＋ Splunk</td><td>StandardScaler、PCA、FieldSelector などで学習用に整える</td></tr>
      <tr><td>アルゴリズムの選択</td><td>MLTK ＋ Splunk</td><td>目的に合うアルゴリズムを選ぶ（アルゴリズムの早見表）</td></tr>
      <tr><td>モデルの作成、テスト、改善</td><td>MLTK ＋ Splunk</td><td>fit、score、Experiments で作って比べる</td></tr>
      <tr><td>運用、監視、アラート</td><td>MLTK ＋ Splunk</td><td>apply をスケジュール検索やアラートにする</td></tr>
      <tr><td>可視化と共有</td><td>Ecosystem ＋ Splunk</td><td>ダッシュボードで結果をチームに見せる</td></tr>
    </tbody>
  </table>
  <p>Splunk だけでも流れは回りますが、MLTK を足すと前処理からモデルの運用までが強くなります。どれも Splunk とそのエコシステムに統合されています。</p>
</section>

<section>
  <h2>ML に必要な3つの専門性</h2>
  <div class="aitk-split">
    <div>{_slide(65)}</div>
    <div>
      <p>AI Toolkit をうまく使っているお客様を見ると、3つの専門性がそろっています。</p>
      <ol>
        <li><b>業務の専門性（IT、セキュリティなど）</b>：ユースケースを見つけ、判断を下し、業務への影響を理解する</li>
        <li><b>Splunk の専門性</b>：サーチ、レポート、アラート、ワークフロー</li>
        <li><b>データサイエンスの専門性</b>：統計と数学の素養、アルゴリズムの選択、モデルの作成</li>
      </ol>
      <p>3つの円が重なるところに、MLTK と DSDL があります。業務と Splunk の重なりには、ML を最初から組み込んだプレミアムアプリと無料のアプリがあります。MLTK は例と案内で、データサイエンスの部分を補います。</p>
    </div>
  </div>
  <p><b>始めるのは業務の専門家から</b>です。たとえばセキュリティアナリストが「このマルウェアが動いていないかを知りたい。手がかりの1つとして、C2 通信に使われる DGA（ドメイン生成アルゴリズム）のドメインを見つけたい」と決めれば、何を探すかがはっきりします。そこから Splunk の専門家が DNS のデータを探し、ドメイン名を取り出し、既存のダッシュボードやレポートを確かめます。データサイエンスの知識が要るのは、その後のモデルの部分だけです。</p>
</section>

<section>
  <h2>データサイエンティストが実際にやっていること</h2>
  <div class="aitk-split">
    <div>{_slide(66)}</div>
    <div>
      <p class="aitk-big">約80%</p>
      <p>Forbes の調査（2016年3月）では、データサイエンティストの作業時間の内訳は次のとおりです。</p>
      <table class="aitk-table">
        <tbody>
          <tr><td>データのクレンジングと整理</td><td><b>60%</b></td></tr>
          <tr><td>データセットの収集</td><td><b>19%</b></td></tr>
          <tr><td>パターンを探すデータマイニング</td><td>9%</td></tr>
          <tr><td>アルゴリズムの改良</td><td>4%</td></tr>
          <tr><td>トレーニングセットの作成</td><td>3%</td></tr>
          <tr><td>その他</td><td>5%</td></tr>
        </tbody>
      </table>
    </div>
  </div>
  <p>収集と整理だけで約8割です。データマイニングまで含めると、データサイエンスの専門知識が要るのは全体の1〜2割ほどしかありません。生のログファイルを開いて中から必要な情報を探したことがある人なら、残りの8割はすでに毎日やっている仕事です。そしてその8割は、データがすでに集まっている Splunk の上で SPL を使って行えます。</p>
</section>

<section>
  <h2>収集からモデルの運用まで</h2>
  <p>ここからは、1本のサーチを1行ずつ育てながら、データの収集からモデルの運用までをたどります。資料では Web ショップのアクセスログ（<code>sourcetype=access_combined</code>）を使っています。</p>

  <h3>1. 集める</h3>
  <p>機械が読める形のデータであれば、種類を問わず Splunk に取り込めます。資料では、ML に使えるのにまだ活かされていないことが多いデータとして、次の5つを挙げています。</p>
  <ul>
    <li>インフラのデータ</li>
    <li>アプリケーションの利用とアクセスのデータ</li>
    <li>生成 AI のプロンプトと出力のデータ</li>
    <li>ヘルプデスクやチケットシステムのデータ</li>
    <li>IoT と OT のデータ</li>
  </ul>

  <h3>2. 規模を気にせず貯める</h3>
  <p>拡張できるインデックスとストレージ、オンプレミスとクラウドを選べる提供形態、複数の場所のデータをまとめて分析する Federated Analytics があります。1日にペタバイト単位を取り込むお客様もいます。ML の流れでいう<b>データの置き場所</b>は、これで満たせます。</p>

  <h3>3. データを理解する</h3>
  <div class="aitk-split">
    <div>{_slide(72)}</div>
    <div>
      <p>大量の機械のデータは、ぱっと見では乱雑で複雑です。図のアクセスログの1行も、そのままでは読みにくい文字列です。</p>
      <p>ところが、この1行には価値のある情報が詰まっています。ユーザーの IP（64.66.0.20）、見た商品（CC-P3-BELKIN-SILBLKIPH5）、使っている言語（FR-fr）、端末（Android の Chrome）です。</p>
      <p>Splunk は取り込みのときに sourcetype に合わせてこれらをフィールドとして取り出し、CIM（Common Information Model）に合わせてそろえます。ETL の Extract にあたる部分です。ではこのユーザーは<b>どの国から</b>アクセスしているのか。それは次の手順で確かめます。</p>
    </div>
  </div>

  <h3>4. 良いデータかを確かめる</h3>
  <p>上の「良いデータかどうか」の5つ（欠け、ノイズ、偏り、重複、外れ値）を、SPL で1つずつ確かめながら整えていきます。ここからが ETL の Transform です。</p>

  <h3>5. SPL で準備して、学習して、運用する</h3>
  <table class="aitk-table aitk-table-fixed">
    <thead><tr><th style="width:120px;">段階</th><th style="width:36%;">サーチに足す行</th><th>何をしているか</th></tr></thead>
    <tbody>
      <tr><td><b>Access</b></td><td><code>index="oidemo" sourcetype="access_combined"</code></td>
          <td>データの置き場所（index）と種類（sourcetype）を指定する。sourcetype が決まると、取り出されるフィールドも決まる</td></tr>
      <tr><td><b>Filter</b></td><td><code>action=purchase</code></td>
          <td>取り込み時に取り出した action フィールドで絞る。action には purchase、addtocart、view、remove、changequantity の5種類があり、購入（purchase）だけを残す。図は、絞り込みの前後でフィールドの値の一覧がどう変わるか</td></tr>
      <tr><td><b>Transform</b></td><td><code>| iplocation clientip</code></td>
          <td>IP アドレスから国や都市を調べて、Country と City の列を足す。「どの国からか」という問いにここで答えられる。ただし図のとおり、場所が分からない IP は空のまま</td></tr>
      <tr><td><b>Clean</b></td><td><code>| fillnull value="Unknown" Country</code></td>
          <td>ML は空の値を推測で補ってくれない。空のまま学習すると結果がゆがむので、空の Country に Unknown を入れる。fillnull は、データを整えるための数ある SPL コマンドの1つ</td></tr>
      <tr><td><b>Aggregate</b></td><td><code>| stats count by product device Country</code></td>
          <td>商品、端末、国の組み合わせごとに件数を数え、学習に使う形にまとめる。必要なデータだけを、目的に合った形でモデルに渡す。ここまでの数行で、データサイエンティストの時間の8割にあたる準備が済んでいる</td></tr>
      <tr><td><b>Train</b></td><td><code>| fit algorithm from clientip into "model"</code></td>
          <td>モデルを学習する。fit の後ろにアルゴリズム名、from の後ろに入力の項目、into の後ろに保存するモデル名を書く。fit や apply は ML の世界の標準の用語。資料の行は形を示すための書き方で、実際には algorithm に LogisticRegression などの名前を入れる。保存は必須ではないが、学習は重いので毎回やり直すのは得策ではない</td></tr>
      <tr><td><b>Apply</b></td><td><code>| apply "model"</code></td>
          <td>学習が済んだら fit の行は要らない。代わりに apply で保存したモデルを当てる。apply の前の行（Access から Aggregate まで）は、<b>学習のときと同じ</b>にしておく。項目の作り方や埋め方が違うと、モデルは正しく判定できない</td></tr>
    </tbody>
  </table>
  <div class="aitk-pipeline-figs">
    <div><span>Filter</span>{img("rk_p075.jpg", "aitk-fig aitk-fig-dark")}</div>
    <div><span>Transform</span>{img("rk_p076.jpg", "aitk-fig aitk-fig-dark")}</div>
    <div><span>Clean</span>{img("rk_p077.jpg", "aitk-fig aitk-fig-dark")}</div>
    <div><span>Aggregate</span>{img("rk_p078.jpg", "aitk-fig aitk-fig-dark")}</div>
    <div><span>Train</span>{img("rk_p079.jpg", "aitk-fig aitk-fig-dark")}</div>
    <div><span>Apply</span>{img("rk_p080.jpg", "aitk-fig aitk-fig-dark")}</div>
  </div>

  <h3>6. 学習と運用の全体</h3>
  <div class="aitk-split">
    <div>{_slide(81)}</div>
    <div>
      <p>ここまでの手順のうち、ML に特有なのは <code>fit</code> と <code>apply</code> だけです。それ以外は、ML を使わない Splunk ユーザーも毎日使っているコマンドです。</p>
      <ul>
        <li><code>fit</code> に <code>into</code> を付けて学習すると、モデルが persisted model として保存される</li>
        <li>保存したモデルは、サーチに <code>| apply モデル名</code> を足すだけで運用に乗る</li>
        <li>その結果を、最初の図と同じくアラートや可視化につなげる</li>
      </ul>
      <p>演習2では、この流れを firewall_traffic.csv で実際にたどります（Filter の代わりに <code>head</code> と <code>sample</code>、Train が <code>fit LogisticRegression</code>、Apply が <code>apply example_malware</code>）。</p>
    </div>
  </div>
</section>

<section>
  <h2>AI Toolkit のコマンドとアルゴリズム</h2>
  <table class="aitk-table">
    <thead><tr><th>コマンド</th><th>何をするか</th></tr></thead>
    <tbody>
      <tr><td><code>fit</code></td><td>モデルを学習し、その場で結果にも当てる</td></tr>
      <tr><td><code>apply</code></td><td>fit で学習したモデルを当てる</td></tr>
      <tr><td><code>summary</code></td><td>モデルの中身をまとめて出す</td></tr>
      <tr><td><code>listmodels</code></td><td>モデルの一覧を出す</td></tr>
      <tr><td><code>deletemodel</code></td><td>モデルを消す</td></tr>
      <tr><td><code>sample</code></td><td>ランダムに抜き出す、または分ける</td></tr>
      <tr><td><code>score</code></td><td>モデルの結果を統計的に評価する</td></tr>
    </tbody>
  </table>
  <h3>アルゴリズムの早見表</h3>
  {img("r83_0.jpg", "aitk-fig aitk-fig-wide")}
</section>

<section>
  <h2>ハンズオンで使うツールとデータ</h2>
  <table class="aitk-table">
    <thead><tr><th>演習</th><th>使うもの</th><th>データ</th></tr></thead>
    <tbody>
      <tr><td>演習1 ユーザーの振る舞いの外れ値</td><td>AI Toolkit の Detect Numeric Outliers（MAD）</td><td><code>logins.csv</code>（AI Toolkit のサンプル。このアプリにも同梱）</td></tr>
      <tr><td>演習2 マルウェアの予測</td><td>AI Toolkit の Predict Categorical Fields（LogisticRegression、RandomForestClassifier）</td><td><code>firewall_traffic.csv</code>（同上）</td></tr>
      <tr><td>演習3 ES での運用</td><td>Splunk Enterprise Security 8.x の Event-based detection、Mission Control</td><td>演習2のモデル</td></tr>
    </tbody>
  </table>
  <p>AI Toolkit、Python for Scientific Computing、Enterprise Security が必要です。Primer と違い、BOTS v2 のデータは使いません。</p>
</section>

<section>
  <h2>AI Toolkit のアルゴリズム一覧</h2>
  <p>資料の3つの大項目（外れ値の検知、予測、分類・グループ分け）ごとに、AI Toolkit 6.1 のアルゴリズムの特徴と使いどころをまとめたページを、メニューの <b>アルゴリズム</b> に用意しています。</p>
  <ul>
    <li><a href="algo_overview">概要：3つの大項目と選び方、下ごしらえと分析</a></li>
    <li><a href="algo_outlier">外れ値（Outlier）：DensityFunction、MultivariateOutlierDetection、LocalOutlierFactor、OneClassSVM など</a></li>
    <li><a href="algo_predictive">予測（Predictive）：回帰、分類、時系列の予測</a></li>
    <li><a href="algo_categorization">分類（Categorization）：クラスタリング、つながりの分析</a></li>
  </ul>
</section>

<footer class="aitk-next">
  <b>次はハンズオン</b>
  <a href="rookies_ex1">演習1 ユーザーの振る舞いの外れ値 →</a>
  <a href="rookies_ex2">演習2 マルウェアの通信の予測 →</a>
  <a href="rookies_ex3">演習3 ML を ES で運用 →</a>
</footer>
</div>
'''


# ================================================================ Algorithm reference pages
ALGO_OVERVIEW = '<div class="aitk-doc"><header class="aitk-doc-hero"><span class="aitk-kicker">アルゴリズム ／ 概要</span><h1>AI Toolkit のアルゴリズム</h1><p>この検証環境の AI Toolkit 6.1 には51のアルゴリズムが入っています。資料にならって、外れ値の検知、予測、分類・グループ分けの3つの大項目に分け、どれにも入らない下ごしらえ用のものを別にまとめました。</p></header><section><h2>3つの大項目</h2><table class="aitk-table"><thead><tr><th style="width:24%;">大項目</th><th>何をするか</th><th style="width:30%;">中の分け方</th></tr></thead><tbody><tr><td><a href="algo_outlier"><b>外れ値の検知（Outlier）</b></a></td><td>ふだんの範囲を学び、そこから外れた振る舞いを見つけて調べる。ラベルの要らない教師なし学習</td><td>数値の項目、カテゴリの項目</td></tr><tr><td><a href="algo_predictive"><b>予測（Predictive）</b></a></td><td>これから起きそうなことに先回りする。正解の付いたデータで学ぶ教師あり学習と、時系列の予測</td><td>数値の予測（回帰）、カテゴリの予測（分類）、時系列の予測</td></tr><tr><td><a href="algo_categorization"><b>分類・グループ分け（Categorization）</b></a></td><td>データの中身を知って、いま起きていることにすばやく対応する</td><td>クラスタリング、つながりの分析、カテゴリの予測（分類）</td></tr></tbody></table><p>カテゴリの予測（分類）は、資料では予測にも分類・グループ分けにも入っています。このメニューでは<a href="algo_predictive">予測</a>のページに載せています。</p></section><section><h2>選び方</h2><ol><li><b>目的から大項目を決める</b>：ふだんとの違いを探すなら外れ値、正解のあるものを当てるなら予測、似た者同士をまとめるなら分類・グループ分け</li><li><b>項目の種類で絞る</b>：目的の項目が数値なら回帰、カテゴリなら分類。外れ値も、元の項目が数値かカテゴリかで道具が変わる</li><li><b>速くて説明しやすいものを基準にする</b>：LinearRegression、LogisticRegression、KMeans、DensityFunction から始める</li><li><b>score で比べる</b>：演習2のように、学習に使わなかったデータで評価しながら、ほかのアルゴリズムを試す</li><li><b>運用するなら保存できるものを選ぶ</b>：アラートや ES の検知で apply したいなら、保存の列が ○ のもの</li></ol><h3>アルゴリズムの早見表</h3><img class="aitk-fig aitk-fig-wide" src="/static/app/aitk_security_training/img/r83_0.jpg"/></section><section><h2>下ごしらえと分析</h2><p>3つの大項目のどれでもなく、学習の前にデータを整えたり、データの性質を調べたりするものです（資料の Prepare Data と Analyze）。</p>\n  <table class="aitk-table aitk-table-fixed"><thead><tr><th style="width:19%;">アルゴリズム</th><th style="width:37%;">特徴</th><th>どんなときに使うか（セキュリティの例）</th><th style="width:7%;">保存</th></tr></thead><tbody><tr><td><code>StandardScaler／RobustScaler</code></td><td>項目の単位や大きさをそろえる。StandardScaler は平均と標準偏差、RobustScaler は中央値と四分位範囲を使うので外れ値に強い</td><td>バイト数とパケット数のように桁の違う項目を、距離を使うアルゴリズム（KMeans、SVM、MLP）に渡す前</td><td style="text-align:center;">○</td></tr><tr><td><code>Imputer</code></td><td>欠けた値を平均、中央値、最頻値などで埋め、Imputed_&lt;項目&gt; 列を作る。この環境ではモデルの保存がエラーになった</td><td>欠けたデータ（Summary の良いデータかどうか）を学習の前に補うとき</td><td style="text-align:center;">×</td></tr><tr><td><code>PCA／KernelPCA／ICA</code></td><td>たくさんの数値の項目を、情報をなるべく残したまま少ない成分にまとめる。KernelPCA は曲がった関係、ICA は互いに独立な成分を取り出す</td><td>項目が多すぎるときや、グラフに描くために2〜3次元に減らしたいとき</td><td style="text-align:center;">○</td></tr><tr><td><code>FieldSelector</code></td><td>目的の項目との関係が強い入力だけを統計の検定で選ぶ</td><td>どの項目を予測に使えばよいか分からないとき</td><td style="text-align:center;">○</td></tr><tr><td><code>TFIDF／HashingVectorizer</code></td><td>文字列を単語や文字の出現の数値に変える。HashingVectorizer は保存できない</td><td>URL、コマンドライン、メールの件名などの文字列を、分類やクラスタリングに使いたいとき</td><td style="text-align:center;">○／×</td></tr><tr><td><code>NPR</code></td><td>値の種類が多いカテゴリの項目を、目的のクラスごとの割合（NPR_&lt;項目&gt;_&lt;クラス&gt;）の数値に変える。この環境では dest_port から NPR_dest_port_yes などができた</td><td>演習2の dest_port や dst_ip のように、種類が100を超えて学習から外されてしまう項目を使いたいとき</td><td style="text-align:center;">○</td></tr><tr><td><code>ACF／PACF</code></td><td>時系列の自己相関を求め、何点ごとに周期があるかを調べる。保存はできない</td><td>ARIMA や StateSpaceForecast の前に、1日や1週間の周期があるかを確かめるとき</td><td style="text-align:center;">×</td></tr><tr><td><code>AITKContainer</code></td><td>学習と推論を外部のコンテナに任せる（DSDL と同じ仕組み）。コンテナの接続先の設定が必要で、この環境では未設定</td><td>深層学習や GPU を使いたいとき（ピラミッドの DSDL の層）</td><td style="text-align:center;">―</td></tr></tbody></table><p class="aitk-note"><b>保存</b>の列は、<code>into</code> でモデルを保存できるか（あとで <code>apply</code> できるか）を、この検証環境の AI Toolkit 6.1 で実際に試した結果です。× は使うたびに fit します。「―」はモデルを作らないものです。</p></section><footer class="aitk-next"><b>アルゴリズム</b><a href="algo_overview">概要</a><a href="algo_outlier">外れ値（Outlier）</a><a href="algo_predictive">予測（Predictive）</a><a href="algo_categorization">分類（Categorization）</a></footer></div>'
ALGO_OUTLIER = '<div class="aitk-doc"><header class="aitk-doc-hero"><span class="aitk-kicker">アルゴリズム ／ 外れ値（Outlier）</span><h1>外れ値の検知のアルゴリズム</h1><p>ふだんの範囲を学び、そこから外れた点を見つけます。ラベルの要らない教師なし学習です。元の項目が数値かカテゴリかで、使う道具が変わります。</p></header><section><h2>数値の項目</h2><p>ふだんの範囲を学び、そこから外れた点を見つけます。ラベルの要らない教師なし学習です。演習1の MAD（中央値からのずれ）はアルゴリズムではなく、SPL の統計で計算する方法です。</p>\n  <table class="aitk-table aitk-table-fixed"><thead><tr><th style="width:19%;">アルゴリズム</th><th style="width:37%;">特徴</th><th>どんなときに使うか（セキュリティの例）</th><th style="width:7%;">保存</th></tr></thead><tbody><tr><td><code>DensityFunction</code></td><td>1つの数値の分布（正規、指数、ガウス KDE、ベータ）を推定し、起きる確率がとても低い端を外れ値にする。<code>by</code> で時間帯などのグループごとに分布を分けられる。入力は1項目だけ</td><td>時間帯ごとのログオン失敗数、通信量、CPU 使用率など、1つの指標のふだんの範囲を作りたいとき（Primer のシナリオ1・2・4）</td><td style="text-align:center;">○</td></tr><tr><td><code>MultivariateOutlierDetection</code></td><td>複数の数値を StandardScaler でそろえ、PCA で1つの成分（PC_1）にまとめてから DensityFunction を当てる。この環境では SS_*、PC_1、IsOutlier(PC_1) の列が出た</td><td>送信バイト数、受信バイト数、パケット数のように、1つずつではふつうでも組み合わせると不自然な通信を見つけたいとき</td><td style="text-align:center;">○</td></tr><tr><td><code>LocalOutlierFactor</code></td><td>その点のまわりの密度を、近くの点のまわりの密度と比べる。全体の範囲の中にあっても、仲間のいない点を外れ値にできる</td><td>まとまりがいくつもある多次元のデータを、その場で調べるとき。モデルを保存できないので、アラートには毎回 fit する形になる</td><td style="text-align:center;">×</td></tr><tr><td><code>OneClassSVM</code></td><td>正常なデータだけから、ふだんの領域の境界を学ぶ。結果は isNormal 列に入る。データが多いと学習が重い</td><td>攻撃のデータが手に入らず、正常な通信や操作のデータだけで基準を作りたいとき</td><td style="text-align:center;">○</td></tr><tr><td><code>AutoAnomalyDetection</code></td><td>Splunk App for Anomaly Detection のジョブが裏で使う。1項目だけで、job_name の指定が必須</td><td>直接は使わない。このアプリは 2025年6月でサポートが終わっている（Primer シナリオ2）</td><td style="text-align:center;">―</td></tr></tbody></table><p class="aitk-note">演習1の MAD（中央値からのずれ）と Primer の平均±2σはアルゴリズムではなく、SPL の統計で計算する方法です。</p><p class="aitk-note"><b>保存</b>の列は、<code>into</code> でモデルを保存できるか（あとで <code>apply</code> できるか）を、この検証環境の AI Toolkit 6.1 で実際に試した結果です。× は使うたびに fit します。「―」はモデルを作らないものです。</p></section><section><h2>カテゴリの項目</h2><table class="aitk-table aitk-table-fixed"><thead><tr><th style="width:19%;">アルゴリズム</th><th style="width:37%;">特徴</th><th>どんなときに使うか（セキュリティの例）</th><th style="width:7%;">保存</th></tr></thead><tbody><tr><td><code>| anomalydetection（コマンド）</code></td><td>値の組み合わせがどれくらい起きやすいかを確率で求め、めったに起きない組み合わせを取り出す。AI Toolkit の Detect Categorical Outliers アシスタントが使う</td><td>ユーザー、アプリ、国の組み合わせなど、カテゴリの項目で珍しいものを探すとき</td><td style="text-align:center;">―</td></tr><tr><td><code>（One-hot エンコーディング）</code></td><td>カテゴリの値ごとに 0／1 の列を作り、数値のアルゴリズムで扱えるようにする。fit が自動で行う</td><td>上の数値のアルゴリズムに、OS や権限のようなカテゴリの項目も混ぜたいとき。値の種類が100を超える項目は既定で学習から外される</td><td style="text-align:center;">―</td></tr></tbody></table></section><footer class="aitk-next"><b>アルゴリズム</b><a href="algo_overview">概要</a><a href="algo_outlier">外れ値（Outlier）</a><a href="algo_predictive">予測（Predictive）</a><a href="algo_categorization">分類（Categorization）</a></footer></div>'
ALGO_PREDICTIVE = '<div class="aitk-doc"><header class="aitk-doc-hero"><span class="aitk-kicker">アルゴリズム ／ 予測（Predictive）</span><h1>予測のアルゴリズム</h1><p>正解の値が付いたデータで学び、まだ分からない値を当てます。目的の項目が数値なら回帰、カテゴリなら分類を使います。時間とともに変わる値の先行きは、時系列の予測で求めます。</p></header><section><h2>数値の予測（回帰）</h2><p>正解の値が付いたデータで学ぶ教師あり学習です。目的の項目が数値なら回帰、カテゴリなら分類を使います。</p>\n  <table class="aitk-table aitk-table-fixed"><thead><tr><th style="width:19%;">アルゴリズム</th><th style="width:37%;">特徴</th><th>どんなときに使うか（セキュリティの例）</th><th style="width:7%;">保存</th></tr></thead><tbody><tr><td><code>LinearRegression</code></td><td>入力と目的の値の関係を直線（平面）で表す。速く、係数で関係を説明しやすい</td><td>まず試す基準として。ユーザー数から通信量を見積もるなど、関係がほぼ比例するとき</td><td style="text-align:center;">○</td></tr><tr><td><code>Ridge／Lasso／ElasticNet</code></td><td>LinearRegression に、係数が大きくなりすぎないための罰則を加えたもの。Lasso は効かない入力の係数を 0 にして、項目を絞り込む。ElasticNet は両方の中間</td><td>入力の項目が多く、互いに似た項目（送受信のバイト数とパケット数など）が混じっているとき</td><td style="text-align:center;">○</td></tr><tr><td><code>KernelRidge</code></td><td>カーネルで曲がった関係も表せる Ridge。データが多いと重い</td><td>関係が直線ではなく、データが数千行程度までのとき</td><td style="text-align:center;">○</td></tr><tr><td><code>DecisionTreeRegressor</code></td><td>しきい値の分かれ道を重ねて値を予測する。結果を説明しやすいが、学習データに合わせすぎやすい</td><td>どの条件で値が大きくなるのかを人が読みたいとき</td><td style="text-align:center;">○</td></tr><tr><td><code>RandomForestRegressor／GradientBoostingRegressor</code></td><td>決定木をたくさん組み合わせる。RandomForest は多数決で安定、GradientBoosting は前の木の誤りを順に直すので精度が出やすいが調整が要る</td><td>関係が複雑で、精度を優先したいとき</td><td style="text-align:center;">○</td></tr><tr><td><code>SGDRegressor</code></td><td>少しずつ学習する線形回帰。partial_fit で、前のモデルに新しいデータを足して学習し直せる</td><td>データが大きく、毎日の新しいデータでモデルを少しずつ更新したいとき</td><td style="text-align:center;">○</td></tr><tr><td><code>SystemIdentification</code></td><td>複数の時系列から、時間の遅れ（どれだけ前の値が効くか）を考えて目的の値を予測する。_time と dynamics の指定が必要</td><td>複数のサーバーの負荷や通信量の動きから、後に続く指標の値を予測したいとき</td><td style="text-align:center;">○</td></tr></tbody></table><p class="aitk-note"><b>保存</b>の列は、<code>into</code> でモデルを保存できるか（あとで <code>apply</code> できるか）を、この検証環境の AI Toolkit 6.1 で実際に試した結果です。× は使うたびに fit します。「―」はモデルを作らないものです。</p></section><section><h2>カテゴリの予測（分類）</h2><p>資料の Categorical Regression で、Categorization にも入っています。F1 は演習2（firewall_traffic.csv、70/30）の結果です。</p>\n  <table class="aitk-table aitk-table-fixed"><thead><tr><th style="width:19%;">アルゴリズム</th><th style="width:37%;">特徴</th><th>どんなときに使うか（セキュリティの例）</th><th style="width:7%;">保存</th></tr></thead><tbody><tr><td><code>LogisticRegression</code></td><td>yes／no などの確率を線形のモデルで求める。速く、まず試す基準になる</td><td>演習2の最初のモデル。この環境では F1 0.79</td><td style="text-align:center;">○</td></tr><tr><td><code>SVM</code></td><td>カーネルで曲がった境界を引ける。この環境では学習が1万行に間引かれ、演習2のデータでは F1 0.46 だった</td><td>データが中くらいまでで、境界が複雑なとき</td><td style="text-align:center;">○</td></tr><tr><td><code>RandomForestClassifier</code></td><td>決定木の多数決。外れ値や偏ったデータに比較的強く、どの入力が効いたかを summary で見られる</td><td>演習2で採用（F1 0.99）。通信やイベントの記録から、マルウェアか、真陽性かを当てたいときの第一候補</td><td style="text-align:center;">○</td></tr><tr><td><code>DecisionTreeClassifier</code></td><td>しきい値の分かれ道で分ける。判定の理由を説明しやすい</td><td>判定のルールを人が読んで、検知のサーチに書き直したいとき（演習2では F1 0.99）</td><td style="text-align:center;">○</td></tr><tr><td><code>GradientBoostingClassifier</code></td><td>前の木の誤りを順に直していく。精度が出やすいが、学習が遅く調整が要る</td><td>RandomForest で足りないときに試す</td><td style="text-align:center;">○</td></tr><tr><td><code>GaussianNB／BernoulliNB</code></td><td>項目どうしが独立だと仮定する単純なモデル。とても速い。GaussianNB は数値が正規分布に近いとき、BernoulliNB は 0／1 の項目向け</td><td>GaussianNB は演習2では F1 0.44。BernoulliNB は、ある単語やフラグが含まれるかどうかで分類するとき</td><td style="text-align:center;">○</td></tr><tr><td><code>MLPClassifier</code></td><td>小さなニューラルネットワーク。複雑な境界も学べるが、入力をそろえる（StandardScaler）必要があり、学習も重い</td><td>ほかの方法で精度が出ず、データが十分にあるとき</td><td style="text-align:center;">○</td></tr><tr><td><code>SGDClassifier</code></td><td>少しずつ学習する線形の分類。partial_fit で新しいデータを足して学習し直せる</td><td>データが大きく、毎日のデータでモデルを更新し続けたいとき</td><td style="text-align:center;">○</td></tr><tr><td><code>AutoPrediction</code></td><td>目的の項目が数値かカテゴリかを見て、回帰か分類かを自動で選ぶ。Smart Prediction アシスタントが使う</td><td>まず手早く当たりを付けたいとき。Showcase の Predict the Presence of Vulnerabilities がこれ</td><td style="text-align:center;">○</td></tr></tbody></table></section><section><h2>時系列の予測</h2><table class="aitk-table aitk-table-fixed"><thead><tr><th style="width:19%;">アルゴリズム</th><th style="width:37%;">特徴</th><th>どんなときに使うか（セキュリティの例）</th><th style="width:7%;">保存</th></tr></thead><tbody><tr><td><code>StateSpaceForecast</code></td><td>カルマンフィルターを使う状態空間モデル。周期を扱え、複数の時系列を同時に予測でき、95%の予測区間も出す</td><td>CPU 使用率やログイン数の先行きを予測し、予測の範囲から外れたら知らせたいとき（Primer シナリオ3）</td><td style="text-align:center;">○</td></tr><tr><td><code>ARIMA</code></td><td>自己回帰と移動平均で1本の時系列を予測する。等間隔で欠けのないデータが必要</td><td>1つの指標を細かく調整して予測したいとき。保存できないので、使うたびに fit する</td><td style="text-align:center;">×</td></tr><tr><td><code>| predict（コマンド）</code></td><td>Splunk 標準の予測コマンド。LLP、LLP5 などの方式で、周期と傾きを自動で扱う</td><td>手軽に予測したいとき。演習1の Showcase の予測値はこれ</td><td style="text-align:center;">―</td></tr><tr><td><code>FineTuneCDTSM</code></td><td>時系列の基盤モデル（TSFM）を自分のデータで追加学習したもの。AI Toolkit の Fine tune time series foundation model の画面で作って公開すると使える</td><td>ふつうの予測モデルでは周期や傾向をとらえきれないとき</td><td style="text-align:center;">○</td></tr></tbody></table></section><footer class="aitk-next"><b>アルゴリズム</b><a href="algo_overview">概要</a><a href="algo_outlier">外れ値（Outlier）</a><a href="algo_predictive">予測（Predictive）</a><a href="algo_categorization">分類（Categorization）</a></footer></div>'
ALGO_CATEGORIZATION = '<div class="aitk-doc"><header class="aitk-doc-hero"><span class="aitk-kicker">アルゴリズム ／ 分類（Categorization）</span><h1>分類・グループ分けのアルゴリズム</h1><p>データの中身を知って、いま起きていることにすばやく対応するための道具です。ラベルを使わずに似た者同士をまとめるクラスタリングと、送信元と宛先のようなつながりを網の目として調べるグラフの分析があります。</p></header><section><h2>クラスタリング</h2><p>ラベルを使わずに、似た者同士をまとめます。カテゴリの予測（分類）は上の表を見てください。</p>\n  <table class="aitk-table aitk-table-fixed"><thead><tr><th style="width:19%;">アルゴリズム</th><th style="width:37%;">特徴</th><th>どんなときに使うか（セキュリティの例）</th><th style="width:7%;">保存</th></tr></thead><tbody><tr><td><code>KMeans</code></td><td>数値の項目で、点を k 個のまとまりに分ける。各まとまりは中心で表される。k は自分で決める</td><td>端末やユーザーを、通信量や操作の量で、似た者同士のグループに分けたいとき</td><td style="text-align:center;">○</td></tr><tr><td><code>XMeans／GMeans</code></td><td>まとまりの数 k を自動で決める KMeans。GMeans は、まとまりが正規分布に近くなるまで分け続ける</td><td>いくつのグループに分かれるか見当がつかないとき</td><td style="text-align:center;">○</td></tr><tr><td><code>Birch</code></td><td>大量のデータを少しずつまとめていく。partial_fit で追加の学習ができる</td><td>データが多く、KMeans では重いとき</td><td style="text-align:center;">○</td></tr><tr><td><code>DBSCAN</code></td><td>点の密集しているところをまとまりとし、どこにも属さない点はノイズとして残す。形がいびつなまとまりも見つけられる。k は不要</td><td>まとまりから外れた点（ノイズ）も一緒に見たいとき。保存できないので、使うたびに fit する</td><td style="text-align:center;">×</td></tr><tr><td><code>SpectralClustering</code></td><td>点どうしのつながりの強さからまとまりを作る。入れ子や輪のような形にも強いが、データが多いと重い</td><td>形の複雑なまとまりを、数千行程度までのデータで調べるとき</td><td style="text-align:center;">×</td></tr></tbody></table><p class="aitk-note"><b>保存</b>の列は、<code>into</code> でモデルを保存できるか（あとで <code>apply</code> できるか）を、この検証環境の AI Toolkit 6.1 で実際に試した結果です。× は使うたびに fit します。「―」はモデルを作らないものです。</p></section><section><h2>つながりの分析（グラフ）</h2><p>送信元と宛先のような2つの項目を、点と線の網の目として扱います。</p>\n  <table class="aitk-table aitk-table-fixed"><thead><tr><th style="width:19%;">アルゴリズム</th><th style="width:37%;">特徴</th><th>どんなときに使うか（セキュリティの例）</th><th style="width:7%;">保存</th></tr></thead><tbody><tr><td><code>GraphCentrality</code></td><td>送信元と宛先のつながりを網の目として見て、各点がどれだけ中心にいるか（degree_centrality など）を求める</td><td>多くの相手とつながっている端末やサーバー（ハブ）を見つけたいとき</td><td style="text-align:center;">○</td></tr><tr><td><code>GraphConnectedComponents</code></td><td>つながっている点どうしを1つのグループにまとめる</td><td>互いに通信している端末のかたまりを見つけたいとき。横展開の範囲を調べるときなど</td><td style="text-align:center;">○</td></tr><tr><td><code>GraphLabelPropagation</code></td><td>つながりの強さから、網の目をコミュニティに分ける</td><td>つながり方の似た端末やアカウントのグループを見つけたいとき</td><td style="text-align:center;">○</td></tr><tr><td><code>MinimumSpanningTree</code></td><td>すべての点を最小の重みでつなぐ木を作る</td><td>この環境（AI Toolkit 6.1）では実行時にエラーになり、動かなかった</td><td style="text-align:center;">―</td></tr></tbody></table></section><section><h2>カテゴリの予測（分類）</h2><p>資料ではカテゴリの予測（Categorical Regression）もこの大項目に入っています。正解の付いたデータで学ぶ方法なので、<a href="algo_predictive">予測</a>のページにまとめています。</p></section><footer class="aitk-next"><b>アルゴリズム</b><a href="algo_overview">概要</a><a href="algo_outlier">外れ値（Outlier）</a><a href="algo_predictive">予測（Predictive）</a><a href="algo_categorization">分類（Categorization）</a></footer></div>'

# ---------------------------------------------------------------- where each algorithm lives in AI Toolkit Experiments
DOC61 = "https://help.splunk.com/en/splunk-enterprise/apply-machine-learning/use-ai-toolkit/6.1.0"
EXP_LINK = '<a class="aitk-open" target="_blank" href="../Splunk_ML_Toolkit/experiments">AI Toolkit の Experiments を開く ↗</a>'
SPL_ONLY = '<span style="color:#5b6b75;">Experiments には無い。Search で <code>| fit</code> を書く</span>'
PREP5 = "StandardScaler（既定）、FieldSelector、PCA、KernelPCA、TFIDF"


def exp_tag(name, kind):
    color = "#0e7c86" if kind == "Smart" else "#5b6b75"
    return (f'<b>{name}</b> <span style="font-size:11px;color:#fff;background:{color};padding:1px 6px;'
            f'border-radius:3px;">{kind}</span>')


def exp_map(title, rows, note=""):
    chip = lambda t: " ".join(f'<code style="word-break:normal;display:inline-block;margin:2px 0;">{x}</code>' for x in t.split("、"))
    body = "".join(f"<tr><td>{chip(a)}</td><td>{b}</td><td>{c}</td></tr>" for a, b, c in rows)
    return (f'<section><h2>{title}</h2>'
            '<p>AI Toolkit の <b>Experiments</b> の画面では、上に並ぶ種類のタイルを選んでから <b>Create New Experiment</b> で始めます。'
            '下の表は、このページのアルゴリズムをどの種類の中で選べるかの対応です。' + EXP_LINK + '</p>'
            '<table class="aitk-table aitk-table-fixed"><thead><tr><th style="width:26%;">アルゴリズム</th>'
            '<th style="width:30%;">Experiments の種類</th><th>画面のどこで選ぶか</th></tr></thead>'
            f'<tbody>{body}</tbody></table>{note}</section>')


MAP_OUTLIER = exp_map("Experiments のどこで使うか", [
    ("DensityFunction", exp_tag("Smart Outlier Detection", "Smart"), "Learn で Field to analyze と Split by fields を選ぶと、裏で DensityFunction の fit が動く。アルゴリズムを選ぶ欄は無い（Primer シナリオ1の GUI の手順）"),
    ("標準偏差／MAD／四分位範囲", exp_tag("Detect Numeric Outliers", "Classic"), "Threshold method で Standard Deviation、Median Absolute Deviation、Interquartile Range から選ぶ。fit は使わない（演習1）"),
    ("| anomalydetection", exp_tag("Detect Categorical Outliers", "Classic"), "カテゴリの項目を選ぶと、値の組み合わせの起きやすさ（確率）で外れを判定する"),
    ("MultivariateOutlierDetection", "―", SPL_ONLY),
    ("LocalOutlierFactor", "―", SPL_ONLY),
    ("OneClassSVM", "―", SPL_ONLY),
    ("AutoAnomalyDetection", "―", "Splunk App for Anomaly Detection のジョブ用。直接は使わない"),
])

MAP_PREDICTIVE = exp_map("Experiments のどこで使うか", [
    ("LinearRegression（既定）、RandomForestRegressor、Lasso、KernelRidge、ElasticNet、Ridge、DecisionTreeRegressor",
     exp_tag("Predict Numeric Fields", "Classic"), f"Algorithm の欄で選ぶ。Preprocessing Steps の +Add a step で {PREP5} を前に挟める"),
    ("GradientBoostingRegressor、SGDRegressor、SystemIdentification", "―", SPL_ONLY),
    ("LogisticRegression（既定）、SVM、RandomForestClassifier、GaussianNB、BernoulliNB、DecisionTreeClassifier",
     exp_tag("Predict Categorical Fields", "Classic"), f"Algorithm の欄で選ぶ（演習2）。前処理は Predict Numeric Fields と同じ {PREP5}"),
    ("GradientBoostingClassifier、MLPClassifier、SGDClassifier", "―", SPL_ONLY),
    ("AutoPrediction", exp_tag("Smart Prediction", "Smart"), "目的の項目と入力の項目を選ぶだけ。回帰か分類かは自動で決まる。アルゴリズムを選ぶ欄は無い"),
    ("StateSpaceForecast", exp_tag("Smart Forecasting", "Smart"), "予測する項目と期間を選ぶと、裏で StateSpaceForecast の fit が動く（Primer シナリオ3と同じアルゴリズム）"),
    ("| predict（Kalman filter・既定）、ARIMA", exp_tag("Forecast Time Series", "Classic"), "Algorithm の欄で Kalman filter（predict コマンド）か ARIMA を選ぶ。ARIMA はモデルを保存できない"),
    ("FineTuneCDTSM", "Fine tune time series foundation model の画面",
     '<a class="aitk-open" target="_blank" href="../Splunk_ML_Toolkit/fine_tune_tsfm">画面を開く ↗</a> Experiments とは別の画面。追加学習が終わったモデルを公開すると、fit／apply で使える'),
])

MAP_CATEGORIZATION = exp_map("Experiments のどこで使うか", [
    ("KMeans", exp_tag("Smart Clustering", "Smart") + "<br/>" + exp_tag("Cluster Numeric Events", "Classic"),
     "Smart Clustering は KMeans だけで、アルゴリズムを選ぶ欄は無い。Cluster Numeric Events では Algorithm の欄で選ぶ"),
    ("DBSCAN、Birch、SpectralClustering", exp_tag("Cluster Numeric Events", "Classic"),
     f"Algorithm の欄で選ぶ。前処理は {PREP5}。DBSCAN と SpectralClustering はモデルを保存できない"),
    ("XMeans、GMeans", "―", SPL_ONLY),
    ("GraphCentrality、GraphConnectedComponents、GraphLabelPropagation", "―", SPL_ONLY),
    ("LogisticRegression などの分類", exp_tag("Predict Categorical Fields", "Classic"), '<a href="algo_predictive">予測</a>のページを見る'),
])

MAP_PREP = exp_map("下ごしらえを Experiments のどこで使うか", [
    ("StandardScaler、FieldSelector、PCA、KernelPCA、TFIDF",
     exp_tag("Predict Numeric Fields", "Classic") + "<br/>" + exp_tag("Predict Categorical Fields", "Classic") + "<br/>" + exp_tag("Cluster Numeric Events", "Classic"),
     "Preprocessing Steps の <b>+Add a step</b> で選ぶ。既定は StandardScaler。前のステップの結果が次のステップに渡る。後から前のステップは変えられず、ステップを消すとそれより後ろも消える"),
    ("時刻から特徴を作る", exp_tag("Smart Outlier Detection", "Smart"), "Learn の <b>+Add preprocessing step</b> で、_time から atf_hour_of_day（時）などを作れる"),
    ("RobustScaler、Imputer、ICA、HashingVectorizer、NPR、ACF、PACF", "―", SPL_ONLY),
    ("AITKContainer", "Connections の画面", "コンテナの接続先を登録してから使う（DSDL と同じ仕組み）"),
])

EXP_TABLE_ROWS = [
    ("Smart Outlier Detection", "Smart", '<a href="algo_outlier">外れ値</a>', "DensityFunction", "時刻の特徴（atf_hour_of_day など）", "Primer シナリオ1"),
    ("Detect Numeric Outliers", "Classic", '<a href="algo_outlier">外れ値</a>', "標準偏差、MAD、四分位範囲（統計。fit は使わない）", "―", "Rookies 演習1"),
    ("Detect Categorical Outliers", "Classic", '<a href="algo_outlier">外れ値</a>', "値の組み合わせの確率（anomalydetection コマンド）", "―", "―"),
    ("Smart Prediction", "Smart", '<a href="algo_predictive">予測</a>', "AutoPrediction", "―", "Showcase の Predict the Presence of Vulnerabilities"),
    ("Predict Numeric Fields", "Classic", '<a href="algo_predictive">予測</a>（回帰）', "LinearRegression（既定）、RandomForestRegressor、Lasso、KernelRidge、ElasticNet、Ridge、DecisionTreeRegressor", PREP5, "―"),
    ("Predict Categorical Fields", "Classic", '<a href="algo_predictive">予測</a>（分類）', "LogisticRegression（既定）、SVM、RandomForestClassifier、GaussianNB、BernoulliNB、DecisionTreeClassifier", PREP5, "Rookies 演習2"),
    ("Smart Forecasting", "Smart", '<a href="algo_predictive">予測</a>（時系列）', "StateSpaceForecast", "―", "Primer シナリオ3（SPL で同じアルゴリズム）"),
    ("Forecast Time Series", "Classic", '<a href="algo_predictive">予測</a>（時系列）', "Kalman filter（predict コマンド、既定）、ARIMA", "―", "―"),
    ("Smart Clustering", "Smart", '<a href="algo_categorization">分類</a>', "KMeans", "―", "―"),
    ("Cluster Numeric Events", "Classic", '<a href="algo_categorization">分類</a>', "KMeans、DBSCAN、Birch、SpectralClustering", PREP5, "―"),
]
EXP_OVERVIEW = (
    '<section><h2>Experiments との対応</h2>'
    '<p>AI Toolkit の <b>Experiments</b> の画面の上には、10種類のタイルが並んでいます。<b>Smart</b> の4つは、アルゴリズムが1つに決まっていて、'
    '画面の案内に答えるだけで進むアシスタントです。残りの6つ（ここでは <b>Classic</b> と呼びます）は、Algorithm の欄でアルゴリズムを自分で選び、前処理も足せます。' + EXP_LINK + '</p>'
    '<table class="aitk-table aitk-table-fixed"><thead><tr><th style="width:20%;">Experiments の種類</th><th style="width:11%;">大項目</th>'
    '<th>選べるアルゴリズム</th><th style="width:20%;">前処理</th><th style="width:15%;">この講座では</th></tr></thead><tbody>'
    + "".join(f"<tr><td>{exp_tag(a, k)}</td><td>{c}</td><td>{d}</td><td>{e}</td><td>{f}</td></tr>" for a, k, c, d, e, f in EXP_TABLE_ROWS)
    + '</tbody></table>'
    '<h3>Experiments に無いアルゴリズム</h3>'
    '<p>次のアルゴリズムは Experiments の画面からは選べません。AI Toolkit アプリの <b>Search</b>（または Search &amp; Reporting）で <code>| fit</code> を直接書きます。'
    '各ページの表の SPL の書き方は、Experiments の <b>Show SPL</b> で出る SPL と同じ形です。</p>'
    + ul(["<b>外れ値</b>：MultivariateOutlierDetection、LocalOutlierFactor、OneClassSVM",
          "<b>予測</b>：GradientBoostingRegressor、SGDRegressor、SystemIdentification、GradientBoostingClassifier、MLPClassifier、SGDClassifier",
          "<b>分類</b>：XMeans、GMeans、GraphCentrality、GraphConnectedComponents、GraphLabelPropagation",
          "<b>下ごしらえと分析</b>：RobustScaler、Imputer、ICA、HashingVectorizer、NPR、ACF、PACF"])
    + f'<p class="aitk-note">出典：AI Toolkit 6.1.0 のドキュメント（<a target="_blank" href="{DOC61}/experiment-assistant-guided-workflows">Experiment Assistant guided workflows</a>、'
    f'<a target="_blank" href="{DOC61}/smart-assistant-guided-workflows">Smart Assistant guided workflows</a>）。画面の文言はバージョンで変わることがあります。</p>'
    '</section>')

ALGO_OVERVIEW = ALGO_OVERVIEW.replace('<section><h2>選び方</h2>', EXP_OVERVIEW + '<section><h2>選び方</h2>', 1)
ALGO_OVERVIEW = ALGO_OVERVIEW.replace('<footer class="aitk-next">', MAP_PREP + '<footer class="aitk-next">', 1)
ALGO_OUTLIER = ALGO_OUTLIER.replace("</header>", "</header>" + MAP_OUTLIER, 1)
ALGO_PREDICTIVE = ALGO_PREDICTIVE.replace("</header>", "</header>" + MAP_PREDICTIVE, 1)
ALGO_CATEGORIZATION = ALGO_CATEGORIZATION.replace("</header>", "</header>" + MAP_CATEGORIZATION, 1)
assert all(x.count("Experiments のどこで使うか") >= 1 for x in (ALGO_OUTLIER, ALGO_PREDICTIVE, ALGO_CATEGORIZATION, ALGO_OVERVIEW))


# ================================================================ Ninja
# The s4n data was imported into index=main with its original times (JST below).
N_JUL = {"earliest": 1783782000, "latest": 1784732400}   # 2026-07-12 .. 07-22
N_SEP = {"earliest": 1789311600, "latest": 1790607600}   # 2026-09-14 .. 09-28
N_HTTP = {"earliest": 1783782000, "latest": 1786460400}  # 2026-07-12 .. 08-11
N_LKP = {"earliest": "0", "latest": "now"}
N_RANGE_JUL = "2026/7/12 〜 7/22（日本時間）"
N_RANGE_SEP = "2026/9/14 〜 9/28（日本時間）"
N_RANGE_HTTP = "2026/7/12 〜 8/11（日本時間）"
N_RANGE_LKP = "指定なし（inputlookup は時間範囲に関係なく http_error_dataset.csv の10行を読む）"
N_LLM = 'provider=Gemini model="gemini-3.6-flash"'

N1_STATS = ('index=main sourcetype="XmlWinEventLog" EventCode=4625 LogonType=3\n'
            '| where isnotnull(IpAddress) AND IpAddress!="-"\n'
            '| bin _time span=2m\n'
            '| stats count as failed_logons\n'
            '        dc(TargetUserName) as unique_accounts\n'
            '        values(TargetUserName) as tried_accounts\n'
            '    by _time IpAddress LogonType dvc\n'
            '| eventstats avg(unique_accounts) as comp_avg\n'
            '             stdev(unique_accounts) as comp_std\n'
            '    by IpAddress LogonType dvc\n'
            '| eval upperBound=comp_avg+(comp_std*2)\n'
            '| eval isOutlier=if(unique_accounts>=4 AND unique_accounts>=upperBound,1,0)\n'
            '| search isOutlier=1\n'
            '| table _time IpAddress dvc LogonType failed_logons unique_accounts\n'
            '        tried_accounts comp_avg comp_std upperBound isOutlier')
N1_PREP = ('index="main" sourcetype="xmlwineventlog" EventCode=4625 LogonType=3\n'
           '| bucket span=2m _time\n'
           '| stats dc(TargetUserName) as unique_accounts\n'
           '        values(TargetUserName) as tried_accounts\n'
           '    by _time IpAddress LogonType dvc\n'
           '| eventstats avg(unique_accounts) as comp_avg\n'
           '             stdev(unique_accounts) as comp_std\n'
           '    by IpAddress LogonType dvc\n'
           '| eval HourOfDay=strftime(_time,"%H")\n'
           '| eval HourOfDay=floor(HourOfDay/4)*4\n'
           '| eval DayOfWeek=strftime(_time,"%w")\n'
           '| eval isWeekend=if(DayOfWeek>=1 AND DayOfWeek<=5,0,1)\n'
           '| sort - comp_avg')
N2_BASE = 'index="main" source="*WinEventLog:Security" EventCode=4648 host!="WIN11-SAKURA"'
N2_DAILY = N2_BASE + "\n| bucket _time span=1d\n| stats count by src_user _time"
N3_BASE = 'index="main" TERM(agent) sourcetype="stream:http" src_ip="*" http_user_agent="*"'
N3_TFIDF = (N3_BASE + "\n| table http_user_agent src_ip dest_ip action dest_port bytes_in bytes_out\n"
            "| head 3000\n| fit TFIDF http_user_agent")
N4_PROMPT = ("HTTP Error '{HTTP_Code}' occurred with message:  '{Error_Message}'. Root cause: '{Root_Cause}'. "
             "What specific steps can we take to resolve this? Provide a precise but informative answer.")
N4_PROMPT_JA = ("HTTP エラー '{HTTP_Code}' が発生しました。メッセージ: '{Error_Message}'。根本原因: '{Root_Cause}'。"
                "解決するための具体的な手順を、日本語で5行以内で答えてください。")


def exp_steps(rows):
    """Table of GUI steps: (label, what to do)."""
    body = "".join(f'<tr><td style="width:18%;"><b>{a}</b></td><td>{b}</td></tr>' for a, b in rows)
    return f'<table class="aitk-table"><tbody>{body}</tbody></table>'


EXPLAIN.update({
    "n1-1": [
        ('index=main sourcetype="XmlWinEventLog"', "Windows のセキュリティログ（XML 形式）に絞る"),
        ("EventCode=4625 LogonType=3", "4625 はログオンの失敗。LogonType=3 はネットワーク経由のログオン（共有フォルダや SMB など、離れた端末からの認証）"),
        ("| stats count … dc(TargetUserName) as accounts dc(dvc) as devices by IpAddress", "送信元の IP アドレスごとに、失敗の数、試したアカウントの種類、狙った端末の数を数える"),
    ],
    "n1-2": [
        ('| where isnotnull(IpAddress) AND IpAddress!="-"', "送信元の IP アドレスが記録されていない失敗（ローカルのログオンなど）を除く"),
        ("| bin _time span=2m", "時刻を2分ごとの区切りにそろえる。2分の間にまとめて試したかどうかを見るため"),
        ("| stats count as failed_logons dc(TargetUserName) as unique_accounts values(TargetUserName) as tried_accounts by _time IpAddress LogonType dvc",
         "2分ごと、送信元と端末（dvc）ごとに、失敗の数、試したアカウントの種類の数、試したアカウントの一覧を出す。スプレーは「1つの送信元が短い間に多くのアカウントを試す」ので unique_accounts が増える"),
        ("| eventstats avg(unique_accounts) as comp_avg stdev(unique_accounts) as comp_std by IpAddress LogonType dvc",
         "同じ送信元と端末の組の、ふだんの unique_accounts の平均と標準偏差を求め、各行に付ける"),
        ("| eval upperBound=comp_avg+(comp_std*2)", "平均＋標準偏差×2 を上限にする"),
        ("| eval isOutlier=if(unique_accounts>=4 AND unique_accounts>=upperBound,1,0)",
         "4アカウント以上を試していて、しかも上限以上なら 1。「4以上」という決め打ちの条件と、統計の上限の両方を満たすものだけを残す"),
        ("| search isOutlier=1 | table …", "外れ値の行だけを、調べるのに必要な列と一緒に並べる"),
    ],
    "n1-3": [
        ("| bucket span=2m _time", "bin と同じ。2分ごとにそろえる"),
        ("| stats dc(TargetUserName) as unique_accounts … by _time IpAddress LogonType dvc", "Search 1-2 と同じ集計。ただし IpAddress が空の行も残っている"),
        ("| eventstats … by IpAddress LogonType dvc", "Search 1-2 と同じ。データの確認用で、このあとのモデルには使わない"),
        ('| eval HourOfDay=strftime(_time,"%H") | eval HourOfDay=floor(HourOfDay/4)*4', "時刻を 0、4、8、12、16、20 の6つの時間帯にまとめる。資料ではモデルに使っていないが、時間帯で分けて試すときに使える"),
        ('| eval DayOfWeek=strftime(_time,"%w") | eval isWeekend=…', "曜日（0＝日曜）と、週末かどうか（1＝土日）を作る"),
        ("| sort - comp_avg", "ふだんの平均が大きい組から並べる"),
    ],
    "n1-5": [
        ("（Search 1-3 と同じ前半）", "Smart Outlier Detection の Define に貼った SPL と同じ"),
        ("| fit DensityFunction unique_accounts by dvc", "GUI の Field to analyze（unique_accounts）と Split by fields（dvc）にあたる。端末ごとに unique_accounts の分布を推定する"),
        ("dist=auto threshold=0.0017", "Distribution type の Auto と、Outlier tolerance threshold の 0.0017。分布の端の 0.17% にあたる範囲を外れ値にする"),
        ("| where 'IsOutlier(unique_accounts)'=1 | table …", "外れ値になった行だけを並べる"),
    ],
    "n1-6": [
        ("（Search 1-2 と同じ SPL）", "時間範囲だけを 9/14〜9/28 に変える"),
    ],
    "n2-1": [
        ('index="main" source="*WinEventLog:Security"', "Windows のセキュリティログに絞る。source の先頭の * で XmlWinEventLog:Security も当てはまる"),
        ("EventCode=4648", "明示的な資格情報を使ったログオンの試み。RunAs やスケジュールタスクでも出るので、出ただけでは怪しいとは言えない"),
        ('host!="WIN11-SAKURA"', "WIN11-SAKURA という端末のログを除く"),
        ("| timechart count by src_user", "日ごと（期間が11日なので自動で1日刻み）、src_user ごとに件数を数え、ユーザーごとの線にする"),
    ],
    "n2-2": [
        ("| bucket _time span=1d", "時刻を1日ごとにそろえる"),
        ("| stats count by src_user _time", "ユーザーと日の組ごとに数える。1行が「あるユーザーのある日の件数」になり、これを Detect Numeric Outliers に渡す"),
    ],
    "n2-4": [
        ("（Search 2-2 と同じ前半）", "1日ごと、ユーザーごとの件数"),
        ("| eventstats avg(count) as avg stdev(count) as stdev", "全行の count の平均と標準偏差を求める。GUI で Fields to split by を空にしたのと同じで、ユーザーに分けずに1つの範囲を作る"),
        ("| eval lowerBound=avg-stdev*2, upperBound=avg+stdev*2", "Threshold method の Standard Deviation、Threshold multiplier の 2 にあたる"),
        ("| eval isOutlier=if(count<lowerBound OR count>upperBound,1,0)", "範囲の外なら 1"),
    ],
    "n2-5": [
        ('src_user="MKRAEUSEN-D$"', "外れ値になったユーザーに絞る。時間範囲は外れ値の日（7/21）だけにしてある"),
        ("| stats count by TargetUserName TargetServerName ProcessName", "誰の資格情報を、どこに向けて、どのプロセスが使ったかを数える"),
    ],
    "n3-1": [
        ('index="main" TERM(agent) sourcetype="stream:http"', "Splunk Stream が取った HTTP の通信に絞る。<code>TERM(agent)</code> は生データに agent という語があるイベントだけを索引から速く選ぶ指定"),
        ('src_ip="*" http_user_agent="*"', "送信元と User-Agent の両方があるイベントだけにする"),
        ("| table http_user_agent action dest_port bytes_in bytes_out", "Detect Categorical Outliers に渡す列を並べる"),
    ],
    "n3-3": [
        ("（Search 3-1 と同じ前半）", "同じイベントを使う"),
        ('| anomalydetection "http_user_agent" action=annotate', "Detect Categorical Outliers が裏で使うコマンド。値がどれくらい起きやすいかを確率で求め、めったに起きない値の行の probable_cause に項目名を入れる"),
        ('| eval isOutlier=if(probable_cause!="",1,0)', "probable_cause が入っていれば外れ値"),
        ("| stats count by isOutlier", "外れ値と、それ以外の数を数える"),
    ],
    "n3-4": [
        ("| head 3000", "重い処理なので、最初の3,000件（新しい順）に絞る"),
        ("| fit TFIDF http_user_agent", "User-Agent の文字列を、単語や文字のつながりの重み（TF-IDF）の数値の列に変える。列名は <code>http_user_agent_tfidf_…</code> になる"),
    ],
    "n3-5": [
        ("| fit KMeans k=5 http_user_agent_tfidf_*", "TF-IDF の数値の列を使って、似た User-Agent を5つのまとまり（cluster）に分ける。ラベルは要らない"),
        ("| stats count dc(http_user_agent) as ua values(http_user_agent) as user_agents by cluster", "まとまりごとに、イベント数、User-Agent の種類、User-Agent の一覧を出す"),
    ],
    "n3-6": [
        ("| fit KMeans k=1 http_user_agent_tfidf_*", "まとまりを1つにして、全体の中心からの距離（cluster_distance）を各イベントに付ける"),
        ("| fields - http_user_agent_tfidf_*", "TF-IDF の列を消して、結果を見やすくする"),
        ("| stats max(cluster_distance) by cluster http_user_agent | sort - max(cluster_distance)", "User-Agent ごとに距離の最大値を取り、中心から遠い順に並べる。上にあるものほど、ほかと似ていない"),
    ],
    "n1-2n": [
        ('IpAddress=172.16.50.200', "Search 1-2 で見つかった送信元だけに絞る。2分ごとにまとめず、失敗を1件ずつ見る"),
        ("| sort 0 _time", "古い順に並べ、どの順番で試したかを追えるようにする"),
        ("| table … SubStatus TargetUserName", "どの端末（dvc）に、どのアカウント（TargetUserName）で、どんな理由（SubStatus）で失敗したかを並べる"),
    ],
    "n4-1": [
        ("| inputlookup http_error_dataset.csv", "HTTP のエラーと、その原因を書いた10行のルックアップを読む"),
    ],
    "n4-3": [
        ("| head 2", "LLM に送る行を2行に絞る。回数と時間を節約するため"),
        ("| ai prompt=\"…'{HTTP_Code}' … '{Error_Message}' … '{Root_Cause}' …\"", "各行の HTTP_Code、Error_Message、Root_Cause をプロンプトに埋め込んで LLM に送り、答えを ai_result_1 列に入れる。項目名は波かっこで囲み、シングルクォートで挟む"),
        (N_LLM, "Connections に登録した接続先とモデル"),
    ],
    "n4-4": [
        ("| ai prompt=\"… 日本語で5行以内で答えてください。\"", "Search 4-3 と同じ。プロンプトを日本語にして、答えの長さも指定する"),
    ],
})

n1 = [
    {"id": "n1-1", "tag": "Search 1-1", "title": "ネットワーク経由のログオン失敗を見る",
     "body": ["Lab1 で使うのは、Windows のセキュリティログのイベント 4625（ログオンの失敗）のうち、LogonType=3（ネットワーク経由）のものです。",
              "パスワードスプレーは、1つの送信元から多くのアカウントに少しずつ試します。まず送信元ごとに、何回失敗し、何種類のアカウントを試したかを見ます。"],
     "spl": ('index=main sourcetype="XmlWinEventLog" EventCode=4625 LogonType=3\n'
             "| stats count as failed_logons dc(TargetUserName) as accounts dc(dvc) as devices by IpAddress\n"
             "| sort - failed_logons"),
     **N_JUL, "range_note": N_RANGE_JUL,
     "views": [("table", "送信元ごとの失敗の数")],
     "checks": ["送信元は7つ（IP が記録されていない <code>-</code> を含む）",
                "失敗がいちばん多いのは 172.16.48.255 の126回だが、試したアカウントは2種類だけ。同じアカウントで何度も失敗している",
                "172.16.50.200 は16回の失敗で <b>8種類</b>のアカウントを、4台の端末に試している。数は少ないが、スプレーらしいのはこちら"]},
    {"id": "n1-2", "tag": "Search 1-2", "title": "単純な統計でスプレーを見つける（Technique #1）",
     "body": ["資料の SPL です。2分ごとに、送信元と端末の組ごとに、何種類のアカウントを試したかを数えます。",
              "その組のふだんの平均＋標準偏差×2 を上限にし、<b>4アカウント以上</b>で、かつ上限以上の2分間だけを残します。決め打ちの条件と統計の条件を組み合わせた、説明しやすい検知です。"],
     "extra_html": ('<div class="aitk-check"><h4>外れ値になる条件（すべて満たすもの）</h4>'
                    + ul(["<b>同じ組</b>：同じ送信元 IP（IpAddress）から、同じ端末（dvc）へのログオン",
                          "<b>同じ2分間</b>：<code>bin _time span=2m</code> でそろえた、06:08〜06:10 のような決まった区切りの中。06:09 と 06:11 のように2分以内でも、区切りをまたぐと別々に数える",
                          "<b>4つ以上の違うアカウント</b>：<code>unique_accounts</code> は失敗の回数（<code>failed_logons</code>）ではなく、失敗したアカウント名の種類（<code>dc(TargetUserName)</code>）。1つのアカウントを何度失敗しても1と数える",
                          "<b>ふだんより多い</b>：その組の <code>unique_accounts</code> の平均＋標準偏差×2（upperBound）以上。172.16.50.200 → MKRAEUSEN-D の組では約3.84"])
                    + '<p class="aitk-note">多くのアカウントを少しずつ試す「パスワードスプレー」を見つける条件です。1つのアカウントを何度も試す「総当たり」は、<code>by</code> に TargetUserName を入れて <code>count</code> で絞る別のサーチになります。</p></div>'),
     "spl": N1_STATS, **N_JUL, "range_note": N_RANGE_JUL,
     "views": [("table", "外れ値になった2分間")],
     "refs": ["n55_0.png"],
     "checks": ["1行だけ出る。資料と同じく、172.16.50.200 が 2026/7/21 06:08 からの2分間に、MKRAEUSEN-D の4アカウントを試している",
                "tried_accounts は damnyoubud、mallory、mkraeusen、what_didbudsay_this_was。実在しないような名前が混ざっている",
                "comp_avg は約1.57、comp_std は約1.13、upperBound は約3.84。4 はぎりぎり上限を超えた"],
     "next": (ul(["172.16.50.200 の失敗をすべて並べると16件ある。7/20 19:35〜19:40 に fatjeta で4台の端末を順に試し、7/21 は MKRAEUSEN-D に、05:44〜06:09 に mkraeusen、malloryk、mallory など、10:11 に welcome14、11:02〜11:05 に Administrator（4回）と malloryk を試している",
                          "Administrator が Search 1-2 に出ないのは、2分ごとの<b>アカウントの種類</b>（dc）で数えるため。同じ名前を何度試しても1種類なので、11:02 からの2分間は2種類（Administrator、malloryk）、11:04 からは1種類で、4に届かない。1つのアカウントを何度も試す総当たりは、この検知では見つからない（count を見る条件が別に要る）",
                          "失敗の理由（SubStatus）は、0xc0000064 が「そのユーザー名は存在しない」、0xc000006a が「パスワードが違う」、0xc0000072 が「アカウントが無効」。Administrator は 0xc000006a が3回で、最後の 11:05 は 0xc0000072。malloryk は 05:56 が 0xc000006a、11:03 が 0xc0000064",
                          "同じ送信元から 4624（ログオン成功）が出ていないか、172.16.50.200 はどの端末か、を続けて確かめる"])
             + '<p class="aitk-note">外れ値は「調べる候補」です。攻撃だと決めるのは、認証、端末、アカウントの情報を合わせて見てからです。</p>'),
     "next_spl": ('index=main sourcetype="XmlWinEventLog" EventCode=4625 LogonType=3 IpAddress=172.16.50.200\n'
                  "| sort 0 _time\n"
                  "| table _time host dvc IpAddress EventCode Computer Logon_Type SubStatus TargetUserName"),
     "next_title": "172.16.50.200 からのログオン失敗（古い順）"},
    {"id": "n1-3", "tag": "Search 1-3", "title": "Smart Outlier Detection に渡すデータを作る",
     "body": ["Technique #2 では、AI Toolkit の Smart Outlier Detection を使います。Search 1-2 では上限を自分で決めましたが、こちらでは端末ごとの unique_accounts の分布を AI Toolkit に推定させます。",
              "次の GUI 1-4 で Define に貼る SPL です。先にここで実行して、どんなデータになるかを見ておきます。"],
     "spl": N1_PREP, **N_JUL, "range_note": N_RANGE_JUL,
     "views": [("table", "Define で読み込まれるデータ（先頭10行）"),
               ("table", "端末（dvc）ごとの行数", None, "| stats count by dvc")],
     "refs": ["n60_0.png"],
     "checks": ["全部で40行。7/20 07:34 〜 7/21 11:04 の2分間のうち、失敗のあったものだけ",
                "端末は4台（winserver 16行、MKRAEUSEN-D 11行、abungstein-l 8行、rschlitzer-d 5行）。どれも行が少ないので、分布の推定は粗くなる"]},
    {"id": "n1-4", "tag": "GUI 1-4", "title": "Smart Outlier Detection で外れ値を探す",
     "body": ["AI Toolkit アプリの <b>Experiments</b> で <b>Smart Outlier Detection</b> を選び、Experiment を作ります。"],
     "extra_html": exp_steps([
         ("開く", '<a class="aitk-open" target="_blank" href="../Splunk_ML_Toolkit/experiments">AI Toolkit の Experiments を開く ↗</a> → <b>Smart Outlier Detection</b> → <b>Create New Experiment</b>。Experiment Title は <code>Password Spraying Attack - 自分のユーザー名</code>（共用の環境で、ほかの人とぶつからないように）'),
         ("Define", "データソースに <b>Search</b> を選び、Search 1-3 の SPL を貼る。時間範囲は <b>2026/7/12 〜 7/22</b> にする。Data Preview に40行が出たら <b>Next</b>"),
         ("Learn", "<b>Field to analyze</b> は unique_accounts、<b>Split by fields</b> は dvc、<b>Distribution type</b> は Auto、<b>Outlier tolerance threshold</b> は <b>0.0017</b> にして <b>Detect Outliers</b>"),
         ("Review", "右上の <b>Total Outliers</b> と、グループごとの分布を見る。「Too few training points in some groups」の注意は、端末ごとの行が少ないために出る。よければ <b>Save and Next</b>"),
         ("Operationalize", "<b>Publish</b> でモデル名を <code>Password_Spray_Attack_自分のユーザー名</code>（空白は使えないので _ でつなぐ）にして公開する。資料では公開先を Enterprise Security にしている"),
     ]) + '<p>Outlier tolerance threshold は「分布の端のどれだけを外れ値の範囲にするか」です。0.0017 なら端の0.17%です。行の0.17%が外れ値になるという意味ではありません。</p>',
     "refs": ["n61_0.png", "n62_0.png", "n63_0.png"],
     "checks": ["資料の画面では Total Outliers が 2（winserver の2点）",
                "この検証環境で同じ設定を SPL で実行すると（次の Search 1-5）、外れ値は1点だった。行の少ない分布の推定はわずかな違いで変わるので、数が資料と違っても慌てない",
                "Search 1-2 で見つかった 172.16.50.200 の4アカウントは、DensityFunction では外れ値にならない。MKRAEUSEN-D の分布の中に収まっているため"]},
    {"id": "n1-5", "tag": "Search 1-5", "title": "GUI 1-4 と同じことを SPL でやる",
     "body": ["Smart Outlier Detection が裏で実行する <code>fit DensityFunction</code> を、そのまま SPL で書いたものです。<code>into</code> を付けていないので、モデルは保存しません。"],
     "spl": N1_PREP + "\n| fit DensityFunction unique_accounts by dvc dist=auto threshold=0.0017\n| where 'IsOutlier(unique_accounts)'=1\n| table _time IpAddress dvc unique_accounts tried_accounts",
     **N_JUL, "range_note": N_RANGE_JUL,
     "views": [("table", "外れ値になった行")],
     "checks": ["この環境では1行（7/21 10:06、172.16.50.206 から rschlitzer-d への、アカウント名が空の失敗。unique_accounts は 0）",
                "ジョブの注意に「Too few training points in some groups」と出る。GUI の Learn の注意と同じ",
                "Search 1-2 と結果が違う。単純な統計は「4以上」という人の知識を入れているが、DensityFunction は分布の形だけで判断している"]},
    {"id": "n1-6", "tag": "Search 1-6", "title": "（追加）9月のスプレーにも同じ SPL を当てる",
     "body": ["取り込んだデータには、9/14〜9/28 にワークショップ用の端末（computer1〜10）へ向けたスプレーも入っています。Search 1-2 と同じ SPL を、時間範囲だけ変えて実行します。",
              "同じ検知が、別の時期、別の端末にもそのまま使えるかを確かめます。"],
     "spl": N1_STATS, **N_SEP, "range_note": N_RANGE_SEP,
     "views": [("table", "外れ値になった2分間")],
     "checks": ["8行出る。すべて 172.16.48.255 から computer2、3、4、7、8、9 へ",
                "1回の2分間で6〜8アカウント（user13 や user97 など）を試している",
                "computer1、5、6、10 も狙われているが、ふだんの試行が多い（comp_avg が高い）ので上限を超えなかった。平均と標準偏差の上限は、ふだんからノイズの多い組では効きにくい"]},
]
N1_INTRO = ('<div class="aitk-hero-text"><span class="aitk-kicker">AITK Security for Ninja ／ Lab1</span>'
            '<h1>リモートからのパスワードスプレーを検知する</h1>'
            '<p>パスワードスプレー（MITRE ATT&amp;CK T1110.003）は、1つのアカウントに多くのパスワードを試す総当たりと違い、1つ（または少数）のパスワードを多くのアカウントに試します。'
            '1アカウントあたりの失敗が少ないので、ロックアウトや決め打ちのしきい値では見つけにくい攻撃です。</p>'
            '<p>ここでは、同じ送信元が短い間に多くのアカウントで失敗していないかを、まず単純な統計で、次に AI Toolkit の Smart Outlier Detection で探し、2つの方法を比べます。</p>'
            '<p class="aitk-flow">データを見る → 平均＋2σでスプレーを見つける → Smart Outlier Detection 用のデータを作る → GUI で外れ値を探す → 同じことを SPL で → 9月のデータにも当てる</p></div>'
            + img("n49_1.png", "aitk-hero-icon"))

n2 = [
    {"id": "n2-1", "tag": "Search 2-1", "title": "明示的な資格情報を使ったログオン（4648）をユーザーごとに見る（Technique #1）",
     "body": ["イベント 4648 は、明示的に資格情報を指定したログオンの試みです。RunAs や、別のアカウントで動くスケジュールタスクでも出ます。",
              "ユーザー（src_user）ごとの件数を折れ線にして、いつもより多いユーザーを目で探します。"],
     "spl": N2_BASE + "\n| timechart count by src_user", **N_JUL, "range_note": N_RANGE_JUL,
     "views": [("line", "ユーザーごとの 4648 の件数（1日ごと）")],
     "refs": ["n68_0.png"],
     "checks": ["7/20〜7/21 に件数が集まっている",
                "いちばん高いのは 7/21 の MKRAEUSEN-D$ の26件。次が 7/20 の KTANNINSKY-L$ の19件",
                "src_user が <code>$</code> で終わるのはコンピューターのアカウント。端末の上で動くサービスやタスクが、別のアカウントの資格情報を使ったことを表す"]},
    {"id": "n2-2", "tag": "Search 2-2", "title": "1日ごと、ユーザーごとの件数を作る",
     "body": ["Technique #2 では、AI Toolkit の Detect Numeric Outliers を使います。次の GUI 2-3 で入力欄に入れる SPL です。"],
     "spl": N2_DAILY, **N_JUL, "range_note": N_RANGE_JUL,
     "views": [("table", "ユーザーと日ごとの件数")],
     "checks": ["24行。1行が「あるユーザーのある日の 4648 の件数」",
                "件数は1〜26。平均は約7.7、標準偏差は約6.3"]},
    {"id": "n2-3", "tag": "GUI 2-3", "title": "Detect Numeric Outliers で外れ値を探す",
     "body": ["AI Toolkit アプリの <b>Experiments</b> で <b>Detect Numeric Outliers</b> を選び、Experiment を作ります。"],
     "extra_html": exp_steps([
         ("開く", '<a class="aitk-open" target="_blank" href="../Splunk_ML_Toolkit/experiments">AI Toolkit の Experiments を開く ↗</a> → <b>Detect Numeric Outliers</b> → <b>Create New Experiment</b>。Experiment Title は <code>Escalated Privilege Windows - 自分のユーザー名</code>'),
         ("検索", "<b>Enter a search</b> に Search 2-2 の SPL を入れ、時間範囲を <b>2026/7/12 〜 7/22</b> にして検索する"),
         ("設定", "<b>Field to analyze</b> は count、<b>Threshold method</b> は <b>Standard Deviation</b>、<b>Threshold multiplier</b> は <b>2</b>。<b>Sliding window</b> と <b>Fields to split by</b> は空のまま"),
         ("実行", "<b>Detect Outliers</b> を押す。外れ値が多すぎるときは倍率を上げる（範囲が広がり、外れ値が減る）"),
         ("確かめる", "グラフの下の <b>Show SPL</b> で、画面が生成した SPL を見る。平均と標準偏差を求め、倍率から上下の範囲を作り、範囲の外に印を付ける、という流れが次の Search 2-4 と同じになっている。<b>Data and Outliers</b> のグラフで黄色の点を押すと、その行が分かる"),
     ]),
     "refs": ["n73_0.png", "n74_0.png", "n75_0.png", "n76_0.png"],
     "checks": ["外れ値は1つ。資料の画面では約20件の点が黄色になっている",
                "この環境では 7/21 の MKRAEUSEN-D$ の26件（上限は約20.3）"]},
    {"id": "n2-4", "tag": "Search 2-4", "title": "GUI 2-3 と同じことを SPL でやる",
     "body": ["Detect Numeric Outliers の Standard Deviation は、全行の平均±標準偏差×倍率を範囲にします。Fields to split by を空にしたので、ユーザーに分けずに1つの範囲です。"],
     "spl": N2_DAILY + "\n| eventstats avg(count) as avg stdev(count) as stdev\n| eval lowerBound=avg-stdev*2, upperBound=avg+stdev*2\n| eval isOutlier=if(count<lowerBound OR count>upperBound,1,0)",
     **N_JUL, "range_note": N_RANGE_JUL,
     "views": [("table", "外れ値の行", None, "| where isOutlier=1 | table _time src_user count avg stdev upperBound"),
               ("table", "全24行", None, "| sort - count | table _time src_user count upperBound isOutlier")],
     "checks": ["外れ値は1行。2026/7/21 の MKRAEUSEN-D$、26件",
                "lowerBound はマイナスになる（平均7.7−標準偏差6.3×2）。件数は0より小さくならないので、下側の外れ値は出ない",
                "倍率を 1.5 にすると、7/20 の KTANNINSKY-L$（19件）も外れ値になる"]},
    {"id": "n2-5", "tag": "Search 2-5", "title": "外れ値の中身を調べる",
     "body": ["外れ値の日の MKRAEUSEN-D$ の 4648 を、誰の資格情報を、どこに向けて、どのプロセスが使ったかで分けます。",
              "4648 が多いことは、権限の昇格が成功した証拠ではありません。使われたアカウントやプロセスを見て、ふだんの管理作業か自動処理なのかを確かめます。"],
     "spl": N2_BASE + ' src_user="MKRAEUSEN-D$"\n| stats count by TargetUserName TargetServerName ProcessName\n| sort - count',
     "earliest": 1784559600, "latest": 1784646000, "range_note": "2026/7/21（日本時間）",
     "views": [("table", "使われた資格情報とプロセス")],
     "checks": ["いちばん多いのは malloryk の資格情報を svchost.exe が localhost に向けて使った7件。lsass.exe からも3件",
                "Lab1 で 172.16.50.200 が MKRAEUSEN-D に malloryk を試していた（7/21 05:56）。同じ端末で同じアカウントが出てくる",
                "DWM-4〜7 は画面の描画のためのアカウントで、ログオンのたびに出るふだんのもの"]},
]
N2_INTRO = ('<div class="aitk-hero-text"><span class="aitk-kicker">AITK Security for Ninja ／ Lab2</span>'
            '<h1>権限昇格のイベントを検知する</h1>'
            '<p>攻撃者は、手に入れた資格情報を使って、より強い権限で操作しようとします。Windows のイベント 4648（明示的な資格情報を使ったログオンの試み）は、その手がかりの1つです。'
            'ただし RunAs やスケジュールタスクでもふつうに出るので、件数がいつもより多いユーザーを見つけて、中身を確かめます。</p>'
            '<p>ここでは、まずユーザーごとの件数を折れ線で見て目で探し、次に AI Toolkit の Detect Numeric Outliers で範囲を計算させます。</p>'
            '<p class="aitk-flow">ユーザーごとの件数を見る → 1日ごとの件数を作る → Detect Numeric Outliers → 同じことを SPL で → 外れ値の中身を調べる</p></div>'
            + img("n64_1.png", "aitk-hero-icon"))

n3 = [
    {"id": "n3-1", "tag": "Search 3-1", "title": "HTTP の User-Agent を見る",
     "body": ["Lab3 で使うのは、Splunk Stream が取った HTTP の通信です。User-Agent（http_user_agent）は、通信したソフトウェアが名乗る文字列で、ブラウザ、OS の更新、スクリプト、スキャナーなどで違います。",
              "User-Agent はカテゴリ（文字の値）なので、数値の外れ値とは別の方法で探します。まず資料の SPL で、どんなデータかを見ます。"],
     "spl": N3_BASE + "\n| table http_user_agent action dest_port bytes_in bytes_out", **N_HTTP, "range_note": N_RANGE_HTTP,
     "views": [("table", "先頭の10行"),
               ("table", "User-Agent ごとの件数（多い順）", None, "| stats count by http_user_agent | sort - count")],
     "checks": ["268,983件。資料の画面（269,126件）とほぼ同じ",
                "User-Agent は110種類。多いのは ELB-HealthChecker/2.0（約5.5万件）、UserAgent（約2.9万件）、Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)（約2.9万件）",
                "MSIE 6.0 のような古いブラウザを名乗る通信も、これだけ数が多いと「珍しい値」にはならない。次の GUI 3-2 の方法で見つかるのは、数の少ない値だけ"]},
    {"id": "n3-2", "tag": "GUI 3-2", "title": "Detect Categorical Outliers で珍しい User-Agent を探す",
     "body": ["AI Toolkit アプリの <b>Experiments</b> で <b>Detect Categorical Outliers</b> を選び、Experiment を作ります。"],
     "extra_html": exp_steps([
         ("開く", '<a class="aitk-open" target="_blank" href="../Splunk_ML_Toolkit/experiments">AI Toolkit の Experiments を開く ↗</a> → <b>Detect Categorical Outliers</b> → <b>Create New Experiment</b>。Experiment Title は <code>HTTP User Agent Outliers - 自分のユーザー名</code>'),
         ("検索", "<b>Enter a search</b> に Search 3-1 の SPL を入れ、時間範囲を <b>2026/7/12 〜 8/11</b>（または All time）にして検索する"),
         ("設定", "<b>Field(s) to analyze</b> に http_user_agent を選び、<b>Detect Outliers</b> を押す"),
         ("見る", "<b>Outlier(s)</b> の数と、<b>Data and Outliers</b> の表（probable_cause、isOutlier）を見る"),
         ("比べる", "Field(s) to analyze を bytes_in や bytes_out に変えて、もう一度 Detect Outliers を押す。数値の項目をカテゴリとして扱うと、どうなるかを見る"),
     ]) + ('<h4 style="margin:14px 0 4px;">考えること</h4>'
           + ul(["裏で何をしているか。値の出やすさを確率で求め、めったに出ない値に印を付けている（次の Search 3-3）",
                 "bytes_in のような数値を「値の種類」として数えると、たまたま一度しか出なかったバイト数が珍しい値になる。数値の外れ値には、Lab1 や Lab2 の方法が向いている",
                 "珍しいことと、悪いことは違う。印が付いたものは、調べる候補として扱う"])),
     "refs": ["n82_0.png", "n83_1.jpg"],
     "checks": ["Outlier(s) は <b>16</b>。資料の画面と同じ",
                "curl/7.72.0、python-requests/2.24.0、Windows-Update-Agent、Picasa などが並ぶ。どれも期間中に1回しか出なかった User-Agent"]},
    {"id": "n3-3", "tag": "Search 3-3", "title": "GUI 3-2 と同じことを SPL でやる",
     "body": ["Detect Categorical Outliers は、裏で <code>anomalydetection</code> コマンドを実行しています。<code>action=annotate</code> にすると、全イベントを残したまま、珍しい値のイベントに印を付けます。"],
     "spl": N3_BASE + '\n| table http_user_agent action dest_port bytes_in bytes_out\n| anomalydetection "http_user_agent" action=annotate\n| eval isOutlier=if(probable_cause!="",1,0)',
     **N_HTTP, "range_note": N_RANGE_HTTP,
     "views": [("table", "外れ値の数", None, "| stats count by isOutlier"),
               ("table", "外れ値になった User-Agent", None, "| where isOutlier=1 | stats count by http_user_agent probable_cause")],
     "checks": ["isOutlier=1 が16件、0 が268,967件。GUI の数と同じ",
                "16件はすべて、期間中に1回だけ出た User-Agent"]},
    text_row('<div class="aitk-step-head"><span class="aitk-tag aitk-tag-info">解説</span><h2>User-Agent をクラスタリングする理由</h2></div>'
             '<p>User-Agent の文字列は、バージョンの数字が1つ違うだけで別の値になります。Detect Categorical Outliers は値が一致するかどうかしか見ないので、'
             '<code>Chrome/84.0.4147.105</code> と <code>Chrome/84.0.4147.125</code> も、まったく別の珍しい値として扱います。</p>'
             '<p>そこで、文字列の「似ている度合い」で考えます。</p>'
             '<p class="aitk-flow">User-Agent → TF-IDF で数値にする → KMeans で似たものをまとめる → まとまりの中心から遠いものを調べる</p>'
             + ul(["<b>TF-IDF</b>：文字列を、単語や文字のつながり（N-gram）ごとの重みの数値に変える。どの文字列にも出る語は軽く、その文字列にしか出ない語は重くなる",
                   "<b>KMeans</b>：数値にした User-Agent を、似たもの同士の k 個のまとまりに分ける。ラベルは要らない",
                   "<b>cluster_distance</b>：まとまりの中心からの距離。遠いほど、ほかと似ていない"])),
    {"id": "n3-4", "tag": "Search 3-4", "title": "TF-IDF で User-Agent を数値にする",
     "body": ["<code>fit TFIDF</code> は、文字列を機械学習で使える数値の列に変える前処理です。重いので、資料のとおり3,000件に絞ります。"],
     "spl": N3_TFIDF, **N_HTTP, "range_note": N_RANGE_HTTP,
     "views": [("table", "TF-IDF の結果（先頭10行）"),
               ("table", "作られた数値の列の数", None, '| fields http_user_agent_tfidf_* | head 1 | transpose 0 | stats count as "TF-IDF の列の数"')],
     "refs": ["n87_0.png"],
     "checks": ["元の http_user_agent の列は残り、<code>http_user_agent_tfidf_…</code> という数値の列が増える",
                "この環境では TF-IDF の列が75個できた",
                "<code>head 3000</code> は新しい順の3,000件なので、期間の最後（8/10〜8/11）のイベントになる。User-Agent は18種類"]},
    {"id": "n3-5", "tag": "Search 3-5", "title": "KMeans で5つのまとまりに分ける",
     "body": ["TF-IDF の数値の列を使って、似た User-Agent を5つのまとまり（k=5）に分けます。まとまりの番号に意味はありません。中に入っている値を見て、どんなまとまりかを読みます。"],
     "spl": N3_TFIDF + "\n| fit KMeans k=5 http_user_agent_tfidf_*\n| stats count dc(http_user_agent) as ua values(http_user_agent) as user_agents by cluster",
     **N_HTTP, "range_note": N_RANGE_HTTP,
     "views": [("table", "まとまりごとの User-Agent")],
     "refs": ["n89_0.png"],
     "checks": ["4つのまとまりは、それぞれ1種類の User-Agent だけ（Microsoft-Delivery-Optimization、Microsoft-CryptoAPI、Microsoft-WNS、python-requests/2.18.4）。件数の多い値がそれぞれ1つのまとまりになった",
                "残りの14種類（pdrlabs、ipip.net、ブラウザ、BITS など）は1つのまとまりに入った。KMeans は数の多いところに中心を置くので、珍しいものはまとめて残る"]},
    {"id": "n3-6", "tag": "Search 3-6", "title": "中心から遠い User-Agent を順に並べる",
     "body": ["まとまりを1つ（k=1）にして、全体の中心からの距離で並べます。上に来るものほど、ほかの User-Agent と似ていません。"],
     "spl": (N3_BASE + "\n| table http_user_agent, src_ip, dest_ip, action, dest_port, bytes_in, bytes_out\n| head 3000\n"
             "| fit TFIDF http_user_agent\n| fit KMeans k=1 http_user_agent_tfidf_*\n| fields - http_user_agent_tfidf_*\n"
             "| stats max(cluster_distance) by cluster http_user_agent\n| sort - max(cluster_distance)"),
     **N_HTTP, "range_note": N_RANGE_HTTP,
     "views": [("table", "中心から遠い順")],
     "refs": ["n91_0.png"],
     "checks": ["18行。上から pdrlabs（Cloud mapping experiment）、NetSystemsResearch、ipip.net（HTTP Banner Detection）、Ruby、cpprestsdk、zgrab",
                "上位はインターネットを調べて回るスキャナーや、スクリプトのライブラリ。社内のブラウザや Windows の部品は下のほうに来る",
                "上位の User-Agent は、送信元の IP、宛先、action、バイト数を合わせて見てから、アラートやリスクの対象にする"]},
    text_row('<div class="aitk-step-head"><span class="aitk-tag aitk-tag-gui" style="background:#7b3fa0;">GUI</span><h2>マルウェアの通信を予測する（Predict the Presence of Malware）</h2></div>'
             '<p>Lab3 の最後は、AI Toolkit の Showcase の <b>Predict the Presence of Malware</b> を開き、firewall_traffic.csv でマルウェアの通信を当てる分類モデルを見ます。'
             'ここまでの Lab はラベルの要らない方法でしたが、これは正解のラベルを使う教師あり学習です。</p>'
             '<p>この内容は、Rookies の演習2で SPL と画面の両方を使って詳しく扱っています。<a class="aitk-open" href="rookies_ex2">Rookies 演習2 を開く ↗</a></p>'
             '<h4 style="margin:14px 0 4px;">資料の問い</h4>'
             + ul(["当てたい項目（used_by_malware）と、手がかりにする項目はどれか",
                   "アルゴリズムを変えると、Precision、Recall、F1 はどう変わるか。どれがいちばんよく、なぜ違うのか",
                   "Accuracy だけで決めてよいか。yes と no の数が偏っているときは、見逃し（Recall）と誤検知（Precision）も見る",
                   "ほかにどんなセキュリティの結果を予測できるか。そのためにどんなデータと項目が要るか。予測はアナリストの判断にどう役立つか"])
             + img("n92_0.png", "aitk-fig")),
]
N3_INTRO = ('<div class="aitk-hero-text"><span class="aitk-kicker">AITK Security for Ninja ／ Lab3</span>'
            '<h1>カテゴリの外れ値を検知する</h1>'
            '<p>HTTP の User-Agent のような文字の値（カテゴリ）は、平均や標準偏差では扱えません。ここでは、まず AI Toolkit の Detect Categorical Outliers で珍しい値を探し、'
            '次に TF-IDF と KMeans で文字列の似ている度合いを使って、ほかと似ていない User-Agent を探します。</p>'
            '<p class="aitk-flow">データを見る → Detect Categorical Outliers → 同じことを SPL で → TF-IDF → KMeans k=5 → KMeans k=1 で距離の順 → 分類モデル（Rookies 演習2）</p></div>'
            + img("n77_1.png", "aitk-hero-icon"))

n4 = [
    {"id": "n4-1", "tag": "Search 4-1", "title": "HTTP エラーのデータを見る",
     "body": ["Lab4 では、AI Toolkit の <code>| ai</code> コマンドで外部の LLM を呼び、HTTP のエラーごとの対処を提案させます。",
              "使うのは、HTTP のエラーコード（HTTP_Code）、メッセージ（Error_Message）、原因（Root_Cause）を書いた10行のルックアップです。このアプリに同梱しています。"],
     "spl": "| inputlookup http_error_dataset.csv", **N_LKP, "range_note": N_RANGE_LKP,
     "views": [("table_wrap", "http_error_dataset.csv")],
     "refs": ["n98_0.png"],
     "checks": ["10行。REQ-001〜REQ-010",
                "1行が1つのエラー。HTTP_Code、Error_Message、Root_Cause の3つを、次のプロンプトに埋め込む"]},
    {"id": "n4-2", "tag": "GUI 4-2", "title": "LLM の接続先を確かめる（Connections）",
     "body": ["<code>| ai</code> は、AI Toolkit の <b>Connections</b> に登録した LLM を呼びます。ここでは <b>Google Gemini</b> の <code>gemini-3.6-flash</code> を使います。"],
     "extra_html": (exp_steps([
         ("開く", '<a class="aitk-open" target="_blank" href="../Splunk_ML_Toolkit/connections">AI Toolkit の Connections を開く ↗</a>'),
         ("見る", "<b>Gemini</b> タブにモデル <code>gemini-3.6-flash</code> の接続があり、既定（Default）になっていることを確かめる。設定は変えない"),
     ]) + '<p class="aitk-note">AI Toolkit の Gemini の既定のモデル名（gemini-2.5-flash）は、新しく作った API キーでは使えません。モデル名は手で入れます。'
          '<code>| ai</code> はプロンプトを外部のサービスに送るので、本番では送ってよいデータか、誰が使えるかを決めてから使います。</p>'),
     "refs": ["n97_0.png"]},
    {"id": "n4-3", "tag": "Search 4-3", "title": "LLM に対処の手順を提案させる（資料のプロンプト）",
     "body": ["資料の SPL です。LLM に送るのは先頭の2行です。",
              "各行の値が <code>'{HTTP_Code}'</code> のように書いたところに入り、行ごとに別のプロンプトになって LLM に送られます。1行あたり10〜20秒かかります。"],
     "spl": f'| inputlookup http_error_dataset.csv\n| head 2\n| ai prompt="{N4_PROMPT}" {N_LLM}',
     **N_LKP, "range_note": N_RANGE_LKP,
     "views": [("table_wrap", "LLM の答え（ai_result_1）", None, "| table Request_ID HTTP_Code Root_Cause ai_result_1")],
     "refs": ["n101_0.png"],
     "checks": ["2行に ai_result_1 の列が付き、英語で手順が返る（REQ-001 の 500、REQ-002 の 404）。この環境では2行で約26秒、答えは1行あたり約2,500字だった",
                "答えは Markdown で書かれるので、<code>**</code> や <code>|</code> がそのまま文字で出る",
                "「This model is currently experiencing high demand」で失敗したら、Google 側の混雑。少し待つか、model を <code>gemini-3.5-flash-lite</code> に変えて試す"]},
    {"id": "n4-4", "tag": "Search 4-4", "title": "プロンプトを変えてみる（日本語で、短く）",
     "body": ["同じデータで、プロンプトだけを変えます。言語や長さ、形式を指定すると、答えも変わります。資料の Challenge のとおり、プロンプトの書き方と答えを見比べます。"],
     "spl": f'| inputlookup http_error_dataset.csv\n| head 2\n| ai prompt="{N4_PROMPT_JA}" {N_LLM}',
     **N_LKP, "range_note": N_RANGE_LKP,
     "views": [("table_wrap", "LLM の答え（ai_result_1）", None, "| table Request_ID HTTP_Code ai_result_1")],
     "checks": ["日本語で、番号付きの4〜5行の手順が返る。この環境では1行あたり200字前後で、Search 4-3 の約10分の1の長さだった",
                "答えが、渡した HTTP_Code、Error_Message、Root_Cause に沿っているか。もっともらしいが間違った手順が混ざっていないかを確かめる"],
     "extra_html": ('<h4 style="margin:14px 0 4px;">LLM の答えを使うときの注意</h4>'
                    + ul(["LLM は、自信のある書き方で間違ったことを答えることがある。答えは人が読んで確かめてから使う",
                          "送るデータに、個人情報や秘密の情報が入っていないかを確かめる。無料枠では、送った内容がサービスの改善に使われる場合がある",
                          "答えをそのまま自動で実行しない。対処を自動化するなら、範囲を決め、人の承認を挟む"]))},
]
N4_INTRO = ('<div class="aitk-hero-text"><span class="aitk-kicker">AITK Security for Ninja ／ Lab4</span>'
            '<h1>外部の LLM を使う</h1>'
            '<p>AI Toolkit の <code>| ai</code> コマンドを使うと、サーチの結果の各行を外部の LLM に渡し、答えを列として受け取れます。'
            'ここでは、HTTP のエラーと原因を LLM に渡して、対処の手順を提案させます。</p>'
            '<p>LLM の答えは、アナリストの手助けです。そのまま信じて自動で実行するものではありません。</p>'
            '<p class="aitk-flow">データを見る → 接続先を確かめる → 資料のプロンプトで | ai → プロンプトを変えて比べる</p></div>'
            + img("n95_1.png", "aitk-hero-icon"))

NINJA_SUMMARY = f'''
<div class="aitk-doc">
<header class="aitk-doc-hero">
  <span class="aitk-kicker">AITK Security for Ninja ／ Summary</span>
  <h1>統計、相関、機械学習を使い分ける</h1>
  <p>Splunk4Ninjas Machine Learning for Security の講義部分を短くまとめたページです。機械学習とは何か、セキュリティのどこで役に立つか、Splunk の何を使うかを確かめてから、4つの Lab に進みます。</p>
</header>

<section>
  <h2>AI、機械学習、ディープラーニング、生成 AI</h2>
  <table class="aitk-table">
    <thead><tr><th style="width:22%;">言葉</th><th>意味</th></tr></thead>
    <tbody>
      <tr><td><b>AI</b></td><td>学習や問題解決のような、人の知的な働きをコンピューターにさせること全体</td></tr>
      <tr><td><b>機械学習（ML）</b></td><td>AI の一部。データから規則を学ばせ、人が1つずつ指示しなくても判断や予測ができるようにする</td></tr>
      <tr><td><b>ディープラーニング</b></td><td>機械学習の一部。何層ものニューラルネットワークで、画像や音声の認識のような複雑なことをする</td></tr>
      <tr><td><b>生成 AI</b></td><td>学んだパターンから、文章、画像、コードのような新しいものを作る（Lab4 の LLM）</td></tr>
    </tbody>
  </table>
  <p>機械学習は、データと問いから始まります。学習でデータのパターンをモデルにし、そのモデルを新しいデータに当てて、分類したり、点数を付けたり、予測したりします。モデルは時間がたつだけでは良くなりません。<b>学習 → 評価 → 適用 → 監視</b>を回し、必要なら新しいデータで学習し直します。</p>
</section>

<section>
  <h2>相関は機械学習ではない</h2>
  <p>いっしょに動く項目や出来事を探す相関は、よい手がかりになります。ただ、相関だけでは機械学習ではなく、原因であることも示しません。「X なら Y」というルールは人が書いた関係で、機械学習のモデルは例から関係を推定し、学習に使わなかったデータで確かめる必要があります。</p>
  <p>セキュリティでは両方を使います。分かっている振る舞いはルールで、複雑なものや変わっていくものはモデルで探します。</p>
</section>

<section>
  <h2>機械学習の現実</h2>
  <table class="aitk-table">
    <thead><tr><th style="width:50%;">よくある思い違い</th><th>機械学習が得意なこと</th></tr></thead>
    <tbody><tr>
      <td>{ul(["データを全部入れて待てば答えが出る魔法ではない", "どんなデータの問題も解決するわけではない", "汎用の人工知能と同じではない", "Splunk 標準の predict コマンドと同じではない", "相関ルールの置き換えではない"])}</td>
      <td>{ul(["データの中のパターンを見つけ、ふだんの姿（ベースライン）を作って、これからの検知に使う", "問いがはっきりしていて範囲が決まっており、必要なデータをよく知っているときにいちばん役に立つ"])}</td>
    </tr></tbody>
  </table>
  <p>データサイエンティストの仕事の約8割は、データを集めて整える作業です。結果の良し悪しは、モデルより先に、データがそろっていて、形が整っていて、実態を表しているかで決まります。平均と標準偏差のような単純な統計や決め打ちのしきい値も大事な道具で、まずそこから始めるのがふつうです。</p>
</section>

<section>
  <h2>機械学習の種類</h2>
  <table class="aitk-table">
    <thead><tr><th style="width:24%;">種類</th><th>データ</th><th style="width:34%;">主な方法</th></tr></thead>
    <tbody>
      <tr><td><b>教師あり学習</b></td><td>正解のラベルが付いたデータ</td><td>回帰、分類（Lab3 の最後）</td></tr>
      <tr><td><b>教師なし学習</b></td><td>ラベルの無いデータ</td><td>クラスタリング、外れ値の検知（Lab1〜3）</td></tr>
      <tr><td><b>強化学習と人のフィードバック</b></td><td>行動の結果に対する報酬や、人の評価</td><td>強化学習、人が判断を返して直す仕組み</td></tr>
    </tbody>
  </table>
</section>

<section>
  <h2>セキュリティで機械学習が要る理由</h2>
  <p>SOC が扱うイベントの量と速さでは、人の目だけで見るのは現実的ではありません。機械学習は、大量のイベントをまとめ、ふだんの振る舞いを学び、そこから外れたものを調べる順に並べます。怪しい動きがたくさんのイベントに散らばっているときや、時間とともに変わるときに特に役立ちます。</p>
  <p>ただし、機械学習はイベントが悪いものだと証明はしません。アナリストの目を向ける先を決める道具です。モデルの結果に、ID、端末、ネットワーク、脅威情報、業務の文脈を合わせて判断します。</p>
  <table class="aitk-table">
    <thead><tr><th style="width:20%;">型</th><th>問い</th><th>セキュリティでの使い方</th></tr></thead>
    <tbody>
      <tr><td><b>外れ値の検知</b></td><td>ふだんと何が違うか</td><td>過去の自分や、似た仲間からのずれを探す。長い時間をかけて少しずつ進む攻撃（low and slow）にも使える</td></tr>
      <tr><td><b>予測</b></td><td>次に何が起きそうか</td><td>過去の対応結果から、アラートが本物か誤検知かを予測する。過去の対応から次の対応を勧める</td></tr>
      <tr><td><b>クラスタリング</b></td><td>何と何が似ているか</td><td>動きの似たユーザーや端末の仲間を作る。似たアラートをまとめてノイズを減らす</td></tr>
    </tbody>
  </table>
</section>

<section>
  <h2>Splunk で機械学習を回すのに要るもの</h2>
  <table class="aitk-table">
    <thead><tr><th style="width:24%;">役割</th><th>担当すること</th></tr></thead>
    <tbody>
      <tr><td><b>その分野の専門家</b>（IT、セキュリティ）</td><td>使い道を決め、結果が業務にどう効くかを説明する</td></tr>
      <tr><td><b>Splunk の担当者</b></td><td>データを探して整え、サーチ、レポート、アラート、ワークフローとして動かす</td></tr>
      <tr><td><b>データサイエンティスト</b></td><td>統計の知識でアルゴリズムを選び、モデルを作って評価する</td></tr>
    </tbody>
  </table>
  <p>AI Toolkit は、Experiments のガイドや Showcase の例、<code>fit</code>、<code>apply</code>、<code>score</code> などの ML-SPL コマンドで、この3つの役割をつなぎます。30以上の標準のアルゴリズムに加えて、Python for Scientific Computing の300以上のオープンソースのアルゴリズムや、ML-SPL API で足した独自のアルゴリズムも使えます。さらに高度なことは DSDL（Data Science and Deep Learning）で、コンテナの中の JupyterLab と TensorFlow や PyTorch を使って行います。</p>
  <p>学習したモデルは、スケジュールしたサーチ、検知、ダッシュボード、アラートの中で <code>| apply</code> して使います。動かすことと監視することまでが、機械学習の作業に含まれます。</p>
</section>

<section>
  <h2>Splunk の AI</h2>
  <ul>
    <li><b>AI Assistant</b>：SPL を自然な言葉から作る、説明する（AI Assistant for SPL）。ES では Finding の要約と調査を、Observability Cloud では原因の切り分けを手伝う</li>
    <li><b>Splunk MCP Server</b>：外部の AI エージェントから、Splunk のデータの検索や SPL の生成を使えるようにする。アクセスは Splunk のロールの権限に従う</li>
    <li><b>AI Canvas</b>：セキュリティ、IT、ネットワークの担当者と AI Assistant が、同じ画面で1つのインシデントを調べる</li>
    <li><b>AI Toolkit と DSDL</b>：自分のデータでモデルを作り、試し、動かす土台。このコースで使う</li>
  </ul>
</section>

<section>
  <h2>Lab</h2>
  <table class="aitk-table">
    <thead><tr><th style="width:26%;">Lab</th><th>データ</th><th>方法</th></tr></thead>
    <tbody>
      <tr><td><a href="ninja_lab1"><b>Lab1：パスワードスプレー</b></a></td><td>Windows 4625（LogonType=3）</td><td>平均＋2σ と決め打ちの条件 → Smart Outlier Detection（DensityFunction）</td></tr>
      <tr><td><a href="ninja_lab2"><b>Lab2：権限昇格</b></a></td><td>Windows 4648</td><td>timechart を目で見る → Detect Numeric Outliers（標準偏差）</td></tr>
      <tr><td><a href="ninja_lab3"><b>Lab3：カテゴリの外れ値</b></a></td><td>Stream の HTTP（User-Agent）</td><td>Detect Categorical Outliers → TF-IDF と KMeans → 分類モデル</td></tr>
      <tr><td><a href="ninja_lab4"><b>Lab4：外部の LLM</b></a></td><td>http_error_dataset.csv</td><td>| ai コマンド（この環境では Gemini）</td></tr>
    </tbody>
  </table>
  <p>どの Lab でも、まず問いを決め、データを整え、統計か機械学習を当て、結果を読みます。手順をなぞるだけでなく、方法どうしを比べ、なぜその結果になるのか、攻撃だと決める前に何を確かめるべきかを考えてください。</p>
</section>

<section>
  <h2>このコースで身につけること</h2>
  <ul>
    <li>統計、相関、機械学習の違いを説明できる</li>
    <li>数値、カテゴリ、文字列のデータに合った方法を選べる</li>
    <li>AI Toolkit で、ふだんと違うセキュリティの動きを見つけて調べられる</li>
    <li>モデルの結果を、自動の結論ではなく調べる手がかりとして読める</li>
    <li>LLM を、人の確認とデータの管理のもとで使える</li>
  </ul>
</section>
<footer class="aitk-next"><b>Ninja</b><a href="ninja_lab1">Lab1</a><a href="ninja_lab2">Lab2</a><a href="ninja_lab3">Lab3</a><a href="ninja_lab4">Lab4</a></footer>
</div>
'''


HOME = f'''
<div class="aitk-doc">
<header class="aitk-doc-hero">
  <span class="aitk-kicker">AITK Security Training</span>
  <h1>Splunk AI Toolkit で学ぶセキュリティの機械学習</h1>
  <p>BOTS v2 のデータを使い、ダッシュボードからサーチを1つずつ実行しながら AI Toolkit（旧 MLTK）の使い方を学ぶトレーニングアプリです。コースは3段階あります。</p>
</header>
<div class="aitk-courses">
  <div class="aitk-course aitk-course-on">
    <span class="aitk-level">入門</span><h2>AITK Security for Primer</h2>
    <p>平均±2σの手動の外れ値検知から始めて、DensityFunction と StateSpaceForecast の fit / apply までを体験します。</p>
    <ul>
      <li><a href="primer_summary">Summary：機械学習の前に知っておくこと</a></li>
      <li><a href="primer_s1">シナリオ1：ユーザーアクセスの異常を検知する</a></li>
      <li><a href="primer_s2">シナリオ2：ユーザーログイン数の異常を検知する</a></li>
      <li><a href="primer_s3">シナリオ3：CPU 使用率を予測する</a></li>
      <li><a href="primer_s4">シナリオ4：ネットワーク使用率テレメトリの外れ値を検知する</a></li>
    </ul>
  </div>
  <div class="aitk-course aitk-course-on">
    <span class="aitk-level">初中級</span><h2>AITK Security for Rookies</h2>
    <p>AI Toolkit の Showcase と Experiment を使い、MAD による外れ値検知、分類モデルの学習と評価、ES の検知への組み込みまでを体験します。</p>
    <ul>
      <li><a href="rookies_summary">Summary：セキュリティの機械学習を始める前に</a></li>
      <li><a href="rookies_ex1">演習1：ユーザーの振る舞いの外れ値を検知する</a></li>
      <li><a href="rookies_ex2">演習2：マルウェアの通信を予測する</a></li>
      <li><a href="rookies_ex3">演習3：ML を ES で運用する</a></li>
    </ul>
  </div>
  <div class="aitk-course aitk-course-on">
    <span class="aitk-level">上級</span><h2>AITK Security for Ninja</h2>
    <p>単純な統計と AI Toolkit の Experiments を比べながら、パスワードスプレー、権限昇格、珍しい User-Agent を探し、| ai で外部の LLM も使います。</p>
    <ul>
      <li><a href="ninja_summary">Summary：統計、相関、機械学習を使い分ける</a></li>
      <li><a href="ninja_lab1">Lab1：リモートからのパスワードスプレーを検知する</a></li>
      <li><a href="ninja_lab2">Lab2：権限昇格のイベントを検知する</a></li>
      <li><a href="ninja_lab3">Lab3：カテゴリの外れ値を検知する</a></li>
      <li><a href="ninja_lab4">Lab4：外部の LLM を使う</a></li>
    </ul>
  </div>
</div>
<section>
  <h2>アルゴリズムの一覧</h2>
  <p>AI Toolkit のアルゴリズムの特徴と使いどころを、メニューの <b>アルゴリズム</b> にまとめています。<a href="algo_overview">概要</a>、<a href="algo_outlier">外れ値（Outlier）</a>、<a href="algo_predictive">予測（Predictive）</a>、<a href="algo_categorization">分類（Categorization）</a>の4ページです。</p>
</section>
<section>
  <h2>このアプリの使い方</h2>
  <ul>
    <li>各シナリオは上から順に進めます。「▶ Search x-x を実行」を押すと、そのステップのサーチが走って結果が出ます。</li>
    <li>fit のステップはモデルを保存します。apply のステップは、その前の fit を実行してから押してください。</li>
    <li>結果パネル右下の虫眼鏡アイコンから Search &amp; Reporting で開けば、SPL を自分で書き換えて試せます。</li>
    <li>右側には元資料の画面キャプチャを並べています。上部のチェックボックスで消せます。</li>
  </ul>
  <h2>必要な環境</h2>
  <p>Primer：AI Toolkit、Python for Scientific Computing、Splunk Add-on for Microsoft Windows、<code>index=botsv2</code>（BOTS v2 フルデータセット）。</p>
  <p>Rookies：AI Toolkit、Python for Scientific Computing、Splunk Enterprise Security 8.x（演習3）。サンプルの logins.csv と firewall_traffic.csv はこのアプリに同梱しています。</p>
  <p>Ninja：AI Toolkit、Python for Scientific Computing、Splunk Add-on for Microsoft Windows、資料の Windows（4625、4648）と Stream の HTTP のデータ、AI Toolkit の Connections に登録した LLM（Lab4）。http_error_dataset.csv はこのアプリに同梱しています。</p>
</section>
</div>
'''

COMING = lambda name: f'''<div class="aitk-doc"><header class="aitk-doc-hero"><span class="aitk-kicker">{name}</span>
<h1>{name}</h1><p>このコースは準備中です。まずは <a href="primer_summary">AITK Security for Primer</a> から始めてください。</p></header></div>'''

NAV = '''<nav search_view="search" color="#0b2d3a">
  <view name="search" icon="magnifier" />
  <view name="summary" default="true" icon="layoutoverview" />
  <collection label="AITK Security for Primer" icon="bookmark">
    <view name="primer_summary" />
    <view name="primer_s1" />
    <view name="primer_s2" />
    <view name="primer_s3" />
    <view name="primer_s4" />
  </collection>
  <collection label="AITK Security for Rookies" icon="chartline">
    <view name="rookies_summary" />
    <view name="rookies_ex1" />
    <view name="rookies_ex2" />
    <view name="rookies_ex3" />
  </collection>
  <collection label="AITK Security for Ninja" icon="star">
    <view name="ninja_summary" />
    <view name="ninja_lab1" />
    <view name="ninja_lab2" />
    <view name="ninja_lab3" />
    <view name="ninja_lab4" />
  </collection>
  <collection label="アルゴリズム" icon="circlesfour">
    <view name="algo_overview" />
    <view name="algo_outlier" />
    <view name="algo_predictive" />
    <view name="algo_categorization" />
  </collection>
</nav>
'''

APP_CONF = f'''[install]
is_configured = true
build = {BUILD}

[ui]
is_visible = true
label = AITK Security Training

[launcher]
author = Splunk Japan
description = AI Toolkit を使ったセキュリティ機械学習のハンズオン（Primer / Rookies / Ninja）
version = {VERSION}

[package]
id = {APP}
check_for_updates = false
'''

META = '''[]
access = read : [ * ], write : [ admin, sc_admin, power ]
export = none

# Rookies exercise 3 runs the detection search inside Enterprise Security
[lookups/firewall_traffic.csv]
export = system

# Ninja Lab4 (| ai) can be run from the AI Toolkit app
[lookups/http_error_dataset.csv]
export = system
'''


def main():
    if os.path.exists(OUT):
        shutil.rmtree(OUT)  # generated output only; source of truth is this script
    for d in ["default/data/ui/views", "default/data/ui/nav", "metadata", "appserver/static/img", "static", "lookups"]:
        os.makedirs(os.path.join(OUT, d), exist_ok=True)
    w = lambda p, s: open(os.path.join(OUT, p), "w", encoding="utf-8").write(s)
    w("default/app.conf", APP_CONF)
    w("default/data/ui/nav/default.xml", NAV)
    w("metadata/default.meta", META)
    v ="default/data/ui/views/"
    w(v + "summary.xml", html_dashboard("Summary", HOME))
    w(v + "primer_summary.xml", html_dashboard("Primer: Summary（機械学習の前に）", PRIMER_SUMMARY))
    w(v + "primer_s1.xml", scenario_form("Primer: シナリオ1 ユーザーアクセスの異常を検知する", S1_INTRO, s1))
    w(v + "primer_s2.xml", scenario_form("Primer: シナリオ2 ユーザーログイン数の異常を検知する", S2_INTRO, s2))
    w(v + "primer_s3.xml", scenario_form("Primer: シナリオ3 CPU 使用率を予測する", S3_INTRO, s3))
    w(v + "primer_s4.xml", scenario_form("Primer: シナリオ4 ネットワークテレメトリの外れ値を検知する", S4_INTRO, s4))
    w(v + "rookies_summary.xml", html_dashboard("Rookies: Summary（セキュリティの機械学習を始める前に）", ROOKIES_SUMMARY))
    w(v + "rookies_ex1.xml", scenario_form("Rookies: 演習1 ユーザーの振る舞いの外れ値を検知する", R1_INTRO, r1))
    w(v + "rookies_ex2.xml", scenario_form("Rookies: 演習2 マルウェアの通信を予測する", R2_INTRO, r2))
    w(v + "rookies_ex3.xml", scenario_form("Rookies: 演習3 ML を ES で運用する", R3_INTRO, r3))
    w(v + "algo_overview.xml", html_dashboard("概要", ALGO_OVERVIEW))
    w(v + "algo_outlier.xml", html_dashboard("外れ値（Outlier）", ALGO_OUTLIER))
    w(v + "algo_predictive.xml", html_dashboard("予測（Predictive）", ALGO_PREDICTIVE))
    w(v + "algo_categorization.xml", html_dashboard("分類（Categorization）", ALGO_CATEGORIZATION))
    w(v + "ninja_summary.xml", html_dashboard("Ninja: Summary（統計、相関、機械学習を使い分ける）", NINJA_SUMMARY))
    w(v + "ninja_lab1.xml", scenario_form("Ninja: Lab1 リモートからのパスワードスプレーを検知する", N1_INTRO, n1))
    w(v + "ninja_lab2.xml", scenario_form("Ninja: Lab2 権限昇格のイベントを検知する", N2_INTRO, n2))
    w(v + "ninja_lab3.xml", scenario_form("Ninja: Lab3 カテゴリの外れ値を検知する", N3_INTRO, n3))
    w(v + "ninja_lab4.xml", scenario_form("Ninja: Lab4 外部の LLM を使う", N4_INTRO, n4))
    shutil.copy(os.path.join(HERE, "aitk.css"), os.path.join(OUT, "appserver/static/aitk.css"))
    for f in os.listdir(os.path.join(HERE, "lookups")):  # AITK sample data, copied for Rookies
        shutil.copy(os.path.join(HERE, "lookups", f), os.path.join(OUT, "lookups", f))
    for f in os.listdir(os.path.join(HERE, "web")):
        shutil.copy(os.path.join(HERE, "web", f), os.path.join(OUT, "appserver/static/img", f))
    for src, dst in [("appIcon.png", "appIcon.png"), ("appIcon_2x.png", "appIcon_2x.png"),
                     ("appIcon.png", "appIconAlt.png"), ("appIcon_2x.png", "appIconAlt_2x.png")]:
        shutil.copy(os.path.join(HERE, "appicon", src), os.path.join(OUT, "static", dst))  # drawn by appicon/make_icon.py
    spl = os.path.join(os.path.dirname(HERE), f"{APP}-{VERSION}.spl")
    with tarfile.open(spl, "w:gz") as t:
        t.add(OUT, arcname=APP, filter=lambda ti: None if os.path.basename(ti.name).startswith(".") else ti)
    print("wrote", spl)


if __name__ == "__main__":
    main()
