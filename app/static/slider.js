/* 顶象「智能无感」滑块——在用户自己的浏览器里跑，服务端不参与。
 *
 * 为什么要放在浏览器里
 *   X-LF-DXRisk-Captcha-Token = "<滑块 token>:<指纹>"，滑块 token 由 /api/v1 签发并
 *   与本次请求的 c（设备指纹）绑定。要拿它必须：把指纹写进 localStorage → 让顶象 SDK
 *   出题 → 解出缺口 → 拖动 → 读 /api/v1。这套东西天然属于浏览器，服务端装 chromium
 *   既重又慢，所以只在这里做。
 *
 * 三个实测结论（决定了下面的实现）
 *   1. SDK 会自动把 localStorage 里的 `_dx_app_<appId>` 填进 /api/a 的 c 参数，
 *      不需要改写请求（Playwright 那套路由重写在这里用不上）。
 *   2. widget 自己的 canvas 被跨域图片污染，getImageData/toDataURL 直接抛 TypeError；
 *      但按图片 URL 自己 fetch（mode:'cors'）能拿到字节 → 自己画到离屏 canvas 上再取像素。
 *   3. 页面内合成 MouseEvent（isTrusted=false）+ 26 步 16ms 的移动，顶象认，
 *      /api/v1 返回 success:true。所以不需要真实指针事件。
 */
(function (global) {
  'use strict';

  var APP_ID = 'd1a43734fc59aeae9f1562dbd70fdf54';
  var API_SERVER = 'https://ly-ver.longhu.net';
  var SDK_URL = 'https://s.longfor.com/dx-captcha/index.js';

  var seen = {a: null, imgs: [], v1: null};
  var hooked = false;

  function log() {
    if (global.console && global.DXSlider && global.DXSlider.debug) {
      console.log.apply(console, ['[DXSlider]'].concat([].slice.call(arguments)));
    }
  }

  /* ---------- 观测：/api/a 的 JSON、图片 URL、/api/v1 的返回 ---------- */

  function hook() {
    if (hooked) return;
    hooked = true;

    // 只打原型，不替换构造器：SDK 里 `new XMLHttpRequest()` / `new Image()` 照旧工作
    var xp = global.XMLHttpRequest && global.XMLHttpRequest.prototype;
    if (xp && xp.open) {
      var open0 = xp.open;
      xp.open = function (m, u) {
        try {
          var url = String(u);
          if (url.indexOf('/api/a') >= 0) {
            this.addEventListener('load', function () {
              try { seen.a = JSON.parse(this.responseText); } catch (e) { log('api/a 解析失败', e); }
            });
          } else if (url.indexOf('/api/v1') >= 0) {
            this.addEventListener('load', function () {
              try { seen.v1 = JSON.parse(this.responseText); } catch (e) { /* 交给调用方超时 */ }
            });
          }
        } catch (e) { /* 观测失败不影响 SDK */ }
        return open0.apply(this, arguments);
      };
    }

    // p1/p2 是 new Image() 加载的，DOM 里查不到，只能拦 src 赋值
    var ip = global.HTMLImageElement && global.HTMLImageElement.prototype;
    var d = ip && Object.getOwnPropertyDescriptor(ip, 'src');
    if (d && d.set) {
      Object.defineProperty(ip, 'src', {
        configurable: true,
        enumerable: d.enumerable,
        get: d.get,
        set: function (v) {
          try {
            var s = String(v);
            if (s.indexOf('/api/p') >= 0 && seen.imgs.indexOf(s) < 0) seen.imgs.push(s);
          } catch (e) { /* 忽略 */ }
          return d.set.call(this, v);
        }
      });
    }
  }

  function imageUrls() {
    var out = seen.imgs.slice();
    if (!out.length && global.performance) {
      global.performance.getEntriesByType('resource').forEach(function (e) {
        if (e.name.indexOf('/api/p') >= 0) out.push(e.name);
      });
    }
    return out;
  }

  function findUrl(kind) {
    // /api/a 里直接给了 p1/p2 的路径，拼接域即可（最稳，不依赖任何 hook）
    var a = seen.a;
    if (a && a[kind]) {
      var p = String(a[kind]);
      return /^https?:/.test(p) ? p : API_SERVER + p;
    }
    var urls = imageUrls();
    for (var i = 0; i < urls.length; i++) {
      if (urls[i].indexOf('/api/' + kind) >= 0) return urls[i];
    }
    return '';
  }

  /* ---------- 图像：取字节 → 离屏 canvas → ImageData ---------- */

  function fetchBytes(url) {
    return fetch(url, {mode: 'cors', credentials: 'omit'}).then(function (r) {
      if (!r.ok) throw new Error('取图失败 ' + r.status + ' ' + url.slice(0, 60));
      return r.arrayBuffer();
    });
  }

  function decode(bytes) {
    return createImageBitmap(new Blob([bytes], {type: 'image/png'})).then(function (bmp) {
      var cv = document.createElement('canvas');
      cv.width = bmp.width; cv.height = bmp.height;
      var ctx = cv.getContext('2d');
      ctx.drawImage(bmp, 0, 0);
      return ctx.getImageData(0, 0, cv.width, cv.height);
    });
  }

  /* ---------- 缺口定位（cv2 那套的等价实现） ---------- */

  function order32(o) {
    var out = [], v, i, k;
    if (!o) return out;
    for (i = 0; i < o.length && out.length < 32; i++) {
      v = o.charCodeAt(i) % 32;
      while (out.indexOf(v) >= 0) v = (v + 1) % 32;
      out.push(v);
    }
    return out;
  }

  // 底图是按竖条打乱后拼进来的，按 order 还原：输出第 k 条 = 输入第 order[k] 条
  function unshuffle(px, w, h, order) {
    var out = new Uint8ClampedArray(px.length);
    out.set(px);
    var n = order.length || 32;
    var space = Math.floor(w / n) || 1;
    for (var k = 0; k < n; k++) {
      var srcX = space * (order[k] % n), dstX = space * k;
      if (srcX >= w || dstX >= w) continue;
      for (var y = 0; y < h; y++) {
        for (var x = 0; x < space && srcX + x < w && dstX + x < w; x++) {
          var s = (y * w + srcX + x) * 4, d = (y * w + dstX + x) * 4;
          out[d] = px[s]; out[d + 1] = px[s + 1]; out[d + 2] = px[s + 2]; out[d + 3] = 255;
        }
      }
    }
    return out;
  }

  function gray(px, w, h) {
    var g = new Float32Array(w * h);
    for (var i = 0, j = 0; i < px.length; i += 4, j++) {
      g[j] = 0.114 * px[i] + 0.587 * px[i + 1] + 0.299 * px[i + 2];
    }
    return g;
  }

  function sobel(g, w, h) {
    var mag = new Float32Array(w * h), x, y, i;
    for (y = 1; y < h - 1; y++) {
      for (x = 1; x < w - 1; x++) {
        i = y * w + x;
        var gx = -g[i - w - 1] - 2 * g[i - 1] - g[i + w - 1] + g[i - w + 1] + 2 * g[i + 1] + g[i + w + 1];
        var gy = -g[i - w - 1] - 2 * g[i - w] - g[i - w + 1] + g[i + w - 1] + 2 * g[i + w] + g[i + w + 1];
        mag[i] = Math.sqrt(gx * gx + gy * gy);
      }
    }
    return mag;
  }

  // 3-4 chamfer 距离变换：每个像素到最近边缘的距离
  function distance(mag, w, h, thresh) {
    var INF = 1e9, dt = new Float32Array(w * h), x, y, i;
    for (i = 0; i < dt.length; i++) dt[i] = mag[i] > thresh ? 0 : INF;
    for (y = 1; y < h; y++) {
      for (x = 1; x < w; x++) {
        i = y * w + x;
        var v = Math.min(dt[i], dt[i - w] + 3, dt[i - 1] + 3, dt[i - w - 1] + 4, dt[i - w + 1] + 4);
        dt[i] = v;
      }
      if (y < h - 1) {
        var e = y * w + w - 1;
        dt[e] = Math.min(dt[e], dt[e - w] + 3);
      }
    }
    for (y = h - 2; y >= 0; y--) {
      for (x = w - 2; x >= 0; x--) {
        i = y * w + x;
        dt[i] = Math.min(dt[i], dt[i + w] + 3, dt[i + 1] + 3, dt[i + w + 1] + 4, dt[i + w - 1] + 4);
      }
      var s = y * w;
      dt[s] = Math.min(dt[s], dt[s + w] + 3);
    }
    return dt;
  }

  // Canny 近似：强边打底 + 弱边按 8 邻域滞后扩张（对应 cv2.Canny(30, 90)）
  function edgeMap(g, w, h) {
    var mag = sobel(g, w, h);
    var edge = new Uint8Array(w * h), stack = [], i, STRONG = 90, WEAK = 30;
    for (i = 0; i < mag.length; i++) {
      if (mag[i] >= STRONG) { edge[i] = 1; stack.push(i); }
    }
    while (stack.length) {
      i = stack.pop();
      var x = i % w, y = (i - x) / w;
      for (var dy = -1; dy <= 1; dy++) {
        for (var ddx = -1; ddx <= 1; ddx++) {
          var xx = x + ddx, yy = y + dy;
          if (xx < 0 || yy < 0 || xx >= w || yy >= h) continue;
          var j = yy * w + xx;
          if (!edge[j] && mag[j] >= WEAK) { edge[j] = 1; stack.push(j); }
        }
      }
    }
    return edge;
  }

  // 到最近边缘的距离场（3-4 chamfer 两避扫描）
  function distToEdge(edge, w, h) {
    var INF = 1e9, dt = new Float32Array(w * h), x, y, i;
    for (i = 0; i < dt.length; i++) dt[i] = edge[i] ? 0 : INF;
    for (y = 1; y < h; y++) {
      for (x = 1; x < w; x++) {
        i = y * w + x;
        dt[i] = Math.min(dt[i], dt[i - w] + 3, dt[i - 1] + 3, dt[i - w - 1] + 4, dt[i - w + 1] + 4);
      }
    }
    for (x = w - 2; x >= 0; x--) {
      dt[(h - 1) * w + x] = Math.min(dt[(h - 1) * w + x], dt[(h - 1) * w + x + 1] + 3);
    }
    for (y = h - 2; y >= 0; y--) {
      for (x = w - 2; x >= 0; x--) {
        i = y * w + x;
        dt[i] = Math.min(dt[i], dt[i + w] + 3, dt[i + 1] + 3, dt[i + w + 1] + 4, dt[i + w - 1] + 4);
      }
      dt[y * w + w - 1] = Math.min(dt[y * w + w - 1], dt[(y + 1) * w + w - 1] + 3);
    }
    return dt;
  }

  /* 拼块 alpha 轮廓 × 全图边缘距离场 的相关匹配（复刻 pass_slider.chamfer_locate）
     score(x,y) = 轮廓点处的平均距离，取最小即轮廓与边缘最贴合处 */
  function chamferLocate(grayPx, w, h, tpl) {
    var pts = tpl.pts || [], N = pts.length;
    if (!N) return null;
    var edge = edgeMap(grayPx, w, h);
    var nEdges = 0, i;
    for (i = 0; i < edge.length; i++) if (edge[i]) nEdges++;
    if (nEdges < 200) return null;

    var dt = distToEdge(edge, w, h);
    var kw = tpl.w, kh = tpl.h;
    var maxX = w - kw, maxY = h - kh;
    if (maxX < 1 || maxY < 1) return null;

    var stride = maxX + 1;
    var score = new Float32Array(stride * (maxY + 1));
    var best = 1e18, bx = 0, by = 0, x, y, k, s;
    for (y = 0; y <= maxY; y++) {
      for (x = 0; x <= maxX; x++) {
        s = 0;
        for (k = 0; k < N; k++) s += dt[(y + pts[k][1]) * w + x + pts[k][0]];
        s /= N;
        score[y * stride + x] = s;
        if (s < best) { best = s; bx = x; by = y; }
      }
    }

    var r = Math.max(12, Math.round(0.75 * Math.max(kw, kh)));
    var s2 = 1e18, v;
    for (y = 0; y <= maxY; y++) {
      for (x = 0; x <= maxX; x++) {
        if (Math.abs(x - bx) < r && Math.abs(y - by) < r) continue;
        v = score[y * stride + x];
        if (v < s2) s2 = v;
      }
    }
    if (!isFinite(s2)) s2 = best;
    var conf = (s2 - best) / Math.max(s2, 1e-6) * Math.exp(-best / 2);
    conf = Math.max(0, Math.min(1, conf));
    return {x0: bx, y0: by, s1: Math.round(best * 1000) / 1000,
            s2: Math.round(s2 * 1000) / 1000, conf: Math.round(conf * 1000) / 1000, w: kw, h: kh};
  }

  // 拼块：alpha>110 的包围盒 + 轮廓点（边缘匹配用）+ 采样像素（暗度匹配用）
  function pieceTemplate(p2) {
    var w = p2.width, h = p2.height, px = p2.data;
    var x0 = w, y0 = h, x1 = -1, y1 = -1, x, y;
    for (y = 0; y < h; y++) {
      for (x = 0; x < w; x++) {
        if (px[(y * w + x) * 4 + 3] > 110) {
          if (x < x0) x0 = x; if (x > x1) x1 = x;
          if (y < y0) y0 = y; if (y > y1) y1 = y;
        }
      }
    }
    if (x1 < 0) return null;
    var bw = x1 - x0 + 1, bh = y1 - y0 + 1;
    var pts = [];
    for (y = y0; y <= y1; y++) {
      for (x = x0; x <= x1; x++) {
        if (px[(y * w + x) * 4 + 3] <= 110) continue;
        var edge = x === x0 || x === x1 || y === y0 || y === y1 ||
          px[(y * w + x - 1) * 4 + 3] <= 110 || px[(y * w + x + 1) * 4 + 3] <= 110 ||
          px[((y - 1) * w + x) * 4 + 3] <= 110 || px[((y + 1) * w + x) * 4 + 3] <= 110;
        if (edge) pts.push([x - x0, y - y0]);
      }
    }
    if (!pts.length) return null;
    return {w: bw, h: bh, pts: pts};
  }

  /* ---------- 拖动 ---------- */

  var DRAG_JS = function (dx, steps) {
    var el = document.querySelector('.dx_captcha_basic_slider');
    if (!el) return Promise.resolve('NO_HANDLE');
    var r = el.getBoundingClientRect();
    var sx = r.x + r.width / 2, sy = r.y + r.height / 2;
    var fire = function (type, cx, cy, target) {
      (target || document).dispatchEvent(new MouseEvent(type, {
        bubbles: true, cancelable: true, clientX: cx, clientY: cy,
        button: 0, buttons: type === 'mouseup' ? 0 : 1, view: window
      }));
    };
    fire('mousedown', sx, sy, el);
    var chain = Promise.resolve();
    for (var i = 1; i <= steps; i++) {
      (function (i) {
        chain = chain.then(function () {
          fire('mousemove', sx + dx * i / steps, sy);
          return new Promise(function (r2) { setTimeout(r2, 16); });
        });
      })(i);
    }
    return chain.then(function () {
      fire('mouseup', sx + dx, sy);
      return 'OK';
    });
  };

  /* ---------- 主流程 ---------- */

  function sleep(ms) {
    return new Promise(function (r) { setTimeout(r, ms); });
  }

  function until(fn, timeoutMs, step) {
    var t0 = Date.now();
    return new Promise(function (resolve) {
      (function loop() {
        var v = fn();
        if (v) return resolve(v);
        if (Date.now() - t0 > timeoutMs) return resolve(null);
        setTimeout(loop, step || 120);
      })();
    });
  }

  function loadSdk() {
    if (global._dx && global._dx.Captcha) return Promise.resolve(true);
    return new Promise(function (resolve) {
      var s = document.createElement('script');
      s.src = SDK_URL;
      s.onload = function () { resolve(!!(global._dx && global._dx.Captcha)); };
      s.onerror = function () { resolve(false); };
      document.head.appendChild(s);
    });
  }

  function canvasEl() {
    var list = document.querySelectorAll('canvas');
    for (var i = 0; i < list.length; i++) {
      if (list[i].width === 400 && list[i].height === 200) return list[i];
    }
    return list[list.length - 1] || null;
  }

  /**
   * 过一次滑块。返回 {ok, token, gap, dx, stage, error}
   *   fingerprint: 服务端生成的那份指纹（写进 localStorage，SDK 会填到 c）
   */
  async function solve(fingerprint, opts) {
    opts = opts || {};
    var appId = opts.appId || APP_ID;
    var timeout = opts.timeoutMs || 30000;
    var onStatus = opts.onStatus || function () {};

    hook();
    seen.a = null; seen.v1 = null; seen.imgs = [];
    try { localStorage.setItem('_dx_app_' + appId, fingerprint); } catch (e) { /* 隐私模式 */ }

    onStatus('loading');
    if (!(await loadSdk())) {
      return {ok: false, stage: 'sdk', error: '顶象脚本没加载出来（检查网络/被拦截）'};
    }

    var host = document.createElement('div');
    host.id = 'dx-slider-host';
    host.style.cssText = 'position:fixed;inset:0;z-index:2147483000;background:rgba(0,0,0,.45);display:flex;align-items:center;justify-content:center;';
    var box = document.createElement('div');
    box.style.cssText = 'background:#fff;border-radius:12px;padding:16px;min-width:340px;min-height:220px;';
    host.appendChild(box);
    document.body.appendChild(host);

    var cap = null;
    try {
      // 这些字段和线上页面一致，少一个 SDK 就会在内部 new 一个 undefined 而抛错
      cap = new global._dx.Captcha(box, {
        appId: appId,
        apiServer: opts.apiServer || API_SERVER,
        constIDServer: 'https://ly-sta.longhu.net/udid/c1',
        constID_js: 'https://s.longfor.com/dx-captcha/libs/const-id.js',
        ua_js: 'https://s.longfor.com/dx-captcha/libs/greenseer.js',
        serverlessBgSrc: 'https://ly-sta.longhu.net',
        isSaaS: false,
        style: 'popup',
        success: function () {},
        fail: function () {},
        ready: function () {},
        onPassByServer: function (t) { seen.passByServer = t; }
      });
      cap.show();
    } catch (e) {
      host.remove();
      return {ok: false, stage: 'sdk', error: '起验证码失败: ' + (e && e.message)};
    }

    var gap = null, dx = 0;
    try {
      onStatus('challenge');
      var ready = await until(function () {
        return seen.a && findUrl('p1') && findUrl('p2') ? true : null;
      }, Math.min(timeout, 15000));
      if (!ready) return {ok: false, stage: 'challenge', error: '等不到题目（没拿到 /api/a 或图片）'};

      onStatus('solving');
      var p1 = await decode(await fetchBytes(findUrl('p1')));
      var p2 = await decode(await fetchBytes(findUrl('p2')));
      var order = order32((seen.a && seen.a.o) || '');
      var restored = unshuffle(p1.data, p1.width, p1.height, order);
      var tpl = pieceTemplate(p2);
      if (!tpl) return {ok: false, stage: 'solve', error: '拼块是空的'};
      var gw = p1.width, gh = p1.height;
      gap = chamferLocate(gray(restored, gw, gh), gw, gh, tpl);
      if (!gap) return {ok: false, stage: 'solve', error: '找不到缺口'};

      var cv = canvasEl();
      var cvRect = cv ? cv.getBoundingClientRect() : null;
      // 位移的是 /api/p2 那张 img；.dx_captcha_basic_pic 只是外框，拿它会得到 0
      var piece = null;
      var imgs = document.querySelectorAll('img');
      for (var ii = 0; ii < imgs.length; ii++) {
        if ((imgs[ii].src || '').indexOf('/api/p2') >= 0) { piece = imgs[ii]; break; }
      }
      if (!piece) piece = document.querySelector('.dx_captcha_basic_pic');
      var pcRect = piece ? piece.getBoundingClientRect() : null;
      var yHint = null;
      if (cvRect && pcRect) {
        yHint = (pcRect.y - cvRect.y) * p1.height / (cvRect.height || 1);
      }
      if (!(yHint > 1 && yHint + tpl.h < p1.height - 1)) {
        yHint = seen.a && typeof seen.a.y === 'number' ? seen.a.y * p1.height / 150 : null;
      }

      // 与原方案一致：缺口左上角 x 直接按画布比例换到 CSS，再扣掉拼块初始左偏移
      var ratio = cvRect && cvRect.width ? cvRect.width / gw : 1;
      var targetCss = gap.x0 * ratio;
      var offsetCss = cvRect && pcRect ? pcRect.x - cvRect.x : 0;
      dx = Math.max(4, Math.round(targetCss - offsetCss));
      gap.dbg = {
        img: gw + 'x' + gh,
        cv: cvRect ? [Math.round(cvRect.width), Math.round(cvRect.height)] : null,
        pc: pcRect ? [Math.round(pcRect.x - cvRect.x), Math.round(pcRect.width)] : null,
        ratio: Number(ratio.toFixed(3)), targetCss: Math.round(targetCss), offsetCss: Math.round(offsetCss),
        yHint: yHint === null ? null : Math.round(yHint)
      };

      onStatus('dragging');
      var dragged = await until(function () {
        return document.querySelector('.dx_captcha_basic_slider') ? true : null;
      }, 5000);
      if (!dragged) return {ok: false, stage: 'drag', error: '没找到滑块手柄'};
      var ret = await DRAG_JS(dx, 26);
      if (ret !== 'OK') return {ok: false, stage: 'drag', error: '拖动没发出去'};

      var done = await until(function () { return seen.v1 ? true : null; }, Math.min(timeout, 15000));
      if (!done) return {ok: false, stage: 'verify', error: '服务端没回 /api/v1'};
      var v = seen.v1;
      if (!v || !v.success || !v.token) {
        return {ok: false, stage: 'verify', error: (v && (v.msg || v.error)) || '滑块没过，可重试', code: v && v.code, gap: gap, dx: dx};
      }
      onStatus('done');
      return {ok: true, token: v.token, gap: gap, dx: dx};
    } catch (e) {
      return {ok: false, stage: 'exception', error: String((e && e.message) || e), gap: gap, dx: dx};
    } finally {
      try { cap && cap.destroy && cap.destroy(); } catch (e) { /* 忽略 */ }
      host.remove();
    }
  }

  /** 调试用：只取题不拖动，把 p1/p2 和几何信息吐出来，方便和 cv2 版本逐项对照 */
  /* 半自动：只负责弹题、写指纹、等用户自己拖，拖通过就把 token 交回去。*/
  async function solveManual(fingerprint, opts) {
    opts = opts || {};
    var appId = opts.appId || APP_ID;
    var timeout = opts.timeoutMs || 180000;
    var onStatus = opts.onStatus || function () {};

    hook();
    seen.a = null; seen.v1 = null; seen.imgs = [];
    try { localStorage.setItem('_dx_app_' + appId, fingerprint); } catch (e) { /* 隐私模式 */ }

    onStatus('loading');
    if (!(await loadSdk())) {
      return {ok: false, stage: 'sdk', error: '顶象脚本没加载出来（检查网络/被拦截）'};
    }

    var host = document.createElement('div');
    host.id = 'dx-slider-host';
    host.style.cssText = 'position:fixed;inset:0;z-index:2147483000;background:rgba(0,0,0,.45);display:flex;align-items:center;justify-content:center;';
    var box = document.createElement('div');
    box.style.cssText = 'background:#fff;border-radius:12px;padding:16px;';
    var tip = document.createElement('div');
    tip.textContent = '把拼块拖到缺口处，拖对会自动通过';
    tip.style.cssText = 'font-size:13px;color:#555;margin-bottom:10px;';
    box.appendChild(tip);
    host.appendChild(box);
    document.body.appendChild(host);

    var cap = null;
    try {
      cap = new global._dx.Captcha(box, {
        appId: appId,
        apiServer: opts.apiServer || API_SERVER,
        constIDServer: 'https://ly-sta.longhu.net/udid/c1',
        constID_js: 'https://s.longfor.com/dx-captcha/libs/const-id.js',
        ua_js: 'https://s.longfor.com/dx-captcha/libs/greenseer.js',
        serverlessBgSrc: 'https://ly-sta.longhu.net',
        isSaaS: false,
        style: 'popup',
        success: function () {},
        fail: function () {},
        ready: function () {},
        onPassByServer: function (t) { seen.passByServer = t; }
      });
      cap.show();
    } catch (e) {
      host.remove();
      return {ok: false, stage: 'sdk', error: '起验证码失败: ' + (e && e.message)};
    }

    onStatus('manual');
    var done = await until(function () { return seen.v1 ? true : null; }, timeout);
    var res;
    if (!done) {
      res = {ok: false, stage: 'manual-timeout', error: '等待超时（没拖动或没通过）'};
    } else {
      var v = seen.v1;
      res = (v && v.success && v.token)
        ? {ok: true, token: v.token}
        : {ok: false, stage: 'verify', error: (v && (v.msg || v.error)) || '没通过', code: v && v.code};
    }
    try { if (cap && cap.destroy) cap.destroy(); } catch (e) { /* 忽略 */ }
    host.remove();
    return res;
  }

  async function probe(fingerprint, opts) {
    opts = opts || {};
    var appId = opts.appId || APP_ID;
    hook();
    seen.a = null; seen.v1 = null; seen.imgs = [];
    try { localStorage.setItem('_dx_app_' + appId, fingerprint); } catch (e) { /* 忽略 */ }
    if (!(await loadSdk())) return {error: 'sdk'};
    var host = document.createElement('div');
    host.style.cssText = 'position:fixed;left:0;top:0;z-index:2147483000;';
    document.body.appendChild(host);
    var cap = new global._dx.Captcha(host, {
      appId: appId, apiServer: opts.apiServer || API_SERVER,
      constIDServer: 'https://ly-sta.longhu.net/udid/c1',
      constID_js: 'https://s.longfor.com/dx-captcha/libs/const-id.js',
      ua_js: 'https://s.longfor.com/dx-captcha/libs/greenseer.js',
      serverlessBgSrc: 'https://ly-sta.longhu.net', isSaaS: false, style: 'popup',
      success: function () {}, fail: function () {}, ready: function () {}
    });
    cap.show();
    var ok = await until(function () { return seen.a && findUrl('p1') && findUrl('p2'); }, 15000);
    if (!ok) { host.remove(); return {error: 'no challenge'}; }
    var p1 = await decode(await fetchBytes(findUrl('p1')));
    var p2 = await decode(await fetchBytes(findUrl('p2')));
    function toUrl(imgData) {
      var cv = document.createElement('canvas');
      cv.width = imgData.width; cv.height = imgData.height;
      cv.getContext('2d').putImageData(imgData, 0, 0);
      return cv.toDataURL('image/png');
    }
    var cv2 = canvasEl(), pc = null;
    var imgs = document.querySelectorAll('img');
    for (var i = 0; i < imgs.length; i++) {
      if ((imgs[i].src || '').indexOf('/api/p2') >= 0) { pc = imgs[i]; break; }
    }
    var cvRect = cv2 ? cv2.getBoundingClientRect() : null;
    var pcRect = pc ? pc.getBoundingClientRect() : null;
    var out = {o: (seen.a.o || ''), a: seen.a,
               p1: toUrl(p1), p2: toUrl(p2),
               cv: cvRect ? [cvRect.width, cvRect.height] : null,
               pc: cvRect && pcRect ? [pcRect.x - cvRect.x, pcRect.y - cvRect.y, pcRect.width, pcRect.height] : null};
    try {
      var order = order32(out.o);
      var restored = unshuffle(p1.data, p1.width, p1.height, order);
      var tpl = pieceTemplate(p2);
      out.gap = tpl ? chamferLocate(gray(restored, p1.width, p1.height), p1.width, p1.height, tpl) : null;
      out.tpl = tpl ? {w: tpl.w, h: tpl.h, pts: tpl.pts.length} : null;
    } catch (e) { out.gapErr = String(e); }
    if (!opts.keep) {
      try { cap.destroy && cap.destroy(); } catch (e) { /* 忽略 */ }
      host.remove();
    }
    return out;
  }

  global.DXSlider = {solve: solve, solveManual: solveManual, probe: probe, version: '1.2.0', debug: false,
                     _internals: {order32: order32, unshuffle: unshuffle, pieceTemplate: pieceTemplate, dragBy: DRAG_JS,
                                  chamferLocate: chamferLocate, edgeMap: edgeMap, imageUrls: imageUrls, seen: seen}};
})(window);
