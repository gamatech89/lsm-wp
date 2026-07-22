/**
 * LSM Ticket Widget — floating support panel for site admins.
 *
 * Talks only to admin-ajax.php (the platform API key never reaches the
 * browser). Screenshot capture uses the bundled html2canvas; the user can
 * draw red rectangles on the capture before attaching it.
 */
(function () {
  'use strict';

  var cfg = window.lsmTicketWidget;
  if (!cfg) return;

  var state = {
    open: false,
    tab: 'new',            // 'new' | 'list' | 'detail'
    tickets: [],
    ticket: null,          // detail payload
    screenshotBlob: null,
    draft: { type: 'bug', subject: '', message: '', priority: 'normal' }, // survives re-renders (e.g. screenshot capture)
    busy: false,
  };

  // Landeseiten lightbulb mark (extracted from the brand logo; static trusted markup)
  var LSM_LOGO_SVG = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="38.5 -0.5 36 40" fill="none" aria-hidden="true"><path d="M61.4076 37.3926C61.101 37.852 60.6411 38.1583 60.1047 38.2344C59.3383 38.3111 58.1122 38.3111 56.4263 38.3111C54.8171 38.3111 53.6675 38.2344 53.0544 38.2344C52.315 38.2344 51.9684 37.7983 51.675 37.3159C51.4607 36.8878 51.7384 36.3975 52.2114 36.3975C53.0544 36.4739 54.434 36.4739 56.4263 36.4739C58.5721 36.4739 60.0279 36.3975 60.9477 36.3975C61.2543 36.3975 61.5606 36.627 61.5606 36.9333C61.5606 37.0864 61.4841 37.2395 61.4076 37.3926Z" fill="white"/><path opacity="0.15" d="M60.1047 38.2344C59.3383 38.3111 58.1122 38.3111 56.4263 38.3111C54.8171 38.3111 53.6675 38.2344 53.0544 38.2344C52.3676 38.2344 52.0076 37.8508 51.675 37.3159C51.4607 36.8878 51.7384 36.3975 52.2114 36.3975C53.2077 36.7801 54.434 37.852 60.1047 38.2344Z" fill="black"/><path d="M63.1717 34.2543C62.7886 34.9432 62.099 35.4023 61.256 35.479C60.1832 35.5557 58.4205 35.6321 56.3514 35.6321C54.3592 35.6321 52.7497 35.5557 51.677 35.479C50.9105 35.4023 50.2208 34.9432 49.8377 34.2543L49.6079 33.8716C49.4546 33.5653 49.5311 33.1827 49.8377 33.0292C49.9142 32.9531 50.0675 32.9531 50.1443 32.9531C51.2936 33.0293 53.4394 33.1827 56.3514 33.1827C59.3402 33.1827 61.5626 33.0293 62.7886 32.9531C63.0952 32.9531 63.4018 33.1827 63.4018 33.4886C63.4018 33.7526 63.2827 34.0052 63.1717 34.2543Z" fill="white"/><path opacity="0.15" d="M61.3115 35.4661C60.2387 35.5428 58.4935 35.6315 56.4245 35.6315C54.4319 35.6315 52.8228 35.555 51.7497 35.4783C50.9835 35.4019 50.3896 35.0729 49.9183 34.3913L49.619 33.8815C49.4044 33.4533 49.6336 32.928 50.1636 32.9499C51.6966 33.5621 53.9548 34.8536 61.3115 35.4661Z" fill="black"/><path fill-rule="evenodd" clip-rule="evenodd" d="M49.1409 8.12227C48.9395 11.0718 48.7359 14.0525 49.5447 14.9706C50.831 16.1948 52.0258 17.2606 53.2159 18.1972C52.5338 19.1952 51.801 20.2699 51.3323 20.9571C51.0605 21.356 51.1641 21.8987 51.563 22.1709L53.3847 23.4136C53.7844 23.6861 54.329 23.584 54.6017 23.185L56.4795 20.4387C57.7759 21.1968 59.0499 21.7899 60.7388 22.4137C60.7393 22.4116 60.7399 22.4096 60.7408 22.4076C63.115 23.269 65.9006 23.9485 69.4412 24.5615C69.4412 24.5615 66.4959 29.8237 65.0106 30.7865C62.3044 31.9873 50.6514 31.8844 47.9663 30.7994C46.1104 30.0495 39.6299 17.8254 39.7117 15.7718C40.781 12.5045 47.6938 1.45755 48.495 1.30664C49.5748 1.76247 49.359 4.92406 49.1409 8.12227Z" fill="#C1B8C7"/><path d="M73.1573 16.8198C73.3929 14.2365 66.424 2.84007 64.2668 1.14171C63.7345 0.792473 62.5341 0.224213 58.9225 0.0791016C63.7082 12.322 62.5978 20.7862 56.7734 31.654C60.3967 31.605 64.6005 31.2063 65.1661 30.702C67.328 28.9985 72.994 18.6101 73.1573 16.8198Z" fill="#ECE4F1"/><path d="M49.2017 12.584C49.2017 12.584 47.5449 12.9189 45.0709 13.525C42.5968 14.1312 40.0329 16.2072 39.8516 16.3678C40.5783 18.8538 41.6715 21.1028 43.067 23.5871C44.4627 26.0715 46.4386 29.7049 47.7548 30.6764C48.1981 30.9777 49.851 31.2271 49.851 31.2271C49.851 31.2271 48.0565 26.1188 48.3263 21.0593C48.5958 15.9998 49.2017 12.584 49.2017 12.584Z" fill="url(#lsm-tw-g0)"/><path d="M69.2453 7.97839C69.2453 7.97839 69.0567 7.82492 70.5178 10.3304C65.3073 11.6348 61.9929 14.9725 61.9929 14.9725C61.9929 14.9725 61.8238 12.531 61.5938 9.31597C64.761 7.97839 69.2453 7.97839 69.2453 7.97839Z" fill="url(#lsm-tw-g1)"/><path d="M42.782 23.1393C42.782 23.1393 39.6992 17.114 39.6992 15.8061C40.1562 13.3841 46.8994 1.65322 48.7588 1.0562C51.1873 0.0222753 62.0738 -0.623119 64.4051 1.21974C66.3912 3.19531 68.3215 6.52553 69.1814 7.98803C56.6837 8.99641 46.4877 15.1405 42.782 23.1393Z" fill="white"/><defs><linearGradient id="lsm-tw-g0" x1="44.6755" y1="18.0828" x2="45.9866" y2="26.5416" gradientUnits="userSpaceOnUse"><stop stop-color="#D8CEDE"></stop><stop offset="0.932292" stop-color="#F3EFF5"></stop></linearGradient><linearGradient id="lsm-tw-g1" x1="64.5271" y1="7.37852" x2="66.3729" y2="16.6581" gradientUnits="userSpaceOnUse"><stop stop-opacity="0.1"></stop><stop offset="1" stop-opacity="0.04"></stop></linearGradient></defs></svg>';

  // High-contrast white lightbulb for the floating button (the detailed brand
  // mark washes out on the purple circle). Static trusted markup.
  var LSM_FAB_ICON = '<svg xmlns="http://www.w3.org/2000/svg" width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M15 14c.2-1 .7-1.7 1.5-2.5 1-.9 1.5-2.2 1.5-3.5A6 6 0 0 0 6 8c0 1 .2 2.2 1.5 3.5.7.7 1.3 1.5 1.5 2.5"/><path d="M9 18h6"/><path d="M10 22h4"/></svg>';

  var root = document.getElementById('lsm-ticket-widget-root');
  if (!root) return;

  // ---------- helpers ----------

  function ajax(action, data, files) {
    var fd = new FormData();
    fd.append('action', action);
    fd.append('nonce', cfg.ticketNonce);
    Object.keys(data || {}).forEach(function (k) { fd.append(k, data[k]); });
    (files || []).forEach(function (f) { fd.append('attachments[]', f, f.name); });
    return fetch(cfg.ajaxUrl, { method: 'POST', credentials: 'same-origin', body: fd })
      .then(function (r) { return r.json(); })
      .then(function (json) {
        if (!json || !json.success) {
          throw new Error((json && json.data && json.data.message) || cfg.i18n.genericError);
        }
        return json.data;
      });
  }

  function el(tag, attrs, children) {
    var node = document.createElement(tag);
    Object.keys(attrs || {}).forEach(function (k) {
      if (k === 'text') node.textContent = attrs[k];
      else if (k.indexOf('on') === 0) node.addEventListener(k.slice(2), attrs[k]);
      else node.setAttribute(k, attrs[k]);
    });
    (children || []).forEach(function (c) { if (c) node.appendChild(c); });
    return node;
  }

  function fmtDate(iso) {
    if (!iso) return '';
    var d = new Date(iso);
    return d.toLocaleDateString() + ' ' + d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  }

  // ---------- screenshot capture + annotation ----------

  // Emulated viewport widths for "how does it look on X" captures.
  var CAPTURE_WIDTHS = { desktop: 1920, laptop: 1366, tablet: 768, phone: 390 };

  // Instant, pixel-perfect capture of the current tab via the browser's
  // native screen-capture API. Asks the user to share the tab once; any
  // refusal/unsupported browser rejects and the caller falls back to
  // html2canvas.
  function nativeViewCapture() {
    if (!navigator.mediaDevices || !navigator.mediaDevices.getDisplayMedia) {
      return Promise.reject(new Error('unsupported'));
    }
    return navigator.mediaDevices.getDisplayMedia({
      video: { displaySurface: 'browser' },
      audio: false,
      preferCurrentTab: true,
      selfBrowserSurface: 'include',
    }).then(function (stream) {
      var video = document.createElement('video');
      video.srcObject = stream;
      video.muted = true;
      return video.play().then(function () {
        // one extra frame so the compositor settles
        return new Promise(function (resolve) { setTimeout(resolve, 150); });
      }).then(function () {
        var canvas = document.createElement('canvas');
        canvas.width = video.videoWidth;
        canvas.height = video.videoHeight;
        canvas.getContext('2d').drawImage(video, 0, 0);
        stream.getTracks().forEach(function (t) { t.stop(); });
        return canvas;
      }).catch(function (e) {
        stream.getTracks().forEach(function (t) { t.stop(); });
        throw e;
      });
    });
  }

  function html2canvasCapture(mode) {
    var opts = { useCORS: true, logging: false };
    if (!mode || mode === 'view') {
      // Just what's on screen right now.
      opts.x = window.scrollX;
      opts.y = window.scrollY;
      opts.width = window.innerWidth;
      opts.height = window.innerHeight;
      opts.windowWidth = window.innerWidth;
    } else {
      // Page re-rendered at the emulated device width (media queries apply).
      // Height is capped so long landing pages stay annotatable and under
      // the attachment size limit.
      opts.windowWidth = CAPTURE_WIDTHS[mode];
      opts.width = CAPTURE_WIDTHS[mode];
      opts.x = 0;
      opts.y = 0;
      opts.height = Math.min(document.body.scrollHeight, 2500);
    }
    return window.html2canvas(document.body, opts);
  }

  function captureScreenshot(mode, onDone) {
    state.open = false;
    render(); // hide the panel so it isn't in the shot
    root.style.display = 'none'; // hide FAB too — nothing of the widget in the shot

    var capture;
    if (!mode || mode === 'view') {
      // Native first (instant + exact pixels); html2canvas as silent fallback.
      // The share prompt can sit unanswered forever — give up after 15s.
      capture = new Promise(function (resolve) { setTimeout(resolve, 150); })
        .then(function () {
          return new Promise(function (resolve, reject) {
            var timedOut = false;
            var timer = setTimeout(function () { timedOut = true; reject(new Error('native-timeout')); }, 15000);
            nativeViewCapture().then(function (canvas) {
              clearTimeout(timer);
              if (!timedOut) resolve(canvas); // late grab: tracks already stopped, just ignore
            }, function (e) {
              clearTimeout(timer);
              reject(e);
            });
          });
        })
        .catch(function () { return html2canvasCapture('view'); });
    } else {
      capture = new Promise(function (resolve) { setTimeout(resolve, 250); })
        .then(function () { return html2canvasCapture(mode); });
    }

    capture
      .then(function (canvas) { root.style.display = ''; annotate(canvas, onDone); })
      .catch(function () { root.style.display = ''; state.open = true; render(); alert(cfg.i18n.screenshotFailed); });
  }

  function annotate(canvas, onDone) {
    var overlay = el('div', { class: 'lsm-tw-annotate-overlay' });
    var work = document.createElement('canvas');
    work.width = canvas.width;
    work.height = canvas.height;
    var ctx = work.getContext('2d');
    ctx.drawImage(canvas, 0, 0);

    var tool = 'rect'; // 'rect' | 'pen' | 'text'
    var drawing = false, sx = 0, sy = 0, base = null;
    var undoStack = [];

    ctx.strokeStyle = '#d63638';
    ctx.fillStyle = '#d63638';
    ctx.lineWidth = Math.max(3, work.width / 400);
    ctx.lineCap = 'round';
    ctx.lineJoin = 'round';

    function snapshot() {
      if (undoStack.length >= 15) undoStack.shift();
      undoStack.push(ctx.getImageData(0, 0, work.width, work.height));
    }

    function pos(e) {
      var r = work.getBoundingClientRect();
      return {
        x: (e.clientX - r.left) * (work.width / r.width),
        y: (e.clientY - r.top) * (work.height / r.height),
      };
    }

    work.addEventListener('mousedown', function (e) {
      var p = pos(e);

      if (tool === 'text') {
        var t = window.prompt(cfg.i18n.textPrompt);
        if (t) {
          snapshot();
          ctx.font = 'bold ' + Math.max(16, Math.round(work.width / 40)) + 'px sans-serif';
          ctx.fillText(t, p.x, p.y);
        }
        return;
      }

      drawing = true;
      sx = p.x; sy = p.y;
      snapshot();
      base = ctx.getImageData(0, 0, work.width, work.height);
      if (tool === 'pen') {
        ctx.beginPath();
        ctx.moveTo(p.x, p.y);
      }
    });
    work.addEventListener('mousemove', function (e) {
      if (!drawing) return;
      var p = pos(e);
      if (tool === 'rect') {
        ctx.putImageData(base, 0, 0);
        ctx.strokeRect(sx, sy, p.x - sx, p.y - sy);
      } else if (tool === 'crop') {
        // marching-ants style preview: dim everything outside the selection
        ctx.putImageData(base, 0, 0);
        ctx.save();
        ctx.fillStyle = 'rgba(0,0,0,.45)';
        ctx.fillRect(0, 0, work.width, work.height);
        ctx.clearRect(Math.min(sx, p.x), Math.min(sy, p.y), Math.abs(p.x - sx), Math.abs(p.y - sy));
        ctx.putImageData(base, 0, 0);
        ctx.globalCompositeOperation = 'multiply';
        ctx.fillRect(0, 0, work.width, work.height);
        ctx.globalCompositeOperation = 'source-over';
        var cx = Math.min(sx, p.x), cy = Math.min(sy, p.y), cw = Math.abs(p.x - sx), ch = Math.abs(p.y - sy);
        ctx.putImageData(base, 0, 0, cx, cy, cw, ch);
        ctx.setLineDash([8, 6]);
        ctx.strokeRect(cx, cy, cw, ch);
        ctx.setLineDash([]);
        ctx.restore();
      } else if (tool === 'pen') {
        ctx.lineTo(p.x, p.y);
        ctx.stroke();
      }
    });
    function finishCrop(e) {
      var p = pos(e);
      var cx = Math.round(Math.min(sx, p.x)), cy = Math.round(Math.min(sy, p.y));
      var cw = Math.round(Math.abs(p.x - sx)), ch = Math.round(Math.abs(p.y - sy));
      // restore the un-dimmed image before cutting
      ctx.putImageData(base, 0, 0);
      if (cw < 20 || ch < 20) return; // ignore accidental clicks
      var cut = document.createElement('canvas');
      cut.width = cw;
      cut.height = ch;
      cut.getContext('2d').drawImage(work, cx, cy, cw, ch, 0, 0, cw, ch);
      work.width = cw;
      work.height = ch;
      ctx.drawImage(cut, 0, 0);
      // stroke settings reset when the canvas is resized
      ctx.strokeStyle = '#d63638';
      ctx.fillStyle = '#d63638';
      ctx.lineWidth = Math.max(3, work.width / 400);
      ctx.lineCap = 'round';
      ctx.lineJoin = 'round';
      undoStack.length = 0; // old snapshots have the wrong dimensions
      setTool('rect');
    }
    function stopDrawing(e) {
      if (drawing && tool === 'crop') finishCrop(e);
      drawing = false;
    }
    document.addEventListener('mouseup', stopDrawing);

    var hint = el('div', { text: cfg.i18n.annotateHint });
    hint.style.color = '#fff';

    // Tool switcher: rectangle / pen / text / undo
    var toolButtons = {};
    function setTool(next) {
      tool = next;
      Object.keys(toolButtons).forEach(function (k) {
        toolButtons[k].className = 'lsm-tw-tool' + (k === next ? ' active' : '');
      });
    }
    var tools = el('div', { class: 'lsm-tw-tools' }, [
      toolButtons.crop = el('button', { class: 'lsm-tw-tool', text: '✂ ' + cfg.i18n.toolCrop, onclick: function () { setTool('crop'); } }),
      toolButtons.rect = el('button', { class: 'lsm-tw-tool active', text: '▭ ' + cfg.i18n.toolRect, onclick: function () { setTool('rect'); } }),
      toolButtons.pen = el('button', { class: 'lsm-tw-tool', text: '✏️ ' + cfg.i18n.toolPen, onclick: function () { setTool('pen'); } }),
      toolButtons.text = el('button', { class: 'lsm-tw-tool', text: 'T ' + cfg.i18n.toolText, onclick: function () { setTool('text'); } }),
      el('button', { class: 'lsm-tw-tool', text: '↩ ' + cfg.i18n.undo, onclick: function () {
        var prev = undoStack.pop();
        if (prev) ctx.putImageData(prev, 0, 0);
      } }),
    ]);

    var buttons = el('div', {}, [
      el('button', { class: 'lsm-tw-btn', text: cfg.i18n.attachShot, onclick: function () {
        // Downscale + JPEG so retina/full-page captures stay well under the
        // 5 MB attachment limit (a raw PNG of a large screen easily exceeds it).
        var MAX_W = 2000;
        var out = work;
        if (work.width > MAX_W) {
          out = document.createElement('canvas');
          out.width = MAX_W;
          out.height = Math.round(work.height * (MAX_W / work.width));
          out.getContext('2d').drawImage(work, 0, 0, out.width, out.height);
        }
        out.toBlob(function (blob) {
          document.removeEventListener('mouseup', stopDrawing);
          document.body.removeChild(overlay);
          state.open = true;
          onDone(blob);
        }, 'image/jpeg', 0.85);
      } }),
      el('button', { class: 'lsm-tw-btn lsm-tw-btn-secondary', text: cfg.i18n.cancel, onclick: function () {
        document.removeEventListener('mouseup', stopDrawing);
        document.body.removeChild(overlay);
        state.open = true;
        render();
      } }),
    ]);
    buttons.style.display = 'flex';
    buttons.style.gap = '8px';

    overlay.appendChild(hint);
    overlay.appendChild(tools);
    overlay.appendChild(work);
    overlay.appendChild(buttons);
    document.body.appendChild(overlay);
  }

  // ---------- views ----------

  function viewNewTicket(body) {
    var err = el('div', { class: 'lsm-tw-error' });
    var shotInfo = el('div');

    function refreshShotInfo() {
      shotInfo.innerHTML = '';
      if (state.screenshotBlob) {
        var img = el('img', { class: 'lsm-tw-shot-preview' });
        img.src = URL.createObjectURL(state.screenshotBlob);
        shotInfo.appendChild(img);
        shotInfo.appendChild(el('button', {
          class: 'lsm-tw-btn lsm-tw-btn-secondary', text: cfg.i18n.removeShot,
          onclick: function () { state.screenshotBlob = null; refreshShotInfo(); },
        }));
      }
    }
    refreshShotInfo();

    // Type picker — icon cards (accessible radiogroup)
    var typeGrid = el('div', { class: 'lsm-tc-grid lsm-ticket-ui', role: 'radiogroup', 'aria-label': cfg.i18n.type });
    (cfg.types || []).forEach(function (t) {
      var card = el('button', {
        type: 'button',
        class: 'lsm-tc-card' + (state.draft.type === t.code ? ' selected' : ''),
        role: 'radio',
        'aria-checked': state.draft.type === t.code ? 'true' : 'false',
        onclick: function () {
          state.draft.type = t.code;
          Array.prototype.forEach.call(typeGrid.querySelectorAll('.lsm-tc-card'), function (c) {
            var on = c === card;
            c.classList.toggle('selected', on);
            c.setAttribute('aria-checked', on ? 'true' : 'false');
          });
        },
      });
      var ic = el('span', { class: 'lsm-tc-ic' });
      ic.innerHTML = t.icon; // static trusted SVG shipped by the plugin
      card.appendChild(ic);
      card.appendChild(el('span', { class: 'lsm-tc-label', text: t.label }));
      typeGrid.appendChild(card);
    });

    // Priority — segmented control (accessible radiogroup)
    var priSeg = el('div', { class: 'lsm-tc-seg lsm-ticket-ui', role: 'radiogroup', 'aria-label': cfg.i18n.priority });
    (cfg.priorities || []).forEach(function (p) {
      var opt = el('button', {
        type: 'button',
        class: 'lsm-tc-seg-opt' + (state.draft.priority === p.code ? ' selected' : ''),
        role: 'radio',
        'aria-checked': state.draft.priority === p.code ? 'true' : 'false',
        text: p.label,
        onclick: function () {
          state.draft.priority = p.code;
          Array.prototype.forEach.call(priSeg.querySelectorAll('.lsm-tc-seg-opt'), function (o) {
            var on = o === opt;
            o.classList.toggle('selected', on);
            o.setAttribute('aria-checked', on ? 'true' : 'false');
          });
        },
      });
      priSeg.appendChild(opt);
    });
    var subject = el('input', { type: 'text', maxlength: '255', oninput: function () { state.draft.subject = subject.value; } });
    subject.value = state.draft.subject;
    var message = el('textarea', { rows: '4', oninput: function () { state.draft.message = message.value; } });
    message.value = state.draft.message;
    var fileInput = el('input', { type: 'file', multiple: 'multiple', accept: '.png,.jpg,.jpeg,.webp,.gif,.pdf' });

    var submit = el('button', { class: 'lsm-tw-btn', text: cfg.i18n.send, onclick: function () {
      err.textContent = '';
      if (!subject.value.trim() || !message.value.trim()) {
        err.textContent = cfg.i18n.fillRequired;
        return;
      }
      submit.disabled = true;

      var fd = new FormData();
      fd.append('action', 'lsm_submit_support');
      fd.append('lsm_nonce', cfg.supportNonce);
      fd.append('issue_type', state.draft.type);
      fd.append('priority', state.draft.priority);
      fd.append('subject', subject.value);
      fd.append('message', message.value);
      fd.append('user_email', cfg.userEmail);
      fd.append('user_name', cfg.userName);
      fd.append('problem_page', cfg.pageUrl);
      fd.append('site_url', cfg.siteUrl);

      var files = Array.prototype.slice.call(fileInput.files, 0, 5);
      if (state.screenshotBlob) {
        files.unshift(new File([state.screenshotBlob], 'page-screenshot.jpg', { type: 'image/jpeg' }));
      }
      files.slice(0, 5).forEach(function (f) { fd.append('attachments[]', f, f.name); });

      fetch(cfg.ajaxUrl, { method: 'POST', credentials: 'same-origin', body: fd })
        .then(function (r) { return r.json(); })
        .then(function (json) {
          if (!json.success) throw new Error((json.data && json.data.message) || cfg.i18n.genericError);
          state.screenshotBlob = null;
          state.draft = { type: 'bug', subject: '', message: '', priority: 'normal' };
          state.tab = 'list';
          loadList();
          alert((json.data && json.data.message) || cfg.i18n.sent);
        })
        .catch(function (e) { err.textContent = e.message; })
        .finally(function () { submit.disabled = false; render(); });
    } });

    // Screenshot: what to capture (current view by default, or the page
    // re-rendered at a device width) + the capture button.
    var modeSel = el('select', {}, [
      el('option', { value: 'view', text: cfg.i18n.modeView }),
      el('option', { value: 'desktop', text: cfg.i18n.modeDesktop }),
      el('option', { value: 'laptop', text: cfg.i18n.modeLaptop }),
      el('option', { value: 'tablet', text: cfg.i18n.modeTablet }),
      el('option', { value: 'phone', text: cfg.i18n.modePhone }),
    ]);
    var captureRow = el('div', { class: 'lsm-tw-capture-row' }, [
      modeSel,
      el('button', { class: 'lsm-tw-btn lsm-tw-btn-secondary', text: '📸 ' + cfg.i18n.captureShot, onclick: function () {
        captureScreenshot(modeSel.value, function (blob) { state.screenshotBlob = blob; render(); });
      } }),
    ]);

    body.appendChild(el('label', { text: cfg.i18n.type }));
    body.appendChild(typeGrid);
    body.appendChild(el('label', { text: cfg.i18n.priority }));
    body.appendChild(priSeg);
    body.appendChild(el('label', { text: cfg.i18n.subject }));
    body.appendChild(subject);
    body.appendChild(el('label', { text: cfg.i18n.message }));
    body.appendChild(message);
    body.appendChild(el('label', { text: cfg.i18n.screenshot }));
    body.appendChild(captureRow);
    body.appendChild(shotInfo);
    body.appendChild(el('label', { text: cfg.i18n.attachments }));
    body.appendChild(fileInput);
    body.appendChild(submit);
    body.appendChild(err);
  }

  function viewList(body) {
    if (!state.tickets.length) {
      body.appendChild(el('div', { class: 'lsm-tw-empty', text: cfg.i18n.noTickets }));
      return;
    }
    state.tickets.forEach(function (t) {
      var unread = t.last_staff_reply_at && (!t.seen_at || t.last_staff_reply_at > t.seen_at);
      var item = el('div', { class: 'lsm-tw-list-item', onclick: function () { openDetail(t.id); } }, [
        el('div', {}, [
          unread ? el('span', { class: 'lsm-tw-unread-dot' }) : null,
          el('strong', { text: t.ticket_number + ' — ' + t.subject }),
        ]),
        el('div', { class: 'lsm-tw-meta' }, [
          el('span', { class: 'lsm-tw-status lsm-tw-status-' + t.status, text: t.status.replace('_', ' ') }),
          el('span', { text: fmtDate(t.last_message_at || t.created_at) }),
          el('span', { text: '💬 ' + (t.message_count || 0) }),
        ]),
      ]);
      body.appendChild(item);
    });
  }

  function viewDetail(body) {
    var t = state.ticket;
    if (!t) return;

    body.appendChild(el('button', { class: 'lsm-tw-btn lsm-tw-btn-secondary', text: '← ' + cfg.i18n.back, onclick: function () {
      state.tab = 'list'; state.ticket = null; loadList();
    } }));
    body.appendChild(el('h3', { text: t.ticket_number + ' — ' + t.subject }));
    body.appendChild(el('span', { class: 'lsm-tw-status lsm-tw-status-' + t.status, text: t.status.replace('_', ' ') }));

    function renderAttachments(container, attachments) {
      (attachments || []).forEach(function (a) {
        container.appendChild(el('a', {
          class: 'lsm-tw-attachment',
          text: '📎 ' + a.filename,
          href: cfg.ajaxUrl + '?action=lsm_ticket_attachment&id=' + a.id + '&nonce=' + cfg.ticketNonce,
          target: '_blank',
        }));
      });
    }

    var original = el('div', { class: 'lsm-tw-msg lsm-tw-msg-client' }, [
      el('div', { class: 'lsm-tw-msg-author', text: cfg.i18n.originalMessage + ' · ' + fmtDate(t.created_at) }),
      el('div', { text: t.message }),
    ]);
    renderAttachments(original, t.attachments);
    body.appendChild(original);

    (t.messages || []).forEach(function (m) {
      var msg = el('div', { class: 'lsm-tw-msg lsm-tw-msg-' + m.author_type }, [
        el('div', { class: 'lsm-tw-msg-author', text: m.author_name + ' · ' + fmtDate(m.created_at) }),
        el('div', { text: m.message }),
      ]);
      renderAttachments(msg, m.attachments);
      body.appendChild(msg);
    });

    var err = el('div', { class: 'lsm-tw-error' });
    var reply = el('textarea', { rows: '3', placeholder: cfg.i18n.replyPlaceholder });
    var replyFiles = el('input', { type: 'file', multiple: 'multiple', accept: '.png,.jpg,.jpeg,.webp,.gif,.pdf' });
    var send = el('button', { class: 'lsm-tw-btn', text: cfg.i18n.sendReply, onclick: function () {
      if (!reply.value.trim()) return;
      send.disabled = true;
      ajax('lsm_ticket_reply', { id: t.id, message: reply.value }, Array.prototype.slice.call(replyFiles.files, 0, 5))
        .then(function (data) {
          if (data && data.dropped_notice) alert(data.dropped_notice);
          openDetail(t.id);
        })
        .catch(function (e) { err.textContent = e.message; send.disabled = false; });
    } });

    body.appendChild(el('label', { text: cfg.i18n.yourReply }));
    body.appendChild(reply);
    body.appendChild(replyFiles);
    body.appendChild(send);
    body.appendChild(err);
  }

  // ---------- data loading ----------

  function loadList() {
    ajax('lsm_tickets_list', {}).then(function (data) {
      state.tickets = data.tickets || [];
      updateBadge(data.unread || 0);
      render();
    }).catch(function () { render(); });
  }

  function openDetail(id) {
    ajax('lsm_ticket_detail', { id: id }).then(function (ticket) {
      state.ticket = ticket;
      state.tab = 'detail';
      render();
    });
  }

  var badgeEl = null;
  function updateBadge(count) {
    if (!badgeEl) return;
    badgeEl.style.display = count > 0 ? 'flex' : 'none';
    badgeEl.textContent = count;
  }

  // ---------- render ----------

  function render() {
    root.innerHTML = '';

    var fab = el('button', { class: 'lsm-tw-fab', title: cfg.i18n.title, onclick: function () {
      state.open = !state.open;
      if (state.open && state.tab === 'list') loadList();
      render();
    } }, []);
    fab.innerHTML = LSM_FAB_ICON;
    badgeEl = el('span', { class: 'lsm-tw-badge' });
    badgeEl.style.display = 'none';
    fab.appendChild(badgeEl);
    root.appendChild(fab);

    if (!state.open) {
      // keep badge fresh even while closed
      ajax('lsm_tickets_unread', {}).then(function (d) { updateBadge(d.unread || 0); }).catch(function () {});
      return;
    }

    var body = el('div', { class: 'lsm-tw-body' });
    if (state.tab === 'new') viewNewTicket(body);
    else if (state.tab === 'list') viewList(body);
    else viewDetail(body);

    var panel = el('div', { class: 'lsm-tw-panel' }, [
      el('div', { class: 'lsm-tw-header' }, [
        el('strong', { text: cfg.i18n.title }),
        el('button', { text: '✕', onclick: function () { state.open = false; render(); } }),
      ]),
      state.tab !== 'detail' ? el('div', { class: 'lsm-tw-tabs' }, [
        el('button', { class: state.tab === 'new' ? 'active' : '', text: cfg.i18n.newTicket, onclick: function () { state.tab = 'new'; render(); } }),
        el('button', { class: state.tab === 'list' ? 'active' : '', text: cfg.i18n.myTickets, onclick: function () { state.tab = 'list'; loadList(); } }),
      ]) : null,
      body,
    ]);
    root.appendChild(panel);
  }

  render();
})();
