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
    draft: { type: 'bug', subject: '', message: '' }, // survives re-renders (e.g. screenshot capture)
    busy: false,
  };

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

  function captureScreenshot(mode, onDone) {
    state.open = false;
    render(); // hide the panel so it isn't in the shot
    root.style.display = 'none'; // hide FAB too — nothing of the widget in the shot

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

    setTimeout(function () {
      window.html2canvas(document.body, opts)
        .then(function (canvas) { root.style.display = ''; annotate(canvas, onDone); })
        .catch(function () { root.style.display = ''; state.open = true; render(); alert(cfg.i18n.screenshotFailed); });
    }, 250);
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
      } else if (tool === 'pen') {
        ctx.lineTo(p.x, p.y);
        ctx.stroke();
      }
    });
    function stopDrawing() { drawing = false; }
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
        work.toBlob(function (blob) {
          document.removeEventListener('mouseup', stopDrawing);
          document.body.removeChild(overlay);
          state.open = true;
          onDone(blob);
        }, 'image/png');
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

    var typeSel = el('select', { onchange: function () { state.draft.type = typeSel.value; } },
      ['bug', 'content', 'design', 'feature', 'question', 'urgent'].map(function (t) {
        return el('option', { value: t, text: cfg.i18n.types[t] || t });
      }));
    typeSel.value = state.draft.type;
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
      fd.append('issue_type', typeSel.value);
      fd.append('subject', subject.value);
      fd.append('message', message.value);
      fd.append('user_email', cfg.userEmail);
      fd.append('user_name', cfg.userName);
      fd.append('problem_page', cfg.pageUrl);
      fd.append('site_url', cfg.siteUrl);

      var files = Array.prototype.slice.call(fileInput.files, 0, 5);
      if (state.screenshotBlob) {
        files.unshift(new File([state.screenshotBlob], 'page-screenshot.png', { type: 'image/png' }));
      }
      files.slice(0, 5).forEach(function (f) { fd.append('attachments[]', f, f.name); });

      fetch(cfg.ajaxUrl, { method: 'POST', credentials: 'same-origin', body: fd })
        .then(function (r) { return r.json(); })
        .then(function (json) {
          if (!json.success) throw new Error((json.data && json.data.message) || cfg.i18n.genericError);
          state.screenshotBlob = null;
          state.draft = { type: 'bug', subject: '', message: '' };
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
    body.appendChild(typeSel);
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
        .then(function () { openDetail(t.id); })
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
    } }, [document.createTextNode('💬')]);
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
