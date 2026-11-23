/**
 * 5D 分析報告輔助系統 - 核心邏輯
 * 具備：
 * 1. 離線 Word (.doc) 與 PowerPoint (.pptx) 產生引擎
 * 2. 智慧健全度檢核與缺漏提醒引導引擎
 * 3. 5W2H 結構化拆解與動態 5 Why 分析推導鏈
 * 4. 本機 JSON 備份、匯入與範例載入
 * 5. 安全性防護 (escapeHtml) 與防 NPE 健壯性設計
 */

// 安全 HTML 轉義函數 (防止 XSS 威脅)
function escapeHtml(str) {
  if (str === null || str === undefined) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

// 安全檔名過濾函數 (防止路徑穿越與非法作業系統字元)
function sanitizeFilename(str) {
  if (!str || typeof str !== 'string') return 'DRAFT';
  const cleaned = str.replace(/[\/\\:*?"<>|\x00-\x1F]/g, '_').replace(/\.\.+/g, '_').trim();
  return (cleaned || 'DRAFT').slice(0, 60);
}

// 動態推算預設目標完成日 (以基準日往後推算 N 天，採用 UTC 日期避免時區偏移)
function getDefaultTargetDate(baseDateStr, daysOffset = 7) {
  const base = baseDateStr && /^\d{4}-\d{2}-\d{2}$/.test(baseDateStr)
    ? new Date(baseDateStr + 'T00:00:00Z')
    : new Date();
  if (isNaN(base.getTime())) {
    return new Date(Date.now() + daysOffset * 86400000).toISOString().slice(0, 10);
  }
  base.setUTCDate(base.getUTCDate() + daysOffset);
  return base.toISOString().slice(0, 10);
}

// 引用本機離線範例唯一來源 (Single Source of Truth: data/sample-data.js)
const SAMPLE_LIFE_5D = (typeof window !== 'undefined' && window.SAMPLE_LIFE_5D) ? window.SAMPLE_LIFE_5D : {};

// 正規化舊版或外部匯入之欄位值，並執行深度結構防禦校驗 (Deep Schema Sanitization)
function normalizeReportData(raw) {
  const today = new Date().toISOString().slice(0, 10);
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    return getBlankReportData();
  }
  const data = raw;
  const toStr = (v, fallback = '') => (v !== null && v !== undefined && typeof v !== 'object') ? String(v) : fallback;

  data.reportId = toStr(data.reportId, `5D-LIFE-${today.replace(/-/g, '')}-001`);
  data.title = toStr(data.title);
  data.partName = toStr(data.partName);
  data.partNumber = toStr(data.partNumber);
  data.customerLine = toStr(data.customerLine);
  data.lotNumber = toStr(data.lotNumber);
  data.machineNumber = toStr(data.machineNumber, data.partName);
  data.owner = toStr(data.owner);
  data.approver = toStr(data.approver);
  data.dateCreated = toStr(data.dateCreated, today);
  data.targetCloseDate = toStr(data.targetCloseDate, getDefaultTargetDate(data.dateCreated, 7));

  // 正規化嚴重等級 (severity)
  const sevMap = {
    'Critical': '極重大事件（人身受傷、重大物品損壞）',
    '極重大事件': '極重大事件（人身受傷、重大物品損壞）',
    'Major': '重大影響（違反約定、擅自拿取或信任破壞）',
    '重大影響': '重大影響（違反約定、擅自拿取或信任破壞）',
    '重要生活約定': '重大影響（違反約定、擅自拿取或信任破壞）',
    'Minor': '一般提醒（言語口角、小摩擦或粗心遺忘）',
    '一般提醒': '一般提醒（言語口角、小摩擦或粗心遺忘）'
  };
  if (data.severity && sevMap[data.severity]) {
    data.severity = sevMap[data.severity];
  } else if (!data.severity || typeof data.severity !== 'string') {
    data.severity = '重大影響（違反約定、擅自拿取或信任破壞）';
  }

  // D1 結構校驗
  if (!data.d1 || typeof data.d1 !== 'object' || Array.isArray(data.d1)) data.d1 = {};
  const d1Keys = ['problemDesc', 'who', 'when', 'where', 'what', 'why', 'how', 'howMany', 'defectRate', 'impactScope'];
  d1Keys.forEach(k => { data.d1[k] = toStr(data.d1[k]); });

  if (data.d1.when && !data.lotNumber) data.lotNumber = data.d1.when;
  if (data.lotNumber && !data.d1.when) data.d1.when = data.lotNumber;
  if (data.d1.where && !data.customerLine) data.customerLine = data.d1.where;
  if (data.customerLine && !data.d1.where) data.d1.where = data.customerLine;

  // D2 結構校驗
  if (!data.d2 || typeof data.d2 !== 'object' || Array.isArray(data.d2)) data.d2 = {};
  data.d2.factoryStock = toStr(data.d2.factoryStock);
  data.d2.transitStock = toStr(data.d2.transitStock);
  data.d2.customerStock = toStr(data.d2.customerStock);
  data.d2.containmentVerification = toStr(data.d2.containmentVerification);
  data.d2.containmentActions = Array.isArray(data.d2.containmentActions)
    ? data.d2.containmentActions.filter(a => a && typeof a === 'object').map(a => ({
        action: toStr(a.action),
        owner: toStr(a.owner),
        dueDate: toStr(a.dueDate),
        status: toStr(a.status, '進行中'),
        result: toStr(a.result)
      }))
    : [];

  // D3 結構校驗
  if (!data.d3 || typeof data.d3 !== 'object' || Array.isArray(data.d3)) data.d3 = {};
  data.d3.rootCauseSummary = toStr(data.d3.rootCauseSummary);
  data.d3.whyMadeChain = Array.isArray(data.d3.whyMadeChain)
    ? data.d3.whyMadeChain.filter(w => w && typeof w === 'object').map((w, i) => ({
        level: toStr(w.level, `Why ${i + 1}`),
        question: toStr(w.question),
        answer: toStr(w.answer)
      }))
    : [];
  data.d3.whyEscapedChain = Array.isArray(data.d3.whyEscapedChain)
    ? data.d3.whyEscapedChain.filter(w => w && typeof w === 'object').map((w, i) => ({
        level: toStr(w.level, `Why ${i + 1}`),
        question: toStr(w.question),
        answer: toStr(w.answer)
      }))
    : [];

  // D4 結構校驗
  if (!data.d4 || typeof data.d4 !== 'object' || Array.isArray(data.d4)) data.d4 = {};
  data.d4.beforeMetric = toStr(data.d4.beforeMetric);
  data.d4.afterMetric = toStr(data.d4.afterMetric);
  data.d4.validationConclusion = toStr(data.d4.validationConclusion);
  data.d4.correctiveActions = Array.isArray(data.d4.correctiveActions)
    ? data.d4.correctiveActions.filter(c => c && typeof c === 'object').map(c => ({
        action: toStr(c.action),
        category: toStr(c.category, '誠意致歉與態度'),
        owner: toStr(c.owner),
        dueDate: toStr(c.dueDate),
        status: toStr(c.status, '規劃中'),
        verification: toStr(c.verification)
      }))
    : [];

  // D5 結構校驗與正規化結案狀態
  if (!data.d5 || typeof data.d5 !== 'object' || Array.isArray(data.d5)) data.d5 = {};
  data.d5.standardDocs = Array.isArray(data.d5.standardDocs)
    ? data.d5.standardDocs.filter(d => d && typeof d === 'object').map(d => ({
        docType: toStr(d.docType, '生活公約 / 家規'),
        docNumber: toStr(d.docNumber),
        docName: toStr(d.docName),
        revDate: toStr(d.revDate, data.dateCreated),
        owner: toStr(d.owner)
      }))
    : [];
  data.d5.horizontalDeployment = Array.isArray(data.d5.horizontalDeployment)
    ? data.d5.horizontalDeployment.filter(h => h && typeof h === 'object').map(h => ({
        target: toStr(h.target),
        action: toStr(h.action),
        dueDate: toStr(h.dueDate),
        status: toStr(h.status, '評估中'),
        owner: toStr(h.owner)
      }))
    : [];

  if (!data.d5.signOff || typeof data.d5.signOff !== 'object' || Array.isArray(data.d5.signOff)) {
    data.d5.signOff = {};
  }
  data.d5.signOff.qaComment = toStr(data.d5.signOff.qaComment);

  const statusMap = {
    '審查中（In Review）': '觀察改善中',
    '審查中': '觀察改善中',
    '待補充改善中': '觀察改善中',
    '同意結案（Closed）': '同意圓滿結案',
    '同意圓滿結案（Closed）': '同意圓滿結案',
    '退回補充對策（Rejected）': '還沒做好，需再加強'
  };
  const curStatus = data.d5.signOff.qaStatus;
  if (curStatus && statusMap[curStatus]) {
    data.d5.signOff.qaStatus = statusMap[curStatus];
  } else if (!curStatus || typeof curStatus !== 'string') {
    data.d5.signOff.qaStatus = '觀察改善中';
  }

  data.d5.signOff.signDate = toStr(data.d5.signOff.signDate, data.dateCreated || today);

  return data;
}

let reportData = {
  reportId: '5D-LIFE-' + new Date().toISOString().slice(0, 10).replace(/-/g, '') + '-001',
  title: '',
  partName: '',
  partNumber: '',
  customerLine: '',
  lotNumber: '',
  machineNumber: '',
  severity: '重大影響（違反約定、擅自拿取或信任破壞）',
  owner: '',
  approver: '',
  dateCreated: new Date().toISOString().slice(0, 10),
  targetCloseDate: '',
  d1: {
    problemDesc: '',
    who: '',
    when: '',
    where: '',
    what: '',
    why: '',
    how: '',
    howMany: '',
    defectRate: '',
    impactScope: ''
  },
  d2: {
    factoryStock: '',
    transitStock: '',
    customerStock: '',
    containmentActions: [],
    containmentVerification: ''
  },
  d3: {
    whyMadeChain: [],
    whyEscapedChain: [],
    rootCauseSummary: ''
  },
  d4: {
    correctiveActions: [],
    beforeMetric: '',
    afterMetric: '',
    validationConclusion: ''
  },
  d5: {
    standardDocs: [],
    horizontalDeployment: [],
    signOff: {
      qaComment: '',
      qaStatus: '觀察改善中',
      signDate: new Date().toISOString().slice(0, 10)
    }
  }
};

// 提示訊息顯示器 (Toast)
function showToast(message, type = 'info') {
  const container = document.getElementById('toast-container');
  if (!container) return;

  const toast = document.createElement('div');
  toast.className = `toast ${type}`;
  toast.textContent = message;
  container.appendChild(toast);

  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transform = 'translateY(10px)';
    setTimeout(() => {
      if (toast.parentNode) {
        toast.parentNode.removeChild(toast);
      }
    }, 200);
  }, 3000);
}

// 初始化與 DOM 綁定
document.addEventListener('DOMContentLoaded', () => {
  initTabs();
  initFormBindings();
  initDynamicTables();
  initActionButtons();
  initSmartInput();

  // 檢查是否有本機自動暫存；若無，則載入生活實例作為初次引導
  const savedDraft = localStorage.getItem('5D_REPORT_AUTOSAVE');
  if (savedDraft) {
    try {
      reportData = normalizeReportData(JSON.parse(savedDraft));
      populateFormFromData();
      renderAllDynamicFields();
      renderLivePreview();
      updateAuditAndScore();
      generateClarificationQuestions();
    } catch (e) {
      loadLifeDemoData();
    }
  } else {
    loadLifeDemoData();
  }
});

// 分頁切換 (Tabs)
function initTabs() {
  const tabBtns = document.querySelectorAll('.tab-btn');
  tabBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      const targetTab = btn.getAttribute('data-tab');
      switchToTab(targetTab);
    });
  });
}

function switchToTab(tabId) {
  const tabBtns = document.querySelectorAll('.tab-btn');
  const tabPanels = document.querySelectorAll('.tab-panel');

  tabBtns.forEach(b => {
    if (b.getAttribute('data-tab') === tabId) {
      b.classList.add('active');
    } else {
      b.classList.remove('active');
    }
  });

  tabPanels.forEach(p => {
    if (p.id === tabId) {
      p.classList.add('active');
    } else {
      p.classList.remove('active');
    }
  });

  if (tabId === 'tab-preview') {
    renderLivePreview();
  } else if (tabId === 'tab-smart-input') {
    generateClarificationQuestions();
  }
}

// 表單輸入資料即時雙向綁定
function initFormBindings() {
  const syncMap = [
    { id: 'reportId', path: 'reportId' },
    { id: 'title', path: 'title' },
    { id: 'partName', path: 'partName' },
    { id: 'partNumber', path: 'partNumber' },
    { id: 'customerLine', path: 'customerLine' },
    { id: 'lotNumber', path: 'lotNumber' },
    { id: 'machineNumber', path: 'machineNumber' },
    { id: 'severity', path: 'severity' },
    { id: 'owner', path: 'owner' },
    { id: 'approver', path: 'approver' },
    { id: 'dateCreated', path: 'dateCreated' },
    { id: 'targetCloseDate', path: 'targetCloseDate' },

    // D1
    { id: 'd1-problemDesc', path: 'd1.problemDesc' },
    { id: 'd1-who', path: 'd1.who' },
    { id: 'd1-when', path: 'd1.when' },
    { id: 'd1-where', path: 'd1.where' },
    { id: 'd1-what', path: 'd1.what' },
    { id: 'd1-why', path: 'd1.why' },
    { id: 'd1-how', path: 'd1.how' },
    { id: 'd1-howMany', path: 'd1.howMany' },
    { id: 'd1-defectRate', path: 'd1.defectRate' },
    { id: 'd1-impactScope', path: 'd1.impactScope' },

    // D2
    { id: 'd2-factoryStock', path: 'd2.factoryStock' },
    { id: 'd2-transitStock', path: 'd2.transitStock' },
    { id: 'd2-customerStock', path: 'd2.customerStock' },
    { id: 'd2-containmentVerification', path: 'd2.containmentVerification' },

    // D3
    { id: 'd3-rootCauseSummary', path: 'd3.rootCauseSummary' },

    // D4
    { id: 'd4-beforeMetric', path: 'd4.beforeMetric' },
    { id: 'd4-afterMetric', path: 'd4.afterMetric' },
    { id: 'd4-validationConclusion', path: 'd4.validationConclusion' },

    // D5
    { id: 'd5-qaComment', path: 'd5.signOff.qaComment' },
    { id: 'd5-qaStatus', path: 'd5.signOff.qaStatus' },
    { id: 'd5-signDate', path: 'd5.signOff.signDate' }
  ];

  syncMap.forEach(item => {
    const el = document.getElementById(item.id);
    if (el) {
      el.addEventListener('input', () => {
        setNestedValue(reportData, item.path, el.value);

        // 雙向同步基本資料與 D1 之時間 (lotNumber <-> d1.when)、地點 (customerLine <-> d1.where) 與物品 (partName <-> machineNumber)
        if (item.id === 'lotNumber') {
          reportData.d1.when = el.value;
          const d1WhenEl = document.getElementById('d1-when');
          if (d1WhenEl) d1WhenEl.value = el.value;
        } else if (item.id === 'd1-when') {
          reportData.lotNumber = el.value;
          const lotEl = document.getElementById('lotNumber');
          if (lotEl) lotEl.value = el.value;
        } else if (item.id === 'customerLine') {
          reportData.d1.where = el.value;
          const d1WhereEl = document.getElementById('d1-where');
          if (d1WhereEl) d1WhereEl.value = el.value;
        } else if (item.id === 'd1-where') {
          reportData.customerLine = el.value;
          const custEl = document.getElementById('customerLine');
          if (custEl) custEl.value = el.value;
        } else if (item.id === 'partName') {
          reportData.machineNumber = el.value;
          const machEl = document.getElementById('machineNumber');
          if (machEl) machEl.value = el.value;
        }

        saveAutoDraft();
        updateAuditAndScore();
        generateClarificationQuestions();
      });
    }
  });
}

// 危險原型鏈屬性黑名單 (防止 Prototype Pollution 攻擊)
const FORBIDDEN_PROTO_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

function setNestedValue(obj, path, value) {
  if (!obj || typeof path !== 'string') return;
  const parts = path.split('.');
  if (parts.some(p => FORBIDDEN_PROTO_KEYS.has(p))) return;

  let current = obj;
  for (let i = 0; i < parts.length - 1; i++) {
    const key = parts[i];
    if (!Object.prototype.hasOwnProperty.call(current, key) || typeof current[key] !== 'object' || current[key] === null) {
      current[key] = {};
    }
    current = current[key];
  }
  current[parts[parts.length - 1]] = value;
}

function getNestedValue(obj, path) {
  if (!obj || typeof path !== 'string') return '';
  const parts = path.split('.');
  if (parts.some(p => FORBIDDEN_PROTO_KEYS.has(p))) return '';

  let current = obj;
  for (let i = 0; i < parts.length; i++) {
    if (current === undefined || current === null || !Object.prototype.hasOwnProperty.call(current, parts[i])) return '';
    current = current[parts[i]];
  }
  return current !== undefined && current !== null ? current : '';
}

function saveAutoDraft() {
  try {
    localStorage.setItem('5D_REPORT_AUTOSAVE', JSON.stringify(reportData));
  } catch (e) {
    // 忽略本機容量配額異常
  }
}

// 根據 reportData 填充所有表單輸入
function populateFormFromData() {
  const inputs = document.querySelectorAll('[data-bind]');
  inputs.forEach(input => {
    const path = input.getAttribute('data-bind');
    const val = getNestedValue(reportData, path);
    if (input.type === 'select-one' || input.tagName === 'SELECT') {
      input.value = val || input.options[0].value;
    } else {
      input.value = val || '';
    }
  });
}

// ==========================================================================
// 動態表格與列表管理 (D2, D3, D4, D5)
// ==========================================================================
function initDynamicTables() {
  // D2: 新增圍堵措施
  const btnAddD2 = document.getElementById('btn-add-d2-action');
  if (btnAddD2) {
    btnAddD2.addEventListener('click', () => {
      reportData.d2.containmentActions.push({
        action: '',
        owner: '',
        dueDate: '',
        status: '進行中',
        result: ''
      });
      renderD2Actions();
      updateAuditAndScore();
      generateClarificationQuestions();
      saveAutoDraft();
    });
  }

  // D3: 新增發生原因 Why
  const btnAddWhyMade = document.getElementById('btn-add-why-made');
  if (btnAddWhyMade) {
    btnAddWhyMade.addEventListener('click', () => {
      const nextLevel = reportData.d3.whyMadeChain.length + 1;
      reportData.d3.whyMadeChain.push({
        level: `Why ${nextLevel}`,
        question: '',
        answer: ''
      });
      renderWhyChains();
      updateAuditAndScore();
      generateClarificationQuestions();
      saveAutoDraft();
    });
  }

  // D3: 新增流出原因 Why
  const btnAddWhyEscaped = document.getElementById('btn-add-why-escaped');
  if (btnAddWhyEscaped) {
    btnAddWhyEscaped.addEventListener('click', () => {
      const nextLevel = reportData.d3.whyEscapedChain.length + 1;
      reportData.d3.whyEscapedChain.push({
        level: `Why ${nextLevel}`,
        question: '',
        answer: ''
      });
      renderWhyChains();
      updateAuditAndScore();
      generateClarificationQuestions();
      saveAutoDraft();
    });
  }

  // D4: 新增永久對策
  const btnAddD4 = document.getElementById('btn-add-d4-action');
  if (btnAddD4) {
    btnAddD4.addEventListener('click', () => {
      reportData.d4.correctiveActions.push({
        action: '',
        category: '誠意致歉與態度',
        owner: '',
        dueDate: '',
        status: '規劃中',
        verification: ''
      });
      renderD4Actions();
      updateAuditAndScore();
      generateClarificationQuestions();
      saveAutoDraft();
    });
  }

  // D5: 新增生活約定
  const btnAddD5Doc = document.getElementById('btn-add-d5-doc');
  if (btnAddD5Doc) {
    btnAddD5Doc.addEventListener('click', () => {
      reportData.d5.standardDocs.push({
        docType: '生活公約 / 家規',
        docNumber: '',
        docName: '',
        revDate: new Date().toISOString().slice(0, 10),
        owner: ''
      });
      renderD5Docs();
      updateAuditAndScore();
      generateClarificationQuestions();
      saveAutoDraft();
    });
  }

  // D5: 新增橫向展開
  const btnAddD5H = document.getElementById('btn-add-d5-horizontal');
  if (btnAddD5H) {
    btnAddD5H.addEventListener('click', () => {
      reportData.d5.horizontalDeployment.push({
        target: '',
        action: '',
        dueDate: '',
        status: '評估中',
        owner: ''
      });
      renderD5Horizontal();
      updateAuditAndScore();
      generateClarificationQuestions();
      saveAutoDraft();
    });
  }
}

function renderAllDynamicFields() {
  renderD2Actions();
  renderWhyChains();
  renderD4Actions();
  renderD5Docs();
  renderD5Horizontal();
}

// 渲染 D2 緊急行動表格
function renderD2Actions() {
  const tbody = document.getElementById('d2-actions-tbody');
  if (!tbody) return;

  if (reportData.d2.containmentActions.length === 0) {
    tbody.innerHTML = `<tr><td colspan="6" style="text-align:center; color:#94a3b8; padding:16px;">尚無緊急行動項目，請點擊右上方「+ 新增緊急行動」建立清單。</td></tr>`;
    return;
  }

  tbody.innerHTML = reportData.d2.containmentActions.map((item, idx) => `
    <tr>
      <td>
        <input type="text" class="form-control d2-act-input" data-idx="${idx}" data-field="action" value="${escapeHtml(item.action)}" placeholder="處置作為說明">
      </td>
      <td style="width: 120px;">
        <input type="text" class="form-control d2-act-input" data-idx="${idx}" data-field="owner" value="${escapeHtml(item.owner)}" placeholder="誰負責">
      </td>
      <td style="width: 140px;">
        <input type="date" class="form-control d2-act-input" data-idx="${idx}" data-field="dueDate" value="${escapeHtml(item.dueDate)}">
      </td>
      <td style="width: 120px;">
        <select class="form-control d2-act-input" data-idx="${idx}" data-field="status">
          <option value="進行中" ${item.status === '進行中' ? 'selected' : ''}>進行中</option>
          <option value="已完成" ${item.status === '已完成' ? 'selected' : ''}>已完成</option>
          <option value="已取消" ${item.status === '已取消' ? 'selected' : ''}>已取消</option>
        </select>
      </td>
      <td>
        <input type="text" class="form-control d2-act-input" data-idx="${idx}" data-field="result" value="${escapeHtml(item.result)}" placeholder="處置結果確認">
      </td>
      <td style="width: 60px; text-align: center;">
        <button class="btn btn-danger btn-sm btn-del-d2" data-idx="${idx}">刪除</button>
      </td>
    </tr>
  `).join('');

  tbody.querySelectorAll('.d2-act-input').forEach(el => {
    el.addEventListener('input', e => {
      const idx = e.target.getAttribute('data-idx');
      const field = e.target.getAttribute('data-field');
      reportData.d2.containmentActions[idx][field] = e.target.value;
      saveAutoDraft();
      updateAuditAndScore();
      generateClarificationQuestions();
    });
  });

  tbody.querySelectorAll('.btn-del-d2').forEach(btn => {
    btn.addEventListener('click', e => {
      const idx = e.target.getAttribute('data-idx');
      reportData.d2.containmentActions.splice(idx, 1);
      renderD2Actions();
      updateAuditAndScore();
      generateClarificationQuestions();
      saveAutoDraft();
    });
  });
}

// 渲染 D3 5 Why 推導鏈
function renderWhyChains() {
  const containerMade = document.getElementById('why-made-chain');
  const containerEscaped = document.getElementById('why-escaped-chain');

  // 1. 發生原因 Why 鏈
  if (containerMade) {
    if (reportData.d3.whyMadeChain.length === 0) {
      containerMade.innerHTML = `<div style="color:#94a3b8; font-size:12px; padding:12px; text-align:center; border:1px dashed #cbd5e1; border-radius:4px;">尚無動機原因推導項目，請點擊右上方「+ 多問一層為什麼」開始思考。</div>`;
    } else {
      containerMade.innerHTML = reportData.d3.whyMadeChain.map((item, idx) => `
        <div class="why-card">
          <div class="why-header">
            <span class="why-badge">${escapeHtml(item.level || `Why ${idx + 1}`)}</span>
            <button class="btn btn-danger btn-sm btn-del-why-made" data-idx="${idx}">刪除</button>
          </div>
          <div class="form-group" style="margin-bottom:8px;">
            <input type="text" class="form-control why-made-input" data-idx="${idx}" data-field="question" value="${escapeHtml(item.question)}" placeholder="提問（例如：為什麼當初會想要做這件事？）">
          </div>
          <div class="form-group" style="margin-bottom:0;">
            <input type="text" class="form-control why-made-input" data-idx="${idx}" data-field="answer" value="${escapeHtml(item.answer)}" placeholder="回答心裡的真實想法（例如：因為短影音與遊戲太吸引人，心想再看五分鐘就好）">
          </div>
        </div>
        ${idx < reportData.d3.whyMadeChain.length - 1 ? '<div class="why-arrow">↓ 繼續往下追問為什麼</div>' : ''}
      `).join('');

      containerMade.querySelectorAll('.why-made-input').forEach(el => {
        el.addEventListener('input', e => {
          const idx = e.target.getAttribute('data-idx');
          const field = e.target.getAttribute('data-field');
          reportData.d3.whyMadeChain[idx][field] = e.target.value;
          saveAutoDraft();
          updateAuditAndScore();
          generateClarificationQuestions();
        });
      });

      containerMade.querySelectorAll('.btn-del-why-made').forEach(btn => {
        btn.addEventListener('click', e => {
          const idx = e.target.getAttribute('data-idx');
          reportData.d3.whyMadeChain.splice(idx, 1);
          renderWhyChains();
          updateAuditAndScore();
          generateClarificationQuestions();
          saveAutoDraft();
        });
      });
    }
  }

  // 2. 流出原因 Why 鏈
  if (containerEscaped) {
    if (reportData.d3.whyEscapedChain.length === 0) {
      containerEscaped.innerHTML = `<div style="color:#94a3b8; font-size:12px; padding:12px; text-align:center; border:1px dashed #cbd5e1; border-radius:4px;">尚無把關機制推導項目，請點擊右上方「+ 多問一層為什麼」找出環境或規矩的漏洞。</div>`;
    } else {
      containerEscaped.innerHTML = reportData.d3.whyEscapedChain.map((item, idx) => `
        <div class="why-card">
          <div class="why-header">
            <span class="why-badge">${escapeHtml(item.level || `Why ${idx + 1}`)}</span>
            <button class="btn btn-danger btn-sm btn-del-why-escaped" data-idx="${idx}">刪除</button>
          </div>
          <div class="form-group" style="margin-bottom:8px;">
            <input type="text" class="form-control why-escaped-input" data-idx="${idx}" data-field="question" value="${escapeHtml(item.question)}" placeholder="提問（例如：為什麼當時沒有人發現或及時提醒阻止？）">
          </div>
          <div class="form-group" style="margin-bottom:0;">
            <input type="text" class="form-control why-escaped-input" data-idx="${idx}" data-field="answer" value="${escapeHtml(item.answer)}" placeholder="回答環境或規矩上的漏洞（例如：睡前沒有把手機放到客廳充電，也沒有設定提醒鬧鐘）">
          </div>
        </div>
        ${idx < reportData.d3.whyEscapedChain.length - 1 ? '<div class="why-arrow">↓ 繼續追問環境與規矩漏洞</div>' : ''}
      `).join('');

      containerEscaped.querySelectorAll('.why-escaped-input').forEach(el => {
        el.addEventListener('input', e => {
          const idx = e.target.getAttribute('data-idx');
          const field = e.target.getAttribute('data-field');
          reportData.d3.whyEscapedChain[idx][field] = e.target.value;
          saveAutoDraft();
          updateAuditAndScore();
          generateClarificationQuestions();
        });
      });

      containerEscaped.querySelectorAll('.btn-del-why-escaped').forEach(btn => {
        btn.addEventListener('click', e => {
          const idx = e.target.getAttribute('data-idx');
          reportData.d3.whyEscapedChain.splice(idx, 1);
          renderWhyChains();
          updateAuditAndScore();
          generateClarificationQuestions();
          saveAutoDraft();
        });
      });
    }
  }
}

// 渲染 D4 改善行動表格
function renderD4Actions() {
  const tbody = document.getElementById('d4-actions-tbody');
  if (!tbody) return;

  if (reportData.d4.correctiveActions.length === 0) {
    tbody.innerHTML = `<tr><td colspan="7" style="text-align:center; color:#94a3b8; padding:16px;">尚無改善行動，請點擊右上方「+ 新增改善行動」進行規劃。</td></tr>`;
    return;
  }

  tbody.innerHTML = reportData.d4.correctiveActions.map((item, idx) => `
    <tr>
      <td>
        <input type="text" class="form-control d4-act-input" data-idx="${idx}" data-field="action" value="${escapeHtml(item.action)}" placeholder="改善與道歉具體作法">
      </td>
      <td style="width: 130px;">
        <select class="form-control d4-act-input" data-idx="${idx}" data-field="category">
          <option value="誠意致歉與態度" ${item.category === '誠意致歉與態度' ? 'selected' : ''}>誠意致歉與態度</option>
          <option value="實質補償與收拾" ${item.category === '實質補償與收拾' ? 'selected' : ''}>實質補償與收拾</option>
          <option value="想法與習慣調整" ${item.category === '想法與習慣調整' ? 'selected' : ''}>想法與習慣調整</option>
          <option value="環境提醒與互助" ${item.category === '環境提醒與互助' ? 'selected' : ''}>環境提醒與互助</option>
        </select>
      </td>
      <td style="width: 120px;">
        <input type="text" class="form-control d4-act-input" data-idx="${idx}" data-field="owner" value="${escapeHtml(item.owner)}" placeholder="誰去做">
      </td>
      <td style="width: 130px;">
        <input type="date" class="form-control d4-act-input" data-idx="${idx}" data-field="dueDate" value="${escapeHtml(item.dueDate)}">
      </td>
      <td style="width: 110px;">
        <select class="form-control d4-act-input" data-idx="${idx}" data-field="status">
          <option value="規劃中" ${item.status === '規劃中' ? 'selected' : ''}>規劃中</option>
          <option value="進行中" ${item.status === '進行中' ? 'selected' : ''}>進行中</option>
          <option value="已完成" ${item.status === '已完成' ? 'selected' : ''}>已完成</option>
        </select>
      </td>
      <td>
        <input type="text" class="form-control d4-act-input" data-idx="${idx}" data-field="verification" value="${escapeHtml(item.verification)}" placeholder="執行成效驗證結論">
      </td>
      <td style="width: 60px; text-align: center;">
        <button class="btn btn-danger btn-sm btn-del-d4" data-idx="${idx}">刪除</button>
      </td>
    </tr>
  `).join('');

  tbody.querySelectorAll('.d4-act-input').forEach(el => {
    el.addEventListener('input', e => {
      const idx = e.target.getAttribute('data-idx');
      const field = e.target.getAttribute('data-field');
      reportData.d4.correctiveActions[idx][field] = e.target.value;
      saveAutoDraft();
      updateAuditAndScore();
      generateClarificationQuestions();
    });
  });

  tbody.querySelectorAll('.btn-del-d4').forEach(btn => {
    btn.addEventListener('click', e => {
      const idx = e.target.getAttribute('data-idx');
      reportData.d4.correctiveActions.splice(idx, 1);
      renderD4Actions();
      updateAuditAndScore();
      generateClarificationQuestions();
      saveAutoDraft();
    });
  });
}

// 渲染 D5 生活公約表格
function renderD5Docs() {
  const tbody = document.getElementById('d5-docs-tbody');
  if (!tbody) return;

  if (reportData.d5.standardDocs.length === 0) {
    tbody.innerHTML = `<tr><td colspan="6" style="text-align:center; color:#94a3b8; padding:16px;">尚無生活約定，請點擊右上方「+ 新增生活約定」訂下共同守則。</td></tr>`;
    return;
  }

  tbody.innerHTML = reportData.d5.standardDocs.map((item, idx) => `
    <tr>
      <td style="width: 170px;">
        <select class="form-control d5-doc-input" data-idx="${idx}" data-field="docType">
          <option value="生活公約 / 家規" ${item.docType === '生活公約 / 家規' ? 'selected' : ''}>生活公約 / 家規</option>
          <option value="日常自我檢查表" ${item.docType === '日常自我檢查表' ? 'selected' : ''}>日常自我檢查表</option>
          <option value="雙方承諾卡" ${item.docType === '雙方承諾卡' ? 'selected' : ''}>雙方承諾卡</option>
          <option value="備忘與標籤提醒" ${item.docType === '備忘與標籤提醒' ? 'selected' : ''}>備忘與標籤提醒</option>
        </select>
      </td>
      <td style="width: 160px;">
        <input type="text" class="form-control d5-doc-input" data-idx="${idx}" data-field="docNumber" value="${escapeHtml(item.docNumber)}" placeholder="例如：RULE-HOME-001 或 班級公約-01">
      </td>
      <td>
        <input type="text" class="form-control d5-doc-input" data-idx="${idx}" data-field="docName" value="${escapeHtml(item.docName)}" placeholder="約定完整名稱與內容">
      </td>
      <td style="width: 140px;">
        <input type="date" class="form-control d5-doc-input" data-idx="${idx}" data-field="revDate" value="${escapeHtml(item.revDate)}">
      </td>
      <td style="width: 110px;">
        <input type="text" class="form-control d5-doc-input" data-idx="${idx}" data-field="owner" value="${escapeHtml(item.owner)}" placeholder="提醒人">
      </td>
      <td style="width: 60px; text-align: center;">
        <button class="btn btn-danger btn-sm btn-del-d5-doc" data-idx="${idx}">刪除</button>
      </td>
    </tr>
  `).join('');

  tbody.querySelectorAll('.d5-doc-input').forEach(el => {
    el.addEventListener('input', e => {
      const idx = e.target.getAttribute('data-idx');
      const field = e.target.getAttribute('data-field');
      reportData.d5.standardDocs[idx][field] = e.target.value;
      saveAutoDraft();
      updateAuditAndScore();
      generateClarificationQuestions();
    });
  });

  tbody.querySelectorAll('.btn-del-d5-doc').forEach(btn => {
    btn.addEventListener('click', e => {
      const idx = e.target.getAttribute('data-idx');
      reportData.d5.standardDocs.splice(idx, 1);
      renderD5Docs();
      updateAuditAndScore();
      generateClarificationQuestions();
      saveAutoDraft();
    });
  });
}

// 渲染 D5 互相提醒與注意項目表格
function renderD5Horizontal() {
  const tbody = document.getElementById('d5-horizontal-tbody');
  if (!tbody) return;

  if (reportData.d5.horizontalDeployment.length === 0) {
    tbody.innerHTML = `<tr><td colspan="6" style="text-align:center; color:#94a3b8; padding:16px;">尚無互相提醒項目，請點擊右上方「+ 新增注意項目」防範其他同類問題。</td></tr>`;
    return;
  }

  tbody.innerHTML = reportData.d5.horizontalDeployment.map((item, idx) => `
    <tr>
      <td>
        <input type="text" class="form-control d5-h-input" data-idx="${idx}" data-field="target" value="${escapeHtml(item.target)}" placeholder="共同遵守與提醒對象（例如：家中其他私人物品、同學的文具）">
      </td>
      <td>
        <input type="text" class="form-control d5-h-input" data-idx="${idx}" data-field="action" value="${escapeHtml(item.action)}" placeholder="大家講好的做法">
      </td>
      <td style="width: 140px;">
        <input type="date" class="form-control d5-h-input" data-idx="${idx}" data-field="dueDate" value="${escapeHtml(item.dueDate)}">
      </td>
      <td style="width: 110px;">
        <select class="form-control d5-h-input" data-idx="${idx}" data-field="status">
          <option value="評估中" ${item.status === '評估中' ? 'selected' : ''}>評估中</option>
          <option value="進行中" ${item.status === '進行中' ? 'selected' : ''}>進行中</option>
          <option value="已完成" ${item.status === '已完成' ? 'selected' : ''}>已完成</option>
        </select>
      </td>
      <td style="width: 110px;">
        <input type="text" class="form-control d5-h-input" data-idx="${idx}" data-field="owner" value="${escapeHtml(item.owner)}" placeholder="負責人">
      </td>
      <td style="width: 60px; text-align: center;">
        <button class="btn btn-danger btn-sm btn-del-d5-h" data-idx="${idx}">刪除</button>
      </td>
    </tr>
  `).join('');

  tbody.querySelectorAll('.d5-h-input').forEach(el => {
    el.addEventListener('input', e => {
      const idx = e.target.getAttribute('data-idx');
      const field = e.target.getAttribute('data-field');
      reportData.d5.horizontalDeployment[idx][field] = e.target.value;
      saveAutoDraft();
      updateAuditAndScore();
      generateClarificationQuestions();
    });
  });

  tbody.querySelectorAll('.btn-del-d5-h').forEach(btn => {
    btn.addEventListener('click', e => {
      const idx = e.target.getAttribute('data-idx');
      reportData.d5.horizontalDeployment.splice(idx, 1);
      renderD5Horizontal();
      updateAuditAndScore();
      generateClarificationQuestions();
      saveAutoDraft();
    });
  });
}

// ==========================================================================
// 智慧健全度檢核與缺漏提醒引導引擎 (Audit & Guidance Engine)
// ==========================================================================
function updateAuditAndScore() {
  const reminders = [];
  let score = 0;

  // 1. D1 問題定義與核心事實檢核 (權重 35 分)
  if (reportData.title && reportData.title.trim().length > 2) score += 5;
  else reminders.push({ level: 'danger', tab: 'tab-d1', focus: 'title', title: '標題還沒寫清楚', desc: '請幫這件事情取一個清楚明白的名稱。' });

  if (reportData.d1.problemDesc && reportData.d1.problemDesc.trim().length > 8) score += 10;
  else reminders.push({ level: 'danger', tab: 'tab-d1', focus: 'd1-problemDesc', title: '第一步：事情經過寫得太簡短', desc: '請多寫幾句把事實經過交代清楚。' });

  const coreD1Fields = ['who', 'when', 'where', 'why', 'how', 'impactScope'];
  const filledCore = coreD1Fields.filter(k => reportData.d1[k] && reportData.d1[k].trim().length > 0);
  score += Math.round((filledCore.length / coreD1Fields.length) * 20);
  if (filledCore.length < coreD1Fields.length) {
    const missing = coreD1Fields.filter(k => !reportData.d1[k] || !reportData.d1[k].trim());
    reminders.push({
      level: 'warning',
      tab: 'tab-d1',
      focus: 'd1-' + missing[0],
      title: '第一步：人事時地物細節待補齊',
      desc: `還有 ${missing.length} 項細節尚未補充。`
    });
  }

  // 2. D2 當下緊急處置檢核 (權重 20 分，須至少有一項非空白之實際處置內容)
  const hasValidD2 = Array.isArray(reportData.d2.containmentActions) &&
    reportData.d2.containmentActions.some(a => a && a.action && a.action.trim().length > 0);
  if (hasValidD2) {
    score += 15;
  } else {
    reminders.push({ level: 'danger', tab: 'tab-d2', focus: 'btn-add-d2-action', title: '第二步：當下緊急處置尚未填寫', desc: '請至少寫一項當下立刻做的處理。' });
  }
  if (reportData.d2.containmentVerification && reportData.d2.containmentVerification.trim().length > 2) {
    score += 5;
  }

  // 3. D3 根本原因分析檢核 (權重 15 分，須至少有一層非空白之原因或提問)
  const hasValidD3 = Array.isArray(reportData.d3.whyMadeChain) &&
    reportData.d3.whyMadeChain.some(w => w && ((w.answer && w.answer.trim().length > 0) || (w.question && w.question.trim().length > 0)));
  if (hasValidD3) {
    score += 8;
  } else {
    reminders.push({ level: 'danger', tab: 'tab-d3', focus: 'btn-add-why-made', title: '第三步：尚未追問為什麼', desc: '請一步步找出心裡為什麼會想這麼做。' });
  }
  if (reportData.d3.rootCauseSummary && reportData.d3.rootCauseSummary.trim().length > 4) {
    score += 7;
  }

  // 4. D4 未來改善行動檢核 (權重 15 分，須至少有一項非空白之改善作法)
  const hasValidD4 = Array.isArray(reportData.d4.correctiveActions) &&
    reportData.d4.correctiveActions.some(c => c && c.action && c.action.trim().length > 0);
  if (hasValidD4) {
    score += 10;
  } else {
    reminders.push({ level: 'danger', tab: 'tab-d4', focus: 'btn-add-d4-action', title: '第四步：改善與補償行動空白', desc: '請提出道歉、補償行動或生活習慣改進。' });
  }
  if ((reportData.d4.validationConclusion && reportData.d4.validationConclusion.trim()) || (reportData.d4.afterMetric && reportData.d4.afterMetric.trim())) {
    score += 5;
  }

  // 5. D5 生活約定檢核 (權重 15 分，須至少有一項非空白之公約名稱)
  const hasValidD5 = Array.isArray(reportData.d5.standardDocs) &&
    reportData.d5.standardDocs.some(d => d && d.docName && d.docName.trim().length > 0);
  if (hasValidD5) {
    score += 15;
  } else {
    reminders.push({ level: 'danger', tab: 'tab-d5', focus: 'btn-add-d5-doc', title: '第五步：生活約定還沒建立', desc: '請訂立一條共同遵守的生活公約。' });
  }

  // 更新頂部導航列完整度徽章
  const scoreEl = document.getElementById('audit-score-num');
  const barFillEl = document.getElementById('audit-score-bar');
  const tagEl = document.getElementById('audit-score-tag');

  if (scoreEl) scoreEl.textContent = `${score}%`;
  if (barFillEl) {
    barFillEl.style.width = `${score}%`;
  }

  if (tagEl) {
    if (score < 50) {
      tagEl.textContent = '待補充細節';
      tagEl.style.backgroundColor = 'var(--danger-bg)';
      tagEl.style.color = 'var(--danger)';
    } else if (score < 85) {
      tagEl.textContent = '逐漸完整';
      tagEl.style.backgroundColor = 'var(--warning-bg)';
      tagEl.style.color = 'var(--warning)';
    } else {
      tagEl.textContent = '分析完整';
      tagEl.style.backgroundColor = 'var(--success-bg)';
      tagEl.style.color = 'var(--success)';
    }
  }

  // 更新提醒容器（相容保留）
  const reminderContainer = document.getElementById('reminder-container');
  if (reminderContainer) {
    if (reminders.length === 0) {
      reminderContainer.innerHTML = `<div class="reminder-item success"><div class="reminder-title">報告非常完善！</div>5D 各步驟均已完整填寫，可隨時點選上方按鈕產出 Word 報告或 PPT 簡報！</div>`;
    } else {
      reminderContainer.innerHTML = reminders.map(r => `
        <div class="reminder-item ${r.level}" onclick="jumpToField('${r.tab}', '${r.focus}')">
          <div class="reminder-title">
            <span>${escapeHtml(r.title)}</span>
          </div>
          <div>${escapeHtml(r.desc)}</div>
        </div>
      `).join('');
    }
  }
}

// 點擊提醒卡片跳轉聚焦
window.jumpToField = function(tabId, fieldId) {
  switchToTab(tabId);
  setTimeout(() => {
    const el = document.getElementById(fieldId);
    if (el) {
      el.focus();
      el.scrollIntoView({ behavior: 'smooth', block: 'center' });
      el.style.transition = 'box-shadow 0.2s';
      el.style.boxShadow = '0 0 0 4px rgba(220, 38, 38, 0.4)';
      setTimeout(() => {
        el.style.boxShadow = '';
      }, 1500);
    }
  }, 100);
};

// ==========================================================================
// 快捷操作與匯出模組 (Export & Actions)
// ==========================================================================
function initActionButtons() {
  // 模式切換器
  const modeSelector = document.getElementById('mode-selector');
  if (modeSelector) {
    modeSelector.addEventListener('change', () => {
      applyAppMode(modeSelector.value);
    });
  }

  // 載入生活實例
  const btnLifeDemo = document.getElementById('btn-load-life-demo');
  if (btnLifeDemo) {
    btnLifeDemo.addEventListener('click', () => {
      if (confirm('載入生活實例將覆蓋當前編輯區內容，是否確認載入？')) {
        loadLifeDemoData();
      }
    });
  }

  // 清空重置
  const btnReset = document.getElementById('btn-reset-form');
  if (btnReset) {
    btnReset.addEventListener('click', () => {
      if (confirm('確定要清空所有填寫內容重新開始？此動作將清除當前編輯內容。')) {
        clearAllReportData();
      }
    });
  }

  // 匯出 Word (.doc) 報告
  const btnExportWord = document.getElementById('btn-export-word');
  if (btnExportWord) {
    btnExportWord.addEventListener('click', exportWordDocument);
  }

  // 匯出 PPT (.pptx) 簡報
  const btnExportPpt = document.getElementById('btn-export-ppt');
  if (btnExportPpt) {
    btnExportPpt.addEventListener('click', exportPptxPresentation);
  }

  // 列印 / 轉存 PDF
  const btnPrint = document.getElementById('btn-print-report');
  if (btnPrint) {
    btnPrint.addEventListener('click', () => {
      switchToTab('tab-preview');
      setTimeout(() => {
        window.print();
      }, 300);
    });
  }
}

// 取得空白 5D 生活資料模型
function getBlankReportData() {
  const today = new Date().toISOString().slice(0, 10);
  const randomSuffix = Math.floor(Math.random() * 900 + 100);
  return {
    reportId: `5D-LIFE-${today.replace(/-/g, '')}-${randomSuffix}`,
    title: '',
    partName: '',
    partNumber: '',
    customerLine: '',
    lotNumber: '',
    machineNumber: '',
    severity: '重大影響（違反約定、擅自拿取或信任破壞）',
    owner: '',
    approver: '',
    dateCreated: today,
    targetCloseDate: '',
    d1: {
      problemDesc: '',
      who: '',
      when: '',
      where: '',
      what: '',
      why: '',
      how: '',
      howMany: '',
      defectRate: '',
      impactScope: ''
    },
    d2: {
      factoryStock: '',
      transitStock: '',
      customerStock: '',
      containmentActions: [],
      containmentVerification: ''
    },
    d3: {
      whyMadeChain: [],
      whyEscapedChain: [],
      rootCauseSummary: ''
    },
    d4: {
      correctiveActions: [],
      beforeMetric: '',
      afterMetric: '',
      validationConclusion: ''
    },
    d5: {
      standardDocs: [],
      horizontalDeployment: [],
      signOff: {
        qaComment: '',
        qaStatus: '觀察改善中',
        signDate: today
      }
    }
  };
}

// 清空所有填寫內容重新開始
function clearAllReportData() {
  reportData = getBlankReportData();
  selectedQuestionIndex = 0;
  lastSupplementedInfo = { label: '', value: '', field: '' };

  const rawInput = document.getElementById('raw-input-text');
  if (rawInput) {
    rawInput.value = '';
  }

  saveAutoDraft();

  populateFormFromData();
  renderAllDynamicFields();
  updateAuditAndScore();
  generateClarificationQuestions();
  renderLivePreview();

  switchToTab('tab-smart-input');
  if (rawInput) {
    rawInput.focus();
  }
  showToast('已清空所有內容，可直接開始填寫新事件', 'info');
}

// 載入生活案例資料
function loadLifeDemoData() {
  applyAppMode('life');
  selectedQuestionIndex = 0;
  lastSupplementedInfo = { label: '', value: '', field: '' };
  const sel = document.getElementById('mode-selector');
  if (sel) sel.value = 'life';

  reportData = normalizeReportData(JSON.parse(JSON.stringify(window.SAMPLE_LIFE_5D || SAMPLE_LIFE_5D)));

  const rawInput = document.getElementById('raw-input-text');
  if (rawInput) {
    rawInput.value = `小豬弟弟無故在未取得小雞姊姊的同意下，擅自將小雞姊姊房間床上的玩偶在 11/18 早上出門時帶去學校展示給同學看，並提供給同學玩。造成小雞姊姊強烈不滿與信任受損。
目前玩偶已自書包取出確認無破損並完成清潔消毒，無在途或學校遺留配件。
真因分析在於弟弟為求同儕認同與炫耀展示心理，且家庭過去未嚴肅界定私有物品所有權邊界；流出原因為房間門扉敞開無實體防護，且晨間出門缺乏異常檢查。
已由弟弟正式道歉，分擔一週家庭公務作為補償，並制定家庭私人物品公約（RULE-HOME-001）。`;
  }

  populateFormFromData();
  renderAllDynamicFields();
  updateAuditAndScore();
  generateClarificationQuestions();
  renderLivePreview();
  saveAutoDraft();
  showToast('已成功載入生活管理案例（小豬弟弟拿玩偶事件）', 'success');
}

// 切換應用領域模式與自適應標籤
function applyAppMode() {
  const titleEl = document.querySelector('.brand-title');
  if (titleEl) {
    titleEl.textContent = '5D 生活問題小幫手';
  }
}

function updateLabel(selector, newText) {
  const label = document.querySelector(selector);
  if (label) {
    const isRequired = newText.includes('*');
    const cleanText = newText.replace('*', '').trim();
    label.innerHTML = `${cleanText} ${isRequired ? '<span class="required">*</span>' : ''}`;
  }
}

function triggerDownload(blob, filename) {
  const link = document.createElement('a');
  link.href = URL.createObjectURL(blob);
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(link.href);
}

// ==========================================================================
// 匯出 Word 報告 (.doc) - 原生 MSO HTML XML 規格
// ==========================================================================
function exportWordDocument() {
  const htmlContent = generateWordHtmlString();
  const blob = new Blob(['\ufeff' + htmlContent], {
    type: 'application/msword;charset=utf-8'
  });
  const fileName = `5D_生活問題分析報告_${sanitizeFilename(reportData.reportId)}.doc`;
  triggerDownload(blob, fileName);
  showToast('Word (.doc) 報告已成功匯出', 'success');
}

function generateWordHtmlString() {
  return `
  <html xmlns:o='urn:schemas-microsoft-com:office:office' xmlns:w='urn:schemas-microsoft-com:office:word' xmlns='http://www.w3.org/TR/REC-html40'>
  <head>
    <meta charset='utf-8'>
    <title>5D 生活問題小幫手分析報告</title>
    <!--[if gte mso 9]>
    <xml>
      <w:WordDocument>
        <w:View>Print</w:View>
        <w:Zoom>100</w:Zoom>
        <w:DoNotOptimizeForBrowser/>
      </w:WordDocument>
    </xml>
    <![endif]-->
    <style>
      @page Section1 {
        size: 595.3pt 841.9pt; /* A4 */
        margin: 2.0cm 2.0cm 2.0cm 2.0cm;
        mso-header-margin: 36.0pt;
        mso-footer-margin: 36.0pt;
        mso-paper-source: 0;
      }
      div.Section1 { page: Section1; }
      body {
        font-family: 'Microsoft JhengHei', '微軟正黑體', 'PingFang TC', sans-serif;
        font-size: 10.5pt;
        line-height: 1.5;
        color: #111827;
      }
      h1 {
        font-size: 18pt;
        font-weight: bold;
        color: #1e3a8a;
        text-align: center;
        margin-bottom: 4pt;
      }
      .subtitle {
        text-align: center;
        font-size: 10pt;
        color: #4b5563;
        margin-bottom: 16pt;
      }
      h2 {
        font-size: 12pt;
        font-weight: bold;
        color: #1e3a8a;
        background-color: #f1f5f9;
        padding: 4pt 8pt;
        border-left: 4pt solid #1e3a8a;
        margin-top: 14pt;
        margin-bottom: 8pt;
      }
      table {
        border-collapse: collapse;
        width: 100%;
        margin-bottom: 10pt;
      }
      th, td {
        border: 1px solid #94a3b8;
        padding: 5pt 7pt;
        font-size: 9.5pt;
        vertical-align: top;
      }
      th {
        background-color: #f8fafc;
        color: #1e3a8a;
        font-weight: bold;
      }
      .badge-danger { color: #dc2626; font-weight: bold; }
      .badge-success { color: #059669; font-weight: bold; }
      .badge-warning { color: #d97706; font-weight: bold; }
      .page-break { page-break-before: always; }
    </style>
  </head>
  <body>
    <div class="Section1">
      <h1>5D 生活問題小幫手分析報告</h1>
      <div class="subtitle">（5D Life Problem Solving & Agreement Report）</div>

      <!-- 基本資訊表 -->
      <table>
        <tr>
          <th style="width: 15%;">報告編號</th>
          <td style="width: 35%;">${escapeHtml(reportData.reportId)}</td>
          <th style="width: 15%;">建立日期</th>
          <td style="width: 35%;">${escapeHtml(reportData.dateCreated)}</td>
        </tr>
        <tr>
          <th>報告主題</th>
          <td colspan="3"><strong>${escapeHtml(reportData.title)}</strong></td>
        </tr>
        <tr>
          <th>涉及物品 / 事項</th>
          <td>${escapeHtml(reportData.partName)}</td>
          <th>物品 / 事項代號</th>
          <td>${escapeHtml(reportData.partNumber)}</td>
        </tr>
        <tr>
          <th>關係對象 / 場所</th>
          <td>${escapeHtml(reportData.customerLine)}</td>
          <th>事發時段 / 書包工具</th>
          <td>${escapeHtml(reportData.lotNumber)} / ${escapeHtml(reportData.machineNumber)}</td>
        </tr>
        <tr>
          <th>提醒等級</th>
          <td><strong>${escapeHtml(reportData.severity)}</strong></td>
          <th>記錄人 / 共同確認人</th>
          <td>${escapeHtml(reportData.owner)} / ${escapeHtml(reportData.approver)}</td>
        </tr>
      </table>

      <!-- D1 問題定義 -->
      <h2>D1：到底發生了什麼事？（問題定義與情況描述）</h2>
      <table>
        <tr>
          <th style="width: 15%;">事情完整描述</th>
          <td colspan="3">${escapeHtml(reportData.d1.problemDesc)}</td>
        </tr>
        <tr>
          <th>Who（誰遇到/影響誰）</th>
          <td style="width: 35%;">${escapeHtml(reportData.d1.who)}</td>
          <th style="width: 15%;">When（什麼時候）</th>
          <td style="width: 35%;">${escapeHtml(reportData.d1.when)}</td>
        </tr>
        <tr>
          <th>Where（在哪裡）</th>
          <td>${escapeHtml(reportData.d1.where)}</td>
          <th>What（發生什麼事）</th>
          <td>${escapeHtml(reportData.d1.what)}</td>
        </tr>
        <tr>
          <th>Why（違反什麼約定）</th>
          <td>${escapeHtml(reportData.d1.why)}</td>
          <th>How（如何被發現）</th>
          <td>${escapeHtml(reportData.d1.how)}</td>
        </tr>
        <tr>
          <th>How Many（影響範圍）</th>
          <td>${escapeHtml(reportData.d1.howMany)}</td>
          <th>違規與影響程度</th>
          <td><strong class="badge-danger">${escapeHtml(reportData.d1.defectRate)}</strong></td>
        </tr>
        <tr>
          <th>心情與信任影響</th>
          <td colspan="3">${escapeHtml(reportData.d1.impactScope)}</td>
        </tr>
      </table>

      <!-- D2 現狀圍堵措施 -->
      <h2>D2：現場與物品緊急怎麼做？（緊急處置）</h2>
      <table>
        <tr>
          <th style="width: 25%;">核心場所物品清查（家中/現場）</th>
          <td>${escapeHtml(reportData.d2.factoryStock)}</td>
        </tr>
        <tr>
          <th>移動途徑物品確認（路途/書包）</th>
          <td>${escapeHtml(reportData.d2.transitStock)}</td>
        </tr>
        <tr>
          <th>外溢場所處置（學校/外部場所）</th>
          <td>${escapeHtml(reportData.d2.customerStock)}</td>
        </tr>
      </table>

      <div style="font-weight:bold; margin: 8pt 0 4pt 0; color:#1e3a8a;">緊急處置措施執行表：</div>
      <table>
        <thead>
          <tr>
            <th style="width: 40%;">處置作為</th>
            <th style="width: 15%;">責任人</th>
            <th style="width: 15%;">期限</th>
            <th style="width: 10%;">狀態</th>
            <th style="width: 20%;">確認結果</th>
          </tr>
        </thead>
        <tbody>
          ${reportData.d2.containmentActions.length > 0 ? reportData.d2.containmentActions.map(a => `
            <tr>
              <td>${escapeHtml(a.action)}</td>
              <td>${escapeHtml(a.owner)}</td>
              <td>${escapeHtml(a.dueDate)}</td>
              <td>${escapeHtml(a.status)}</td>
              <td>${escapeHtml(a.result)}</td>
            </tr>
          `).join('') : '<tr><td colspan="5" style="text-align:center;">無處置項目記錄</td></tr>'}
        </tbody>
      </table>
      <p><strong>現場處置效果確認結論：</strong>${escapeHtml(reportData.d2.containmentVerification)}</p>

      <div class="page-break"></div>

      <!-- D3 根本原因分析 -->
      <h2>D3：為什麼會這樣？（深入找原因 5 Why）</h2>
      <div style="font-weight:bold; margin-bottom: 4pt; color:#1e3a8a;">為什麼會做這件事？（動機推導 Why Made）：</div>
      <table>
        <thead>
          <tr>
            <th style="width: 15%;">層級</th>
            <th style="width: 45%;">提問（Question）</th>
            <th style="width: 40%;">答覆（Answer）</th>
          </tr>
        </thead>
        <tbody>
          ${reportData.d3.whyMadeChain.length > 0 ? reportData.d3.whyMadeChain.map(w => `
            <tr>
              <td><strong>${escapeHtml(w.level)}</strong></td>
              <td>${escapeHtml(w.question)}</td>
              <td>${escapeHtml(w.answer)}</td>
            </tr>
          `).join('') : '<tr><td colspan="3" style="text-align:center;">無推導資料</td></tr>'}
        </tbody>
      </table>

      <div style="font-weight:bold; margin-top: 10pt; margin-bottom: 4pt; color:#1e3a8a;">為什麼當下沒被發現或阻止？（防範推導 Why Escaped）：</div>
      <table>
        <thead>
          <tr>
            <th style="width: 15%;">層級</th>
            <th style="width: 45%;">提問（Question）</th>
            <th style="width: 40%;">答覆（Answer）</th>
          </tr>
        </thead>
        <tbody>
          ${reportData.d3.whyEscapedChain.length > 0 ? reportData.d3.whyEscapedChain.map(w => `
            <tr>
              <td><strong>${escapeHtml(w.level)}</strong></td>
              <td>${escapeHtml(w.question)}</td>
              <td>${escapeHtml(w.answer)}</td>
            </tr>
          `).join('') : '<tr><td colspan="3" style="text-align:center;">無推導資料</td></tr>'}
        </tbody>
      </table>
      <p style="margin-top: 8pt; padding: 6pt; background-color:#eff6ff; border: 1px solid #bfdbfe;">
        <strong>根本原因確認總結：</strong>${escapeHtml(reportData.d3.rootCauseSummary)}
      </p>

      <!-- D4 永久改善對策 -->
      <h2>D4：以後怎麼改善？（好方法與成效）</h2>
      <table>
        <thead>
          <tr>
            <th style="width: 35%;">改善好方法具體作法</th>
            <th style="width: 12%;">對策分類</th>
            <th style="width: 13%;">負責人</th>
            <th style="width: 12%;">預定完成日</th>
            <th style="width: 10%;">狀態</th>
            <th style="width: 18%;">檢核結論</th>
          </tr>
        </thead>
        <tbody>
          ${reportData.d4.correctiveActions.length > 0 ? reportData.d4.correctiveActions.map(c => `
            <tr>
              <td>${escapeHtml(c.action)}</td>
              <td>${escapeHtml(c.category)}</td>
              <td>${escapeHtml(c.owner)}</td>
              <td>${escapeHtml(c.dueDate)}</td>
              <td>${escapeHtml(c.status)}</td>
              <td>${escapeHtml(c.verification)}</td>
            </tr>
          `).join('') : '<tr><td colspan="6" style="text-align:center;">無改善對策記錄</td></tr>'}
        </tbody>
      </table>

      <table>
        <tr>
          <th style="width: 20%;">改善前情況（Before）</th>
          <td style="width: 80%;">${escapeHtml(reportData.d4.beforeMetric)}</td>
        </tr>
        <tr>
          <th>改善後情況（After）</th>
          <td><strong class="badge-success">${escapeHtml(reportData.d4.afterMetric)}</strong></td>
        </tr>
        <tr>
          <th>成效判定結論</th>
          <td>${escapeHtml(reportData.d4.validationConclusion)}</td>
        </tr>
      </table>

      <!-- D5 再發防止與生活約定 -->
      <h2>D5：訂立生活約定（生活公約與好習慣）</h2>
      <div style="font-weight:bold; margin-bottom: 4pt; color:#1e3a8a;">共同生活約定清單：</div>
      <table>
        <thead>
          <tr>
            <th style="width: 20%;">約定類別</th>
            <th style="width: 20%;">公約編號</th>
            <th style="width: 35%;">公約名稱與內容</th>
            <th style="width: 13%;">訂立日期</th>
            <th style="width: 12%;">提醒人</th>
          </tr>
        </thead>
        <tbody>
          ${reportData.d5.standardDocs.length > 0 ? reportData.d5.standardDocs.map(d => `
            <tr>
              <td>${escapeHtml(d.docType)}</td>
              <td><strong>${escapeHtml(d.docNumber)}</strong></td>
              <td>${escapeHtml(d.docName)}</td>
              <td>${escapeHtml(d.revDate)}</td>
              <td>${escapeHtml(d.owner)}</td>
            </tr>
          `).join('') : '<tr><td colspan="5" style="text-align:center;">尚無生活約定記錄</td></tr>'}
        </tbody>
      </table>

      <div style="font-weight:bold; margin-top: 10pt; margin-bottom: 4pt; color:#1e3a8a;">舉一反三：其他東西也要注意（互相提醒與留意）：</div>
      <table>
        <thead>
          <tr>
            <th style="width: 35%;">其他要注意的對象或物品</th>
            <th style="width: 35%;">大家講好的做法</th>
            <th style="width: 15%;">實施時間</th>
            <th style="width: 15%;">負責人</th>
          </tr>
        </thead>
        <tbody>
          ${reportData.d5.horizontalDeployment.length > 0 ? reportData.d5.horizontalDeployment.map(h => `
            <tr>
              <td>${escapeHtml(h.target)}</td>
              <td>${escapeHtml(h.action)}</td>
              <td>${escapeHtml(h.dueDate)}</td>
              <td>${escapeHtml(h.owner)}</td>
            </tr>
          `).join('') : '<tr><td colspan="4" style="text-align:center;">尚無互相提醒項目</td></tr>'}
        </tbody>
      </table>

      <!-- 家長/老師見證評語區塊 -->
      <table style="margin-top: 16pt;">
        <tr>
          <th style="width: 18%;">家長 / 老師見證評語</th>
          <td style="width: 42%;">${escapeHtml(reportData.d5.signOff.qaComment || '待確認評語')}</td>
          <th style="width: 13%;">處理結果判定</th>
          <td style="width: 13%; text-align:center;"><strong>${escapeHtml(reportData.d5.signOff.qaStatus)}</strong></td>
          <th style="width: 7%;">日期</th>
          <td style="width: 7%; text-align:center;">${escapeHtml(reportData.d5.signOff.signDate || reportData.dateCreated)}</td>
        </tr>
      </table>
    </div>
  </body>
  </html>
  `;
}

// ==========================================================================
// 匯出 PowerPoint 簡報 (.pptx) - 本機 PptxGenJS 引擎 (16:9 LAYOUT_WIDE 排版)
// ==========================================================================
function exportPptxPresentation() {
  if (typeof PptxGenJS === 'undefined') {
    alert('無法載入本機 PptxGenJS 投影片產生引擎，請確認 libs/pptxgen.min.js 是否存在。');
    return;
  }

  try {
    const pptx = new PptxGenJS();
    // 使用現代 16:9 寬螢幕版面 (13.333 x 7.5 英吋)，徹底杜絕文字與表格超出邊界問題
    pptx.layout = 'LAYOUT_WIDE';
    pptx.author = reportData.owner || '生活小幫手小組';
    pptx.company = '5D 生活問題解決小組';
    pptx.title = reportData.title || '5D 生活問題分析簡報';

    // 投影片 1: 封面 (Title Slide)
    const s1 = pptx.addSlide();
    s1.background = { color: '0F172A' }; // 曜石深藍沉穩底色

    s1.addText('5D LIFE PROBLEM SOLVING REPORT', {
      x: 0.8, y: 0.9, w: 11.7, h: 0.4,
      fontSize: 14, color: '38BDF8', bold: true, fontFace: 'Microsoft JhengHei'
    });

    s1.addText(reportData.title || '5D 生活問題分析報告', {
      x: 0.8, y: 1.4, w: 11.7, h: 1.3,
      fontSize: 24, color: 'FFFFFF', bold: true, fontFace: 'Microsoft JhengHei',
      valign: 'top'
    });

    s1.addShape(pptx.shapes.RECTANGLE, {
      x: 0.8, y: 2.9, w: 2.2, h: 0.05, fill: { color: '38BDF8' }
    });

    const metaItems = [
      `事件編號：${reportData.reportId || '5D-LIFE-001'}`,
      `涉及物品 / 主角：${reportData.partName || '-'} (${reportData.partNumber || '無代號'})`,
      `發生情境：${reportData.customerLine || '家庭與校園生活'}`,
      `裝放書包或使用工具：${reportData.machineNumber || '-'}`,
      `嚴重程度：${reportData.severity || '重大影響'}`,
      `記錄人：${reportData.owner || '-'}`,
      `共同約定人：${reportData.approver || '-'}`,
      `建立日期：${reportData.dateCreated || new Date().toISOString().slice(0, 10)}`
    ];

    s1.addText(metaItems.join('\n'), {
      x: 0.8, y: 3.2, w: 11.7, h: 3.6,
      fontSize: 12.5, color: 'E2E8F0', fontFace: 'Microsoft JhengHei', lineSpacing: 21
    });

    // 投影片 2: 5D 分析流程總覽看板 (Summary)
    const s2 = pptx.addSlide();
    addSlideHeader(s2, '5D 分析流程總覽', 'EXECUTIVE SUMMARY & PROGRESS');

    const d2SummaryDesc = reportData.d2.containmentVerification
      ? `${reportData.d2.containmentVerification.slice(0, 28)}\n處置措施 ${reportData.d2.containmentActions.length} 項`
      : `已執行緊急處置 ${reportData.d2.containmentActions.length} 項\n當下事態已妥善控制`;

    const cards = [
      { step: 'D1 發生什麼事', desc: reportData.d1.what || reportData.d1.problemDesc || '完成問題 5W2H 拆解' },
      { step: 'D2 緊急怎麼做', desc: d2SummaryDesc },
      { step: 'D3 為什麼會這樣', desc: reportData.d3.rootCauseSummary ? '完成原因與防範 5 Why 分析' : '5 Why 因果推導中' },
      { step: 'D4 以後怎麼改善', desc: `擬定好方法 ${reportData.d4.correctiveActions.length} 項\n成效已檢核確認` },
      { step: 'D5 訂立生活約定', desc: `訂立共同約定 ${reportData.d5.standardDocs.length} 項\n習慣養成推廣中` }
    ];

    cards.forEach((c, idx) => {
      const xPos = 0.8 + idx * 2.38;
      s2.addShape(pptx.shapes.ROUNDED_RECTANGLE, {
        x: xPos, y: 1.55, w: 2.15, h: 5.1,
        fill: { color: 'F8FAFC' }, line: { color: 'CBD5E1', width: 1.5 }
      });
      s2.addText(c.step, {
        x: xPos, y: 1.75, w: 2.15, h: 0.45,
        fontSize: 13, bold: true, color: '1E3A8A', align: 'center', fontFace: 'Microsoft JhengHei'
      });
      s2.addText(c.desc, {
        x: xPos + 0.15, y: 2.35, w: 1.85, h: 4.1,
        fontSize: 10.5, color: '334155', fontFace: 'Microsoft JhengHei', valign: 'top'
      });
    });

    // 投影片 3: D1 發生什麼事
    const s3 = pptx.addSlide();
    addSlideHeader(s3, 'D1：發生什麼事與情況說明', 'DEFINE THE PROBLEM (5W2H)');

    s3.addShape(pptx.shapes.ROUNDED_RECTANGLE, {
      x: 0.8, y: 1.45, w: 11.7, h: 1.05, fill: { color: 'EFF6FF' }, line: { color: '93C5FD' }
    });
    s3.addText(`事情經過摘要：${reportData.d1.problemDesc || '無'}`, {
      x: 1.0, y: 1.55, w: 11.3, h: 0.85,
      fontSize: 11, color: '1E3A8A', bold: true, fontFace: 'Microsoft JhengHei'
    });

    const d1Rows = [
      [
        { text: '5W2H 維度', options: { bold: true, fill: 'F1F5F9' } },
        { text: '具體內容說明', options: { bold: true, fill: 'F1F5F9' } },
        { text: '5W2H 維度', options: { bold: true, fill: 'F1F5F9' } },
        { text: '具體內容說明', options: { bold: true, fill: 'F1F5F9' } }
      ],
      [
        { text: 'Who（誰遇到 / 誰發現）', options: { bold: true } },
        { text: reportData.d1.who || '-' },
        { text: 'When（什麼時候發生）', options: { bold: true } },
        { text: reportData.d1.when || '-' }
      ],
      [
        { text: 'Where（在哪裡發生）', options: { bold: true } },
        { text: reportData.d1.where || '-' },
        { text: 'What（具體發生了什麼事）', options: { bold: true } },
        { text: reportData.d1.what || '-' }
      ],
      [
        { text: 'Why（違反什麼約定/期望）', options: { bold: true } },
        { text: reportData.d1.why || '-' },
        { text: 'How（是怎麼被發現的）', options: { bold: true } },
        { text: reportData.d1.how || '-' }
      ],
      [
        { text: 'How Many（影響程度或次數）', options: { bold: true } },
        { text: reportData.d1.howMany || '-' },
        { text: '嚴重程度與違規情形', options: { bold: true, color: 'DC2626' } },
        { text: reportData.d1.defectRate || '-', options: { bold: true, color: 'DC2626' } }
      ]
    ];

    s3.addTable(d1Rows, {
      x: 0.8, y: 2.7, w: 11.7, colW: [2.3, 3.55, 2.3, 3.55],
      fontSize: 10.5, fontFace: 'Microsoft JhengHei', border: { pt: 0.5, color: 'CBD5E1' }
    });

    // 投影片 4: D2 緊急怎麼做
    const s4 = pptx.addSlide();
    addSlideHeader(s4, 'D2：緊急怎麼做（當下應變與處置）', 'CONTAINMENT ACTIONS & STATUS');

    const stockRows = [
      [
        { text: '處置環節', options: { bold: true, fill: 'F1F5F9' } },
        { text: '具體應變與當前確認狀態', options: { bold: true, fill: 'F1F5F9' } }
      ],
      [{ text: '1. 現場立即處置', options: { bold: true } }, { text: reportData.d2.factoryStock || '已妥善確認' }],
      [{ text: '2. 過程與隨身檢查', options: { bold: true } }, { text: reportData.d2.transitStock || '已確認無衍生問題' }],
      [{ text: '3. 向重要關係人說明', options: { bold: true } }, { text: reportData.d2.customerStock || '已完成溝通說明' }]
    ];

    s4.addTable(stockRows, {
      x: 0.8, y: 1.45, w: 11.7, colW: [3.2, 8.5],
      fontSize: 10, fontFace: 'Microsoft JhengHei', border: { pt: 0.5, color: 'CBD5E1' }
    });

    s4.addText('當下立刻做的緊急行動清單：', {
      x: 0.8, y: 3.25, w: 6.0, h: 0.35,
      fontSize: 12, bold: true, color: '1E3A8A', fontFace: 'Microsoft JhengHei'
    });

    const actHeaders = [
      { text: '具體做了什麼處置', options: { bold: true, fill: 'F1F5F9' } },
      { text: '誰負責', options: { bold: true, fill: 'F1F5F9' } },
      { text: '完成時間', options: { bold: true, fill: 'F1F5F9' } },
      { text: '目前進度', options: { bold: true, fill: 'F1F5F9' } },
      { text: '確認的結果', options: { bold: true, fill: 'F1F5F9' } }
    ];

    const actBody = reportData.d2.containmentActions.slice(0, 4).map(a => [
      { text: a.action || '-' },
      { text: a.owner || '-' },
      { text: a.dueDate || '-' },
      { text: a.status || '-' },
      { text: a.result || '-' }
    ]);

    s4.addTable([actHeaders, ...(actBody.length > 0 ? actBody : [[{ text: '尚無緊急行動項目' }, { text: '-' }, { text: '-' }, { text: '-' }, { text: '-' }]])], {
      x: 0.8, y: 3.65, w: 11.7, colW: [4.5, 1.5, 1.5, 1.2, 3.0],
      fontSize: 10, fontFace: 'Microsoft JhengHei', border: { pt: 0.5, color: 'CBD5E1' }
    });

    s4.addShape(pptx.shapes.ROUNDED_RECTANGLE, {
      x: 0.8, y: 5.95, w: 11.7, h: 0.75, fill: { color: 'F0FDF4' }, line: { color: 'BBF7D0' }
    });
    s4.addText(`處置結論：${reportData.d2.containmentVerification || '當下事態已獲得妥善控制，各方情緒平復，未衍生進一步問題。'}`, {
      x: 1.0, y: 6.05, w: 11.3, h: 0.55,
      fontSize: 10.5, bold: true, color: '166534', fontFace: 'Microsoft JhengHei'
    });

    // 投影片 5: D3 為什麼會這樣
    const s5 = pptx.addSlide();
    addSlideHeader(s5, 'D3：為什麼會這樣（追問原因 5 Why）', 'ROOT CAUSE ANALYSIS (5 WHY)');

    // 發生原因 5 Why
    s5.addText('為什麼會做這件事（動機推導）：', {
      x: 0.8, y: 1.45, w: 5.7, h: 0.35,
      fontSize: 12, bold: true, color: '1E3A8A', fontFace: 'Microsoft JhengHei'
    });
    const whyMadeText = reportData.d3.whyMadeChain.map((w, i) => `${w.level || `Why ${i+1}`}：${w.answer || w.question}`).join('\n↓\n') || '尚未建立動機原因推導';
    s5.addShape(pptx.shapes.ROUNDED_RECTANGLE, {
      x: 0.8, y: 1.85, w: 5.7, h: 3.7, fill: { color: 'F8FAFC' }, line: { color: 'CBD5E1' }
    });
    s5.addText(whyMadeText, {
      x: 1.0, y: 1.95, w: 5.3, h: 3.5,
      fontSize: 10, color: '1E293B', fontFace: 'Microsoft JhengHei', valign: 'top', lineSpacing: 15
    });

    // 流出原因 5 Why
    s5.addText('為什麼當下沒被發現/阻止（把關機制推導）：', {
      x: 6.8, y: 1.45, w: 5.7, h: 0.35,
      fontSize: 12, bold: true, color: '1E3A8A', fontFace: 'Microsoft JhengHei'
    });
    const whyEscapedText = reportData.d3.whyEscapedChain.map((w, i) => `${w.level || `Why ${i+1}`}：${w.answer || w.question}`).join('\n↓\n') || '尚未建立把關機制推導';
    s5.addShape(pptx.shapes.ROUNDED_RECTANGLE, {
      x: 6.8, y: 1.85, w: 5.7, h: 3.7, fill: { color: 'F8FAFC' }, line: { color: 'CBD5E1' }
    });
    s5.addText(whyEscapedText, {
      x: 7.0, y: 1.95, w: 5.3, h: 3.5,
      fontSize: 10, color: '1E293B', fontFace: 'Microsoft JhengHei', valign: 'top', lineSpacing: 15
    });

    s5.addShape(pptx.shapes.ROUNDED_RECTANGLE, {
      x: 0.8, y: 5.75, w: 11.7, h: 0.9, fill: { color: 'EFF6FF' }, line: { color: 'BFDBFE' }
    });
    s5.addText(`根本原因總結：${reportData.d3.rootCauseSummary || '無'}`, {
      x: 1.0, y: 5.85, w: 11.3, h: 0.7,
      fontSize: 11, bold: true, color: '1E3A8A', fontFace: 'Microsoft JhengHei'
    });

    // 投影片 6: D4 以後怎麼改善
    const s6 = pptx.addSlide();
    addSlideHeader(s6, 'D4：以後怎麼改善（好方法與成效）', 'BETTER SOLUTIONS & VALIDATION');

    const d4Headers = [
      { text: '改善與補償做法', options: { bold: true, fill: 'F1F5F9' } },
      { text: '類別', options: { bold: true, fill: 'F1F5F9' } },
      { text: '誰去做', options: { bold: true, fill: 'F1F5F9' } },
      { text: '完成期限', options: { bold: true, fill: 'F1F5F9' } },
      { text: '進度', options: { bold: true, fill: 'F1F5F9' } },
      { text: '成效驗證', options: { bold: true, fill: 'F1F5F9' } }
    ];

    const d4Body = reportData.d4.correctiveActions.slice(0, 4).map(c => [
      { text: c.action || '-' },
      { text: c.category || '-' },
      { text: c.owner || '-' },
      { text: c.dueDate || '-' },
      { text: c.status || '-' },
      { text: c.verification || '-' }
    ]);

    s6.addTable([d4Headers, ...(d4Body.length > 0 ? d4Body : [[{ text: '尚無改善行動' }, { text: '-' }, { text: '-' }, { text: '-' }, { text: '-' }, { text: '-' }]])], {
      x: 0.8, y: 1.45, w: 11.7, colW: [4.2, 1.2, 1.3, 1.3, 1.0, 2.7],
      fontSize: 10, fontFace: 'Microsoft JhengHei', border: { pt: 0.5, color: 'CBD5E1' }
    });

    s6.addText('改善前後改變與成效對比：', {
      x: 0.8, y: 3.65, w: 6.0, h: 0.35,
      fontSize: 12, bold: true, color: '1E3A8A', fontFace: 'Microsoft JhengHei'
    });

    const metricRows = [
      [
        { text: '改善前情況（Before）', options: { bold: true, fill: 'FEE2E2', color: '991B1B' } },
        { text: reportData.d4.beforeMetric || '待填寫' }
      ],
      [
        { text: '改善後情況（After）', options: { bold: true, fill: 'D1FAE5', color: '065F46' } },
        { text: reportData.d4.afterMetric || '待填寫' }
      ],
      [
        { text: '成效判定結論', options: { bold: true, fill: 'F1F5F9' } },
        { text: reportData.d4.validationConclusion || '待填寫' }
      ]
    ];

    s6.addTable(metricRows, {
      x: 0.8, y: 4.05, w: 11.7, colW: [3.2, 8.5],
      fontSize: 10.5, fontFace: 'Microsoft JhengHei', border: { pt: 0.5, color: 'CBD5E1' }
    });

    s6.addShape(pptx.shapes.ROUNDED_RECTANGLE, {
      x: 0.8, y: 5.85, w: 11.7, h: 0.75, fill: { color: 'F0FDF4' }, line: { color: 'BBF7D0' }
    });
    s6.addText(`檢核結論：${reportData.d4.validationConclusion || '新方法已試行並獲得正面成效。'}`, {
      x: 1.0, y: 5.95, w: 11.3, h: 0.55,
      fontSize: 10.5, bold: true, color: '166534', fontFace: 'Microsoft JhengHei'
    });

    // 投影片 7: D5 訂立生活約定
    const s7 = pptx.addSlide();
    addSlideHeader(s7, 'D5：訂立生活約定（約定與習慣養成）', 'FAMILY AGREEMENTS & HABIT FORMATION');

    s7.addText('生活共同約定清單：', {
      x: 0.8, y: 1.45, w: 6.0, h: 0.35,
      fontSize: 12, bold: true, color: '1E3A8A', fontFace: 'Microsoft JhengHei'
    });

    const docHeaders = [
      { text: '約定類別', options: { bold: true, fill: 'F1F5F9' } },
      { text: '公約編號', options: { bold: true, fill: 'F1F5F9' } },
      { text: '公約名稱與內容', options: { bold: true, fill: 'F1F5F9' } },
      { text: '訂立日期', options: { bold: true, fill: 'F1F5F9' } },
      { text: '提醒人', options: { bold: true, fill: 'F1F5F9' } }
    ];

    const docBody = reportData.d5.standardDocs.slice(0, 4).map(d => [
      { text: d.docType || '-' },
      { text: d.docNumber || '-', options: { bold: true } },
      { text: d.docName || '-' },
      { text: d.revDate || '-' },
      { text: d.owner || '-' }
    ]);

    s7.addTable([docHeaders, ...(docBody.length > 0 ? docBody : [[{ text: '尚無生活約定' }, { text: '-' }, { text: '-' }, { text: '-' }, { text: '-' }]])], {
      x: 0.8, y: 1.85, w: 11.7, colW: [2.5, 2.5, 3.7, 1.5, 1.5],
      fontSize: 10, fontFace: 'Microsoft JhengHei', border: { pt: 0.5, color: 'CBD5E1' }
    });

    s7.addText('舉一反三：其他東西也要注意（互相提醒與留意）：', {
      x: 0.8, y: 3.8, w: 8.0, h: 0.35,
      fontSize: 12, bold: true, color: '1E3A8A', fontFace: 'Microsoft JhengHei'
    });

    const hHeaders = [
      { text: '其他要注意的對象或物品', options: { bold: true, fill: 'F1F5F9' } },
      { text: '大家講好的做法', options: { bold: true, fill: 'F1F5F9' } },
      { text: '實施時間', options: { bold: true, fill: 'F1F5F9' } },
      { text: '負責人', options: { bold: true, fill: 'F1F5F9' } }
    ];

    const hBody = reportData.d5.horizontalDeployment.slice(0, 3).map(h => [
      { text: h.target || '-' },
      { text: h.action || '-' },
      { text: h.dueDate || '-' },
      { text: h.owner || '-' }
    ]);

    s7.addTable([hHeaders, ...(hBody.length > 0 ? hBody : [[{ text: '尚無互相提醒項目' }, { text: '-' }, { text: '-' }, { text: '-' }]])], {
      x: 0.8, y: 4.2, w: 11.7, colW: [4.0, 4.7, 1.5, 1.5],
      fontSize: 10, fontFace: 'Microsoft JhengHei', border: { pt: 0.5, color: 'CBD5E1' }
    });

    s7.addShape(pptx.shapes.ROUNDED_RECTANGLE, {
      x: 0.8, y: 5.85, w: 11.7, h: 0.75, fill: { color: 'EFF6FF' }, line: { color: 'BFDBFE' }
    });
    s7.addText(`見證評語與結果（${reportData.d5.signOff.qaStatus || '觀察改善中'}）：${reportData.d5.signOff.qaComment || '共同遵守生活公約，養成負責任與互相尊重的良好生活習慣。'}`, {
      x: 1.0, y: 5.95, w: 11.3, h: 0.55,
      fontSize: 10.5, bold: true, color: '1E3A8A', fontFace: 'Microsoft JhengHei'
    });

    // 儲存 PPT 檔案
    const pptFileName = `5D_生活問題分析簡報_${sanitizeFilename(reportData.reportId)}.pptx`;
    pptx.writeFile({ fileName: pptFileName })
      .then(() => {
        showToast('PowerPoint (.pptx) 簡報已成功匯出', 'success');
      })
      .catch(err => {
        console.error('匯出 PPT 失敗:', err);
        alert('匯出 PowerPoint 投影片時發生錯誤，請檢查主控台。');
      });

  } catch (err) {
    console.error('PPT 產生引擎錯誤:', err);
    alert('產生 PPTX 失敗：' + err.message);
  }
}

// 輔助函式：新增統一投影片頁首
function addSlideHeader(slide, title, enTitle) {
  slide.addText(title, {
    x: 0.8, y: 0.45, w: 8.5, h: 0.45,
    fontSize: 18, bold: true, color: '0F172A', fontFace: 'Microsoft JhengHei'
  });
  slide.addText(enTitle, {
    x: 0.8, y: 0.9, w: 8.5, h: 0.28,
    fontSize: 9.5, color: '64748B', bold: true, fontFace: 'Microsoft JhengHei'
  });
  slide.addShape('rect', {
    x: 0.8, y: 1.22, w: 11.7, h: 0.02, fill: { color: 'CBD5E1' }
  });
}

// ==========================================================================
// 即時預覽模式渲染 (Live Report Preview)
// ==========================================================================
function renderLivePreview() {
  const container = document.getElementById('preview-content-container');
  if (!container) return;

  container.innerHTML = `
    <div class="preview-header">
      <div>
        <div class="preview-title">5D 生活問題小幫手分析報告</div>
        <div style="font-size:13px; color:#475569; margin-top:4px;">5D Life Problem Solving & Agreement Report</div>
      </div>
      <div class="preview-meta">
        <div><strong>報告編號：</strong>${escapeHtml(reportData.reportId)}</div>
        <div><strong>建立日期：</strong>${escapeHtml(reportData.dateCreated)}</div>
        <div><strong>嚴重等級：</strong><span style="color:#dc2626; font-weight:bold;">${escapeHtml(reportData.severity)}</span></div>
      </div>
    </div>

    <!-- 基本資訊 -->
    <table class="data-table" style="margin-bottom: 20px;">
      <tr>
        <th style="width: 15%;">報告主題</th>
        <td colspan="3"><strong>${escapeHtml(reportData.title || '（未命名主題）')}</strong></td>
      </tr>
      <tr>
        <th>涉及物品 / 事項</th>
        <td style="width: 35%;">${escapeHtml(reportData.partName || '-')}</td>
        <th style="width: 15%;">物品 / 事項代號</th>
        <td style="width: 35%;">${escapeHtml(reportData.partNumber || '-')}</td>
      </tr>
      <tr>
        <th>關係對象 / 場所</th>
        <td>${escapeHtml(reportData.customerLine || '-')}</td>
        <th>事發時段 / 書包工具</th>
        <td>${escapeHtml(reportData.lotNumber || '-')} / ${escapeHtml(reportData.machineNumber || '-')}</td>
      </tr>
      <tr>
        <th>記錄人</th>
        <td>${escapeHtml(reportData.owner || '-')}</td>
        <th>見證 / 約定人</th>
        <td>${escapeHtml(reportData.approver || '-')}</td>
      </tr>
    </table>

    <!-- D1 -->
    <div class="preview-section">
      <div class="preview-section-title">D1：到底發生了什麼事？（問題定義）</div>
      <p style="margin-bottom: 12px; font-size:13px;"><strong>事情完整描述：</strong>${escapeHtml(reportData.d1.problemDesc || '尚未填寫')}</p>
      <table class="data-table">
        <tr>
          <th style="width: 15%;">Who</th>
          <td style="width: 35%;">${escapeHtml(reportData.d1.who || '-')}</td>
          <th style="width: 15%;">When</th>
          <td style="width: 35%;">${escapeHtml(reportData.d1.when || '-')}</td>
        </tr>
        <tr>
          <th>Where</th>
          <td>${escapeHtml(reportData.d1.where || '-')}</td>
          <th>What</th>
          <td>${escapeHtml(reportData.d1.what || '-')}</td>
        </tr>
        <tr>
          <th>Why</th>
          <td>${escapeHtml(reportData.d1.why || '-')}</td>
          <th>How</th>
          <td>${escapeHtml(reportData.d1.how || '-')}</td>
        </tr>
        <tr>
          <th>How Many</th>
          <td>${escapeHtml(reportData.d1.howMany || '-')}</td>
          <th>嚴重程度與違規情形</th>
          <td><strong style="color:#dc2626;">${escapeHtml(reportData.d1.defectRate || '-')}</strong></td>
        </tr>
        <tr>
          <th>對大家的感受與影響</th>
          <td colspan="3">${escapeHtml(reportData.d1.impactScope || '-')}</td>
        </tr>
      </table>
    </div>

    <!-- D2 -->
    <div class="preview-section">
      <div class="preview-section-title">D2：現場與物品緊急怎麼做？（緊急處置）</div>
      <table class="data-table" style="margin-bottom: 12px;">
        <tr>
          <th style="width: 25%;">1. 現場立即處置</th>
          <td>${escapeHtml(reportData.d2.factoryStock || '-')}</td>
        </tr>
        <tr>
          <th>2. 過程與隨身檢查</th>
          <td>${escapeHtml(reportData.d2.transitStock || '-')}</td>
        </tr>
        <tr>
          <th>3. 向重要關係人說明</th>
          <td>${escapeHtml(reportData.d2.customerStock || '-')}</td>
        </tr>
      </table>
      <div style="font-weight:bold; font-size:13px; margin-bottom:6px;">當下立刻做的緊急行動清單：</div>
      <table class="data-table">
        <thead>
          <tr>
            <th>具體做了什麼處置</th>
            <th style="width: 120px;">誰負責</th>
            <th style="width: 120px;">完成時間</th>
            <th style="width: 100px;">目前進度</th>
            <th>確認的結果</th>
          </tr>
        </thead>
        <tbody>
          ${reportData.d2.containmentActions.length > 0 ? reportData.d2.containmentActions.map(a => `
            <tr>
              <td>${escapeHtml(a.action)}</td>
              <td>${escapeHtml(a.owner)}</td>
              <td>${escapeHtml(a.dueDate)}</td>
              <td>${escapeHtml(a.status)}</td>
              <td>${escapeHtml(a.result)}</td>
            </tr>
          `).join('') : '<tr><td colspan="5" style="text-align:center; color:#94a3b8;">尚無緊急處置記錄</td></tr>'}
        </tbody>
      </table>
      <p style="margin-top: 8px; font-size:12px;"><strong>緊急處理後的確認結果：</strong>${escapeHtml(reportData.d2.containmentVerification || '待確認')}</p>
    </div>

    <div class="page-break"></div>

    <!-- D3 -->
    <div class="preview-section">
      <div class="preview-section-title">D3：為什麼會這樣？（深入找原因 5 Why）</div>
      <div style="display:grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-bottom: 12px;">
        <div style="border: 1px solid #cbd5e1; padding: 12px; border-radius: 4px; background-color: #f8fafc;">
          <strong style="color: #1e3a8a;">為什麼會做這件事？（動機推導）：</strong>
          <div style="margin-top: 8px; font-size: 12px;">
            ${reportData.d3.whyMadeChain.map(w => `
              <div style="margin-bottom: 6px;"><strong>${escapeHtml(w.level)}：</strong>${escapeHtml(w.answer || w.question)}</div>
            `).join('') || '<span style="color:#94a3b8;">尚無動機原因推導資料</span>'}
          </div>
        </div>
        <div style="border: 1px solid #cbd5e1; padding: 12px; border-radius: 4px; background-color: #f8fafc;">
          <strong style="color: #1e3a8a;">為什麼當下沒被發現或阻止？（把關機制推導）：</strong>
          <div style="margin-top: 8px; font-size: 12px;">
            ${reportData.d3.whyEscapedChain.map(w => `
              <div style="margin-bottom: 6px;"><strong>${escapeHtml(w.level)}：</strong>${escapeHtml(w.answer || w.question)}</div>
            `).join('') || '<span style="color:#94a3b8;">尚無把關機制推導資料</span>'}
          </div>
        </div>
      </div>
      <div style="padding: 10px 14px; background-color: #eff6ff; border-left: 4px solid #2563eb; font-size: 13px;">
        <strong>最後找出的真正原因總結：</strong>${escapeHtml(reportData.d3.rootCauseSummary || '尚未總結')}
      </div>
    </div>

    <!-- D4 -->
    <div class="preview-section">
      <div class="preview-section-title">D4：以後怎麼改善？（好方法與成效）</div>
      <table class="data-table" style="margin-bottom: 12px;">
        <thead>
          <tr>
            <th>改善與補償做法</th>
            <th style="width: 110px;">類別</th>
            <th style="width: 110px;">誰去做</th>
            <th style="width: 110px;">完成期限</th>
            <th style="width: 90px;">進度</th>
            <th>成效驗證</th>
          </tr>
        </thead>
        <tbody>
          ${reportData.d4.correctiveActions.length > 0 ? reportData.d4.correctiveActions.map(c => `
            <tr>
              <td>${escapeHtml(c.action)}</td>
              <td>${escapeHtml(c.category)}</td>
              <td>${escapeHtml(c.owner)}</td>
              <td>${escapeHtml(c.dueDate)}</td>
              <td>${escapeHtml(c.status)}</td>
              <td>${escapeHtml(c.verification)}</td>
            </tr>
          `).join('') : '<tr><td colspan="6" style="text-align:center; color:#94a3b8;">尚無改善行動記錄</td></tr>'}
        </tbody>
      </table>
      <table class="data-table">
        <tr>
          <th style="width: 20%;">改善前情況（Before）</th>
          <td>${escapeHtml(reportData.d4.beforeMetric || '-')}</td>
        </tr>
        <tr>
          <th>改善後情況（After）</th>
          <td><strong style="color:#059669;">${escapeHtml(reportData.d4.afterMetric || '-')}</strong></td>
        </tr>
        <tr>
          <th>大家共同認可的改善結論</th>
          <td>${escapeHtml(reportData.d4.validationConclusion || '-')}</td>
        </tr>
      </table>
    </div>

    <!-- D5 -->
    <div class="preview-section">
      <div class="preview-section-title">D5：訂立生活約定（生活公約與好習慣）</div>
      <div style="font-weight:bold; font-size:13px; margin-bottom:6px;">全家或班級新訂立的生活約定（公約）：</div>
      <table class="data-table" style="margin-bottom: 12px;">
        <thead>
          <tr>
            <th style="width: 160px;">約定類別</th>
            <th style="width: 160px;">公約編號</th>
            <th>公約名稱與內容</th>
            <th style="width: 120px;">訂立日期</th>
            <th style="width: 100px;">提醒人</th>
          </tr>
        </thead>
        <tbody>
          ${reportData.d5.standardDocs.length > 0 ? reportData.d5.standardDocs.map(d => `
            <tr>
              <td>${escapeHtml(d.docType)}</td>
              <td><strong>${escapeHtml(d.docNumber)}</strong></td>
              <td>${escapeHtml(d.docName)}</td>
              <td>${escapeHtml(d.revDate)}</td>
              <td>${escapeHtml(d.owner)}</td>
            </tr>
          `).join('') : '<tr><td colspan="5" style="text-align:center; color:#94a3b8;">尚無生活約定記錄</td></tr>'}
        </tbody>
      </table>
      <div style="font-weight:bold; font-size:13px; margin-bottom:6px;">舉一反三：其他東西也要注意（互相提醒與留意）：</div>
      <table class="data-table" style="margin-bottom: 16px;">
        <thead>
          <tr>
            <th>其他要注意的對象或物品</th>
            <th>大家講好的做法</th>
            <th style="width: 120px;">實施時間</th>
            <th style="width: 100px;">負責人</th>
          </tr>
        </thead>
        <tbody>
          ${reportData.d5.horizontalDeployment.length > 0 ? reportData.d5.horizontalDeployment.map(h => `
            <tr>
              <td>${escapeHtml(h.target)}</td>
              <td>${escapeHtml(h.action)}</td>
              <td>${escapeHtml(h.dueDate)}</td>
              <td>${escapeHtml(h.owner)}</td>
            </tr>
          `).join('') : '<tr><td colspan="4" style="text-align:center; color:#94a3b8;">尚無互相提醒項目</td></tr>'}
        </tbody>
      </table>
      <div style="border: 1px solid #cbd5e1; padding: 12px; background-color: #f8fafc; border-radius: 4px; display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:8px;">
        <div><strong>家長 / 老師見證評語：</strong>${escapeHtml(reportData.d5.signOff.qaComment || '待確認評語')}</div>
        <div style="display:flex; gap:16px; align-items:center;">
          <div><strong>處理結果判定：</strong><span style="font-weight:bold; color:#1e3a8a;">${escapeHtml(reportData.d5.signOff.qaStatus)}</span></div>
          <div><strong>見證日期：</strong>${escapeHtml(reportData.d5.signOff.signDate || reportData.dateCreated || '-')}</div>
        </div>
      </div>
    </div>
  `;
}

// ==========================================================================
// 智慧對話與非結構化文字分析引擎 (Smart Parser & Guided Interview)
// ==========================================================================
let currentPendingQuestions = [];

function initSmartInput() {
  const btnParse = document.getElementById('btn-parse-text');
  if (btnParse) {
    btnParse.addEventListener('click', runSmartAnalysis);
  }

  const btnPasteSample = document.getElementById('btn-paste-sample-text');
  if (btnPasteSample) {
    btnPasteSample.addEventListener('click', () => {
      const sampleText = `小豬弟弟無故在未取得小雞姊姊的同意下，擅自將小雞姊姊房間床上的玩偶在 11/18 早上出門時帶去學校展示給同學看，並提供給同學玩，請幫我分析並產出報告。`;
      const textarea = document.getElementById('raw-input-text');
      if (textarea) textarea.value = sampleText;
      showToast('已帶入生活案例文字（拿玩偶事件）', 'info');
    });
  }

  const btnToggleAi = document.getElementById('btn-toggle-ai-settings');
  const aiBox = document.getElementById('ai-settings-box');
  if (btnToggleAi && aiBox) {
    btnToggleAi.addEventListener('click', () => {
      aiBox.style.display = aiBox.style.display === 'none' ? 'block' : 'none';
    });
  }

  const selectProvider = document.getElementById('llm-provider');
  const groupApiKey = document.getElementById('group-api-key');
  const groupModelName = document.getElementById('group-model-name');
  if (selectProvider) {
    selectProvider.addEventListener('change', () => {
      const val = selectProvider.value;
      if (groupApiKey) groupApiKey.style.display = val === 'gemini' ? 'block' : 'none';
      if (groupModelName) groupModelName.style.display = (val === 'gemini' || val === 'ollama') ? 'block' : 'none';
    });
  }

  const btnSubmitReply = document.getElementById('btn-submit-interview-reply');
  const inputReply = document.getElementById('interview-reply-input');
  if (btnSubmitReply && inputReply) {
    btnSubmitReply.addEventListener('click', () => submitInterviewReply());
    inputReply.addEventListener('keydown', e => {
      if (e.key === 'Enter') {
        submitInterviewReply();
      }
    });
  }

  const btnAutoDemo = document.getElementById('btn-auto-demo');
  if (btnAutoDemo) {
    btnAutoDemo.addEventListener('click', () => {
      const sel = document.getElementById('demo-scenario-select');
      runShortVideoAutoDemo(sel ? sel.value : 'phone');
    });
  }

  // 支援全局快捷鍵 Alt + D 啟動自動播放示範（方便短影音全螢幕錄製）
  document.addEventListener('keydown', e => {
    if (e.altKey && (e.key === 'd' || e.key === 'D')) {
      e.preventDefault();
      const sel = document.getElementById('demo-scenario-select');
      runShortVideoAutoDemo(sel ? sel.value : 'phone');
    }
  });
}

let isAutoDemoRunning = false;
const AUTO_DEMO_SCENARIOS = {
  phone: '小明昨天玩手機玩到清晨1點才睡覺，造成今天早上起不來上學遲到。',
  borrow: '弟弟昨天下午在家裡客廳沒經過姊姊同意，直接拿姊姊鉛筆盒裡的專業彩色筆來畫畫還弄斷筆芯，造成姊姊非常生氣。',
  money: '小明這禮拜把媽媽給的500元早餐錢省下來，偷偷拿去超商買手機遊戲點數卡儲值，今天媽媽整理發票時才發現。'
};

// 短影音錄製專用：一鍵自動模擬真人逐字輸入、分析、補充看板更新至 100% 並切換 A4 報告預覽
window.runShortVideoAutoDemo = async function(scenarioKey = 'phone') {
  if (isAutoDemoRunning) return;
  isAutoDemoRunning = true;
  const btnAuto = document.getElementById('btn-auto-demo');
  if (btnAuto) {
    btnAuto.disabled = true;
    btnAuto.textContent = '示範播放中...';
  }

  const sleep = (ms) => new Promise(resolve => setTimeout(resolve, ms));

  try {
    // 1. 清空重寫回到第一步純淨畫面
    clearAllReportData();
    await sleep(600);

    // 2. 模擬真人逐字輸入案例文字
    const demoText = AUTO_DEMO_SCENARIOS[scenarioKey] || AUTO_DEMO_SCENARIOS.phone;
    const textarea = document.getElementById('raw-input-text');
    if (textarea) {
      textarea.focus();
      textarea.value = '';
      for (const ch of demoText) {
        textarea.value += ch;
        await sleep(55);
      }
    }
    await sleep(700);

    // 3. 觸發分析並展開即時看板與小幫手提問
    parseRawTextTo5D(demoText);
    await sleep(1400);

    // 4. 自動點選第 1 題建議參考，展示綠色「最新補充已寫入報告」與「剛更新」標籤
    if (currentPendingQuestions && currentPendingQuestions.length > 0) {
      const firstQ = currentPendingQuestions[0];
      applyQuickAnswer(firstQ.field, firstQ.quickVal);
    }
    await sleep(1400);

    // 5. 自動一鍵代入剩餘全部建議參考，完整度達標 100%
    if (typeof window.applyAllQuickAnswers === 'function') {
      window.applyAllQuickAnswers();
    }
    await sleep(1600);

    // 6. 自動切換至「預覽完整報告」展示 A4 正式生活約定單
    switchToTab('tab-preview');
  } finally {
    isAutoDemoRunning = false;
    if (btnAuto) {
      btnAuto.disabled = false;
      btnAuto.textContent = '自動播放示範';
    }
  }
};

// 執行智慧文字分析
function runSmartAnalysis() {
  const textarea = document.getElementById('raw-input-text');
  if (!textarea || !textarea.value.trim()) {
    alert('請先在文字框中輸入或貼上事件描述。');
    return;
  }

  const rawText = textarea.value.trim();
  const provider = document.getElementById('llm-provider')?.value || 'offline-rules';

  showToast('正在進行 5D 語意萃取與結構化拆解...', 'info');

  if (provider === 'gemini') {
    callGeminiApi(rawText);
  } else if (provider === 'ollama') {
    callOllamaApi(rawText);
  } else {
    // 預設本機 100% 離線啟發式語意萃取
    parseRawTextTo5D(rawText);
  }
}

let selectedQuestionIndex = 0;
let lastSupplementedInfo = { label: '', value: '', field: '' };

const FIELD_LABEL_MAP = {
  'd1.when': 'D1 發生時間（When）',
  'd1.where': 'D1 事發地點（Where）',
  'd1.why': 'D1 違反的規矩或約定（Why）',
  'd1.how': 'D1 發現與察覺過程（How）',
  'd1.impactScope': 'D1 造成的影響與感受',
  'd2.action': 'D2 當下緊急處置',
  'd3.why': 'D3 為什麼會這樣（真正原因）',
  'd4.action': 'D4 以後怎麼改善與補償',
  'd5.doc': 'D5 訂立生活公約'
};

// 渲染第一步頁面上的「目前已整理的 5D 報告內容即時看板」
function renderLive5DSummary() {
  const card = document.getElementById('live-5d-summary-card');
  const body = document.getElementById('live-5d-summary-body');
  if (!card || !body) return;

  const hasContent = (reportData.title && reportData.title.trim()) ||
                     (reportData.d1 && reportData.d1.problemDesc && reportData.d1.problemDesc.trim());

  if (!hasContent) {
    card.style.display = 'none';
    body.innerHTML = '';
    return;
  }

  card.style.display = 'block';

  const badgeDone = (isLatest) => isLatest
    ? `<span style="font-size:11px; padding:1px 6px; border-radius:4px; background:#16a34a; color:#ffffff; font-weight:700; margin-left:6px;">剛更新</span>`
    : `<span style="font-size:11px; padding:1px 6px; border-radius:4px; background:#dcfce7; color:#166534; font-weight:600; margin-left:6px;">已填寫</span>`;
  const badgePending = `<span style="font-size:11px; padding:1px 6px; border-radius:4px; background:#fef3c7; color:#92400e; font-weight:600; margin-left:6px;">待補充</span>`;

  const renderVal = (val, fieldKey) => {
    const isLatest = lastSupplementedInfo.field === fieldKey;
    if (val && String(val).trim()) {
      return `<span style="color:var(--text-main); font-weight:${isLatest ? '700' : '500'};">${escapeHtml(val)}</span>${badgeDone(isLatest)}`;
    }
    return `<span style="color:#94a3b8;">（尚未補充）</span>${badgePending}`;
  };

  const d2Text = Array.isArray(reportData.d2?.containmentActions)
    ? reportData.d2.containmentActions.map(a => a && a.action ? a.action.trim() : '').filter(Boolean).join('；')
    : '';
  const d3ChainText = Array.isArray(reportData.d3?.whyMadeChain)
    ? reportData.d3.whyMadeChain.map(w => w ? (w.answer || w.question || '').trim() : '').filter(Boolean).join(' → ')
    : '';
  const d3Text = d3ChainText || (reportData.d3?.rootCauseSummary || '');
  const d4Text = Array.isArray(reportData.d4?.correctiveActions)
    ? reportData.d4.correctiveActions.map(c => c && c.action ? c.action.trim() : '').filter(Boolean).join('；')
    : '';
  const d5Text = Array.isArray(reportData.d5?.standardDocs)
    ? reportData.d5.standardDocs.map(d => d && d.docName ? d.docName.trim() : '').filter(Boolean).join('；')
    : '';

  const latestBanner = lastSupplementedInfo.value ? `
    <div style="margin-bottom: 10px; padding: 8px 12px; border-radius: 6px; background-color: #dcfce7; border: 1px solid #86efac; color: #14532d; font-size: 13px; display: flex; justify-content: space-between; align-items: center;">
      <div>
        <strong>最新補充已寫入報告：</strong>【${escapeHtml(lastSupplementedInfo.label)}】 → 「${escapeHtml(lastSupplementedInfo.value)}」
      </div>
      <span style="font-size: 11px; color: #166534; font-weight: 700;">即時同步完成</span>
    </div>
  ` : '';

  body.innerHTML = `
    ${latestBanner}
    <div style="font-size: 13px; font-weight: 700; color: var(--primary); margin-bottom: 8px;">
      報告主題：${escapeHtml(reportData.title || '未命名事件')}
      ${reportData.partName ? `<span style="font-weight:normal; color:var(--text-muted); margin-left:10px;">（涉及物品/事項：${escapeHtml(reportData.partName)}）</span>` : ''}
    </div>
    <table class="data-table" style="font-size: 12.5px; margin-bottom: 0;">
      <tbody>
        <tr>
          <th style="width: 145px; cursor:pointer;" onclick="switchToTab('tab-d1')" title="點擊前往 D1 分頁">D1 誰與何時</th>
          <td>
            <div><strong>主角：</strong>${escapeHtml(reportData.d1?.who || '-')}</div>
            <div style="margin-top:2px;"><strong>時間：</strong>${renderVal(reportData.d1?.when || reportData.lotNumber, 'd1.when')}</div>
          </td>
          <th style="width: 145px; cursor:pointer;" onclick="switchToTab('tab-d1')" title="點擊前往 D1 分頁">D1 地點與發現</th>
          <td>
            <div><strong>地點：</strong>${renderVal(reportData.d1?.where || reportData.customerLine, 'd1.where')}</div>
            <div style="margin-top:2px;"><strong>如何發現：</strong>${renderVal(reportData.d1?.how, 'd1.how')}</div>
          </td>
        </tr>
        <tr>
          <th style="cursor:pointer;" onclick="switchToTab('tab-d1')">D1 違反約定</th>
          <td>${renderVal(reportData.d1?.why, 'd1.why')}</td>
          <th style="cursor:pointer;" onclick="switchToTab('tab-d1')">D1 造成影響</th>
          <td>${renderVal(reportData.d1?.impactScope, 'd1.impactScope')}</td>
        </tr>
        <tr>
          <th style="cursor:pointer;" onclick="switchToTab('tab-d2')">D2 當下緊急處置</th>
          <td colspan="3">${renderVal(d2Text, 'd2.action')}</td>
        </tr>
        <tr>
          <th style="cursor:pointer;" onclick="switchToTab('tab-d3')">D3 為什麼會這樣</th>
          <td colspan="3">${renderVal(d3Text, 'd3.why')}</td>
        </tr>
        <tr>
          <th style="cursor:pointer;" onclick="switchToTab('tab-d4')">D4 以後怎麼改善</th>
          <td colspan="3">${renderVal(d4Text, 'd4.action')}</td>
        </tr>
        <tr>
          <th style="cursor:pointer;" onclick="switchToTab('tab-d5')">D5 訂立生活約定</th>
          <td colspan="3">${renderVal(d5Text, 'd5.doc')}</td>
        </tr>
      </tbody>
    </table>
  `;
}

// 本機離線語意萃取引擎
function parseRawTextTo5D(text) {
  applyAppMode();
  selectedQuestionIndex = 0;
  lastSupplementedInfo = { label: '', value: '', field: '' };

  // 1. 若完全為預設玩偶範例文本（例如點擊了「帶入生活案例文字」）
  const isSampleDollText = text.includes('房間床上的玩偶') && text.includes('帶去學校展示');
  if (isSampleDollText) {
    if (window.SAMPLE_LIFE_5D) {
      reportData = normalizeReportData(JSON.parse(JSON.stringify(window.SAMPLE_LIFE_5D)));
    }
    populateFormFromData();
    renderAllDynamicFields();
    updateAuditAndScore();
    renderLivePreview();
    saveAutoDraft();
    showToast('生活案例 5D 分析拆解完成！', 'success');
    generateClarificationQuestions();
    return;
  }

  // 2. 自定義生活文字：重置前次事件分析之專屬資料，徹底杜絕前次範本或殘留資料污染
  reportData.title = '';
  reportData.partName = '';
  reportData.partNumber = '';
  reportData.customerLine = '';
  reportData.lotNumber = '';
  reportData.machineNumber = '';
  reportData.severity = '重大影響（違反約定、擅自拿取或信任破壞）';
  reportData.owner = '家長 / 調解負責人';
  reportData.approver = '全體家庭成員審核';
  reportData.targetCloseDate = reportData.targetCloseDate || getDefaultTargetDate(reportData.dateCreated, 7);

  reportData.d1 = {
    problemDesc: text.trim(),
    who: '',
    when: '',
    where: '',
    what: '',
    why: '',
    how: '',
    howMany: '',
    defectRate: '',
    impactScope: ''
  };
  reportData.d2 = {
    factoryStock: '',
    transitStock: '',
    customerStock: '',
    containmentActions: [],
    containmentVerification: ''
  };
  reportData.d3 = {
    whyMadeChain: [],
    whyEscapedChain: [],
    rootCauseSummary: ''
  };
  reportData.d4 = {
    correctiveActions: [],
    beforeMetric: '',
    afterMetric: '',
    validationConclusion: ''
  };
  reportData.d5 = {
    standardDocs: [],
    horizontalDeployment: [],
    signOff: {
      qaComment: '',
      qaStatus: '觀察改善中',
      signDate: reportData.dateCreated || new Date().toISOString().slice(0, 10)
    }
  };

  // 3. 忠實萃取文字中客觀存在之實體（人、事、時、地、物與使用者在文字中已寫出之原因/處置/改善）
  // (A) 人物識別（支援擴充稱謂詞庫與「小X / 阿X」常見小名動態捕捉，並依原文出現順序排序）
  const matchedActors = [];
  const knownNames = [
    '小豬弟弟', '小雞姊姊', '體育股長', '風紀股長', '衛生股長', '學藝股長', '副班長',
    '班長阿明', '班長', '股長', '大毛', '小強', '小華', '小明', '小美', '小芳', '小杰', '小凱', '小豬',
    '阿哲', '阿豪', '阿凱', '阿明', '阿志', '阿宏',
    '表哥', '表姊', '表姐', '表弟', '表妹', '堂哥', '堂姊', '堂姐', '堂弟', '堂妹',
    '哥哥', '姊姊', '姐姐', '弟弟', '妹妹', '孫子', '孫女', '兒子', '女兒',
    '外公', '外婆', '阿公', '阿嬤', '爺爺', '奶奶', '媽媽', '爸爸', '母親', '父親',
    '家長', '家人', '長輩', '大人', '導師', '老師', '教練', '主任', '校長',
    '學長', '學姊', '學姐', '學弟', '學妹', '室友', '同桌', '隊友', '同學', '朋友'
  ];
  knownNames.sort((a, b) => b.length - a.length);
  for (const name of knownNames) {
    const pos = text.indexOf(name);
    if (pos !== -1) {
      const alreadyCovered = matchedActors.some(existing => existing.name.includes(name) || name.includes(existing.name));
      if (!alreadyCovered) {
        matchedActors.push({ name, pos });
      }
    }
  }
  // 動態補足「小X / 阿X」小名（排除常見非人名詞彙）
  const nickBlacklist = new Set([
    '小心', '小時', '小狗', '小貓', '小鳥', '小魚', '小兔', '小偷', '小費', '小考',
    '小菜', '小隊', '小組', '小學', '小腿', '小手', '小聲', '小事', '小看', '小氣',
    '小北', '小七', '小號', '小題', '小節', '小說', '阿姨', '阿伯', '阿叔'
  ]);
  const nickRegex = /(?:小|阿)[\u4e00-\u9fa5]/g;
  let nickMatch;
  while ((nickMatch = nickRegex.exec(text)) !== null) {
    const candidate = nickMatch[0];
    if (!nickBlacklist.has(candidate)) {
      const alreadyCovered = matchedActors.some(existing => existing.name.includes(candidate) || candidate.includes(existing.name));
      if (!alreadyCovered) {
        matchedActors.push({ name: candidate, pos: nickMatch.index });
      }
    }
  }
  matchedActors.sort((a, b) => a.pos - b.pos);
  const whoList = matchedActors.map(item => item.name);
  const whoActor = whoList[0] || '當事人';
  const whoAffected = whoList.slice(1).join('、');
  reportData.d1.who = `行為人：${whoActor}${whoAffected ? `；關係人/受影響人：${whoAffected}` : ''}`;

  // (B) 物品/載具識別
  const itemMatch = text.match(/(Switch電動|Switch|PS5|iPad|智慧手錶|手機遊戲點數卡|遊戲點數卡|點數卡|信用卡|手機|平板|電腦|筆電|遊戲機|耳機|充電線|充電器|遙控器|電視|冷氣|戶外教學通知單|通知單|准考證|學生證|悠遊卡|考卷|成績單|聯絡簿|數學習作|國語習作|自然習作|英文習作|習作|作業簿|參考書|講義|課本|字典|漫畫書|漫畫|故事書|小說|圖書|書本|直笛|美術用具|水彩筆|水彩|專業彩色筆|彩色筆|馬克筆|色鉛筆|原子筆|自動鉛筆|鉛筆盒|橡皮擦|剪刀|美工刀|圓規|尺|膠水|修正帶|文具|紙條|海報|黑板|收藏卡牌|寶可夢卡牌|寶可夢卡|遊戲王卡|卡牌|樂高積木|積木|模型|桌遊|棋子|拼圖|玩偶|娃娃|玩具|貼紙|史萊姆|口紅|香水|化妝品|籃球|躲避球|羽球拍|球拍|足球|排球|直排輪|滑板|自行車|腳踏車|單車|安全帽|護目鏡|滴管|實驗器材|撲滿|壓歲錢|零用錢|早餐錢|午餐錢|生活費|班費|補習費|找零|發票|鈔票|硬幣|[0-9]+元|保溫瓶|水壺|便當盒|餐具|碗盤|玻璃杯|馬克杯|杯子|吹風機|濕毛巾|毛巾|浴巾|床單|地毯|花盆|眼鏡|手錶|鑰匙|雨傘|外套|制服|運動服|球鞋|鞋子|臭襪子|襪子|書包|垃圾車|垃圾袋|垃圾|廚餘|飼料|泡麵|零食|辣條|糖果|巧克力|餅乾|炸雞|薯條|冰淇淋|布丁|蛋糕|草莓|珍珠奶茶|奶茶|汽水|可樂|果汁|牛奶|飲料|私人物品)/);
  if (itemMatch) {
    reportData.partName = itemMatch[0];
    reportData.machineNumber = itemMatch[0];
  }

  // (C) 時間時段識別
  let extractedWhen = '';
  const nightMatch = text.match(/(?:晚上|傍晚|凌晨|清晨|半夜)\s*[0-9\uFF10-\uFF19]+(?:\s*點(?:[0-9\uFF10-\uFF19]+分|半)?|\s*:\s*[0-9]+)/);
  if ((text.includes('下課後') || text.includes('下課')) && nightMatch) {
    extractedWhen = (text.includes('今天') ? '今天' : (text.includes('昨天') ? '昨天' : '')) + `下課後至${nightMatch[0]}`;
  } else if ((text.includes('放學後') || text.includes('放學')) && nightMatch) {
    extractedWhen = (text.includes('今天') ? '今天' : (text.includes('昨天') ? '昨天' : '')) + `放學後至${nightMatch[0]}`;
  } else if (text.match(/(?:昨天|昨晚).*(?:清晨|凌晨|半夜)\s*[0-9\uFF10-\uFF19]+\s*點/)) {
    const morningH = text.match(/(?:清晨|凌晨|半夜)\s*[0-9\uFF10-\uFF19]+\s*點(?:[0-9\uFF10-\uFF19]+分|半)?/)[0];
    extractedWhen = `昨天夜間至${morningH}` + (text.includes('今天早上') ? '、今天早上' : (text.includes('今天早自習') ? '、今天早自習' : ''));
  } else {
    const compoundTimeMatch = text.match(/((?:上禮拜[一二三四五六日天]|上週[一二三四五六日天]|這禮拜[一二三四五六日天]|這週[一二三四五六日天]|禮拜[一二三四五六日天]|週[一二三四五六日天]|週末|假日|[0-9]{1,2}月[0-9]{1,2}[日號]|[0-9]{1,2}\/[0-9]{1,2}|今天|昨天|昨日|昨晚|前天|今早|這禮拜|這個禮拜|上禮拜|這週|上週|這個月|上個月|最近每天|每天|平日)\s*(?:早上|早晨|早自習|上午|中午|午休|下午|傍晚|晚上|夜間|半夜|深夜|清晨|凌晨|睡前|放學回家後|放學後|放學|下課後|下課|社團活動結束後)?\s*(?:[0-9\uFF10-\uFF19]+點(?:[0-9\uFF10-\uFF19]+分|半)?)?)/);
    if (compoundTimeMatch && compoundTimeMatch[0].trim()) {
      extractedWhen = compoundTimeMatch[0].trim();
    } else {
      const simpleTimeMatch = text.match(/(今天美術課|美術課|歷史課|體育課|音樂課|實驗課時|實驗課|游泳課|電腦課|早自習|午休|社團活動結束後|放學回家後|放學後|下課後|下課時|上課時|清晨\s*[0-9\uFF10-\uFF19]+\s*點|凌晨\s*[0-9\uFF10-\uFF19]+\s*點|半夜\s*[0-9\uFF10-\uFF19]+\s*點|晚上\s*[0-9\uFF10-\uFF19]+\s*點|傍晚\s*[0-9\uFF10-\uFF19]+\s*點|晚上八點|晚上|傍晚|下午|中午|早上|連續[一二三四五六七兩0-9]+天|冬天洗澡時|洗澡時)/);
      if (simpleTimeMatch) extractedWhen = simpleTimeMatch[0].trim();
    }
  }
  if (extractedWhen) {
    reportData.lotNumber = extractedWhen;
    reportData.d1.when = extractedWhen;
  }

  // (D) 場所場域識別
  const placeMatch = text.match(/(學校美術課|學校教室|歷史課教室|實驗室|實驗課|體育課|美術課|音樂課|操場司令台旁邊|操場司令台|操場|走廊|樓梯間|福利社|合作社|圖書館|體育館|游泳池|保健室|學務處|教務處|校門口|安親班門口|安親班|補習班|幼兒園|宿舍寢室|宿舍|寢室|同學家|鄰居家|親戚家|阿嬤家|外婆家|河濱公園|公園|籃球場|羽球場|球場|網咖|電玩店|超商|便利商店|百貨公司|大賣場|超市|文具店|書店|玩具店|夜市|餐廳|速食店|早餐店|公車上|捷運上|後座車上|車上|過馬路時|過馬路|馬路口|路口|馬路|路上|客廳沙發|客廳餐桌|客廳|房間床上|房間書桌|房間|個人臥室|臥室|棉被裡|床上|書房|書桌上|書桌|餐桌|廚房|冰箱|浴室|澡堂|廁所|洗手台|玄關|陽台|院子|水溝|學校|校外|家裡|家中|班上|教室)/);
  if (placeMatch) {
    const cleanPlace = placeMatch[0] === '過馬路時' ? '馬路' : placeMatch[0];
    reportData.customerLine = cleanPlace;
    reportData.d1.where = cleanPlace;
  }

  // (E) 事實陳述 What
  reportData.d1.what = text.trim();

  // (F) 直接後果/影響識別
  const impactMatch = text.match(/(?:造成|導致|使得|引起|結果造成|結果導致|害得|害(?![怕羞])[\u4e00-\u9fa5]+|影響)[^，。；.\n]+/);
  if (impactMatch) {
    reportData.d1.impactScope = impactMatch[0].trim();
  }

  // (G) 若使用者在文字框內已一併寫出違反規定、發現過程、當下處置、原因、改善或公約，亦忠實萃取
  const whyRuleMatch = text.match(/(違反[^，。；.\n]+|未遵守[^，。；.\n]+)/);
  if (whyRuleMatch) {
    reportData.d1.why = whyRuleMatch[0].trim();
  }
  const howMatch = text.match(/([^，。；.\n]*(?:叫不醒|詢問時|打電話通知|致電家長|巡堂時|檢查時|點名時|抽查時|聽見|聽到|看到|撞見|聞到|發現時|才發現|被發現|發現|抓到|察覺|通報|當場沒收|當場制止)[^，。；.\n]*)/);
  if (howMatch) {
    reportData.d1.how = howMatch[0].trim();
  }
  const d2Match = text.match(/(?:當下|立刻|馬上|第一時間|緊急處置是|緊急處理)[：:為是]?([^，。；.\n]+)/);
  if (d2Match) {
    applyFieldUpdateSilent('d2.action', d2Match[1].trim());
  }
  const d3Match = text.match(/(?:因為|原因是|真正原因是|由於)[：:為是]?([^，。；.\n]+)/);
  if (d3Match) {
    applyFieldUpdateSilent('d3.why', d3Match[1].trim());
  }
  const d4Match = text.match(/(?:以後決定|以後要|改善行動是|改善方式為|接下來要)[：:為是]?([^，。；.\n]+)/);
  if (d4Match) {
    applyFieldUpdateSilent('d4.action', d4Match[1].trim());
  }
  const d5Match = text.match(/(?:訂立公約|生活公約是|共同約定是|訂下家規)[：:為是]?([^，。；.\n]+)/);
  if (d5Match) {
    applyFieldUpdateSilent('d5.doc', d5Match[1].trim());
  }

  // (H) 動態標題組裝
  if (text.match(/([0-9]+元|早餐錢|零用錢|壓歲錢|生活費|班費|點數卡|儲值|課金|借錢|請客|找零)/)) {
    reportData.title = `${whoActor}金錢使用與消費自律事件分析`;
  } else if (text.match(/(過馬路|紅綠燈|闖紅燈|安全帽|騎單車|騎腳踏車|摔車|走廊奔跑|護目鏡|實驗室|一氧化碳|浴室窗戶|辣條|汽水|蛀牙)/)) {
    reportData.title = `${whoActor}日常安全與健康飲食常規事件分析`;
  } else if (text.match(/(倒垃圾|垃圾車|廚餘|臭襪子|洗衣籃|洗碗|做家事|打掃|整理|雜物|長螞蟻|發霉|忘記餵|洗澡|濕毛巾)/)) {
    reportData.title = `${whoActor}家務分工與個人環境衛生習慣事件分析`;
  } else if (text.match(/(手機|平板|Switch|電動|電腦|筆電|熬夜|清晨|凌晨|遲到|起不來|打瞌睡)/)) {
    reportData.title = `${whoActor}數位設備使用與睡眠作息事件分析`;
  } else if (text.match(/(出去玩|晚歸|未通知|沒告知|失聯|找不到人|網咖|百貨公司|河濱公園)/)) {
    reportData.title = `${whoActor}課後外出晚歸未報備事件分析`;
  } else if (text.match(/(作業|功課|聯絡簿|習作|考卷|缺交|沒寫|代簽|隱瞞|忘記帶|傳紙條|通知單)/)) {
    reportData.title = `${whoActor}課業學習與誠信常規事件分析`;
  } else if (text.match(/(彩色筆|筆記本|文具|水壺|保溫瓶|漫畫書|卡牌|籃球|擅自|借用|弄壞|弄髒|摔斷)/)) {
    reportData.title = `${whoActor}物品借用與尊重他人界限事件分析`;
  } else if (text.match(/(遙控器|電視|搶奪|爭吵|吵架|打架|口角|推擠|吃醋|說壞話)/)) {
    reportData.title = `${whoActor}手足與同儕人際互動衝突事件分析`;
  } else {
    reportData.title = `${whoActor}日常生活常規事件分析`;
  }

  // 4. 更新介面
  populateFormFromData();
  renderAllDynamicFields();
  updateAuditAndScore();
  renderLivePreview();
  saveAutoDraft();

  showToast('事件事實萃取完成！請查看下方即時看板與待補充項目。', 'info');
  generateClarificationQuestions();
}

// 產生智慧缺漏診斷與引導對話
function generateClarificationQuestions() {
  const container = document.getElementById('interview-chat-container');
  const badge = document.getElementById('interview-status-badge');
  const replyBox = document.getElementById('interview-reply-box');
  if (!container) return;

  // 同步更新第一步頁面上方的「目前已整理的 5D 報告即時看板」
  renderLive5DSummary();

  const hasContent = (reportData.title && reportData.title.trim()) || 
                     (reportData.d1 && reportData.d1.problemDesc && reportData.d1.problemDesc.trim());

  if (!hasContent) {
    if (badge) {
      badge.textContent = '等待輸入事件';
      badge.style.backgroundColor = 'var(--bg-subtle)';
      badge.style.color = 'var(--text-muted)';
    }
    container.innerHTML = `
      <div style="color: var(--text-muted); font-size: 13px; text-align: center; padding: 20px 12px; line-height: 1.6;">
        請在上方輸入框描述生活事件，或點擊右上角「載入生活實例」；小幫手將協助進行 5D 結構化拆解並提供具體建議。
      </div>
    `;
    if (replyBox) replyBox.style.display = 'none';
    currentPendingQuestions = [];
    return;
  }

  // 偵測當前事件主題，以提供精準的生活化建議值（涵蓋 8 大核心生活領域，絕不出現無關案例之寫死內容）
  const desc = (reportData.d1?.problemDesc || '') + ' ' + (reportData.title || '');
  const isMoneySpend = !!desc.match(/([0-9]+元|早餐錢|午餐錢|零用錢|壓歲錢|生活費|班費|補習費|找零|點數卡|儲值|課金|借錢|還錢|請客|偷買|亂買|花光)/);
  const isSafetyHealth = !isMoneySpend && !!desc.match(/(過馬路|紅綠燈|紅燈|安全帽|騎單車|騎腳踏車|自行車|下坡|摔車|奔跑|樓梯|階梯|扭傷|滑倒|擦傷|流血|護目鏡|滴管|實驗課|實驗室|一氧化碳|浴室窗戶|通風|辣條|汽水|炸雞|泡麵|零食|挑食|蛀牙|牙醫|肚子痛)/);
  const isChoreHygiene = !isMoneySpend && !isSafetyHealth && !!desc.match(/(倒垃圾|垃圾車|垃圾|廚餘|臭襪子|洗衣籃|洗碗|水槽|沒洗|發臭|值日生|擦黑板|做家事|家務|打掃|整理|雜物|長螞蟻|發霉|餵|飼料|柴犬|小狗|小貓|寵物|洗澡|吹風機|濕毛巾|剪紙碎屑)/);
  const isRoutineSleep = !isMoneySpend && !isSafetyHealth && !isChoreHygiene && !!desc.match(/(手機|平板|Switch|電動|電腦|筆電|遊戲|直播|看電視|熬夜|清晨|凌晨|起不來|睡過頭|遲到|睡眠|半夜|打瞌睡)/);
  const isOutingLate = !isMoneySpend && !isSafetyHealth && !isChoreHygiene && !isRoutineSleep && !!desc.match(/(出去玩|去玩|外出|晚歸|未通知|沒告知|沒說|詢問時才|沒回家|未歸|失聯|找不到人|網咖|百貨公司|文具店|河濱公園|逗留)/);
  const isStudyHomework = !isMoneySpend && !isSafetyHealth && !isChoreHygiene && !isRoutineSleep && !isOutingLate && !!desc.match(/(作業|功課|聯絡簿|習作|考卷|成績單|未交|缺交|沒寫|代簽|隱瞞|作弊|偷看|傳紙條|忘記帶|直笛|美術用具|通知單)/);
  const isItemConflict = !isMoneySpend && !isSafetyHealth && !isChoreHygiene && !isRoutineSleep && !isOutingLate && !isStudyHomework && !!desc.match(/(彩色筆|筆記本|文具|水壺|保溫瓶|漫畫書|卡牌|玩偶|玩具|籃球|手錶|眼鏡|橡皮擦|私人物品|擅自|沒經過同意|未經同意|借來|摔斷|損壞|弄壞|弄髒|弄丟|踢進水溝)/);
  const isSiblingConflict = !isMoneySpend && !isSafetyHealth && !isChoreHygiene && !isRoutineSleep && !isOutingLate && !isStudyHomework && !isItemConflict && !!desc.match(/(遙控器|電視|搶走|搶奪|互推|推擠|吵架|爭吵|口角|打架|手足|吃醋|說壞話|不理對方|大吵大鬧|踢對方)/);

  // 根據領域準備建議值
  let suggWhy = '違反日常生活常規、個人自律或生活共同約定';
  let suggHow = '相關人員在現場發現異常或主動詢問後得知事件經過';
  let suggImpact = '造成生活常規受擾、信任感減損，生活秩序受到影響';
  let suggWhere = '家庭生活空間 / 日常環境';
  let suggWhen = '事發當日時段';
  let suggD2 = '暫停當下不當行為，雙方先喝口水冷靜 10 分鐘，確認現場安全';
  let suggD3 = '當下一時受情緒或誘惑驅使心存僥倖，未能深思行為後果';
  let suggD4 = '當面向受影響的成員誠懇鞠躬致歉，並承擔一項家務作為反省補償';
  let suggD5 = '個人日常生活自律與行為常規共同守則公約';

  if (isMoneySpend) {
    suggWhy = '違反「專款專用、誠實記帳、未經家長同意不得私自儲值或借貸金錢」之家庭理財約定';
    suggHow = '家長核對發票明細、零用錢餘額或接獲師長同學反映後察覺金錢流向異常';
    suggImpact = '造成個人正餐營養與生活費短缺、同儕金錢糾紛，並嚴重損及家庭財務信任';
    suggWhere = '超商門市 / 學校福利社 / 家中';
    suggWhen = '本週日常消費時段';
    suggD2 = '立即盤點剩餘金額與發票收據，若有向他人借錢或欠款則由家長陪同先行歸還結清';
    suggD3 = '受遊戲點數或零食玩具誘惑一時衝動消費，缺乏預算規劃概念且心存僥倖隱瞞';
    suggD4 = '準備個人零用錢記帳本每日睡前與家長核對收支，並透過分擔家務勞動償還透支金額';
    suggD5 = '家庭零用錢記帳管理與誠實消費生活公約';
  } else if (isSafetyHealth) {
    suggWhy = '違反「遵守交通與場所安全守則、愛惜身體健康與均衡飲食」之安全健康規範';
    suggHow = '師長或家人在現場巡視、目擊危險動作，或因身體不適就醫檢查時發現';
    suggImpact = '造成人身跌倒受傷或健康受損風險，亦讓家人與師長極度擔憂人身安全';
    suggWhere = '上下學馬路 / 校園走廊操場 / 家中';
    suggWhen = '事發當日活動時段';
    suggD2 = '立即停止危險行為並檢查身體有無外傷或擦傷，必要時先進行簡易包紮或就醫檢查';
    suggD3 = '當下貪圖一時好玩耍帥或口腹之慾，低估環境潛在危險性且忽略安全防護規範';
    suggD4 = '出門與上課前確實穿戴安全防護裝備，減少購買高糖高油零食並由家人每日關心檢視';
    suggD5 = '日常交通安全防護與健康飲食作息生活公約';
  } else if (isChoreHygiene) {
    suggWhy = '違反「按時完成個人負責家務、保持環境整潔與良好衛生習慣」之家庭分工約定';
    suggHow = '家人返家巡視環境發現髒亂異味、物品散落或寵物未獲照料而察覺';
    suggImpact = '造成居家環境髒亂滋生蚊蟲異味、找尋物品耗時延誤作息，並增加其他家人負擔';
    suggWhere = '家中客廳 / 個人房間書桌 / 廚房';
    suggWhen = '日常放學後與晚間家務時段';
    suggD2 = '立即放下手邊娛樂活動，馬上將散落物品歸位、清理垃圾廚餘或補齊照料工作';
    suggD3 = '回家後只想先放鬆看電視或玩樂，抱持「等一下再收也沒關係」的拖延心態導致遺忘';
    suggD4 = '在房間與客廳張貼「每日家務與睡前整潔打勾表」，先完成家務與整理才能進行休閒活動';
    suggD5 = '家庭家務分工責任與個人環境衛生整潔生活公約';
  } else if (isRoutineSleep) {
    suggWhy = '違反「夜間就寢前定時收納手機與數位設備、保障充足睡眠與準時就學」之作息常規';
    suggHow = '到了早晨預定出門時間呼叫未醒或課堂精神不濟，詢問後始察覺夜間熬夜使用設備';
    suggImpact = '造成晨間起不來上學遲到、日間課堂精神不濟打瞌睡，並打亂全家早晨出門作息';
    suggWhere = '家中個人臥室 / 學校教室';
    suggWhen = '昨天夜間至今日清晨';
    suggD2 = '家長協助當事人快速清醒整裝，數位設備暫時由長輩集中保管避免繼續沉迷分心';
    suggD3 = '遊戲關卡與影音娛樂誘惑過大，缺乏時間自律感知，心想再玩一下造成嚴重拖延';
    suggD4 = '在客廳設置「家庭數位設備專屬充電區」，睡前 30 分鐘統一將手機與遊戲機放客廳充電';
    suggD5 = '家庭健康睡眠作息與夜間 3C 設備定時收納生活公約';
  } else if (isOutingLate) {
    suggWhy = '違反「放學外出遊玩或行程變更必須第一時間向家人報備」的家庭安全約定';
    suggHow = '到了常態放學返家時間未見蹤影，家人主動電話聯繫或詢問導師同學才獲知動向';
    suggImpact = '造成家人極度擔憂人身安全與恐慌，嚴重破壞家庭對其自主時間管理之信任';
    suggWhere = '學校下課後校外場所 / 返家途中';
    suggWhen = '放學下課後至晚間時段';
    suggD2 = '家人立即透過電話確認當事人平安與所在位置，要求停止逗留並立刻平安返家';
    suggD3 = '放學當下急著與同學去玩或逛街，心存僥倖以為晚一點回家大人不會發現';
    suggD4 = '養成行程變更前必須先親口或傳訊息報備的鐵律習慣，並隨身確認手機電量充足';
    suggD5 = '家庭放學課後行程報備與準時返家安全生活公約';
  } else if (isStudyHomework) {
    suggWhy = '違反「每日誠實完成指定作業、備妥學用品並由家長親自簽名」之誠信學習約定';
    suggHow = '學校老師課堂檢查、批改考卷或致電家長查證時發現異常狀況';
    suggImpact = '造成課業進度延宕脫節、形成拖延逃避不良習慣，並損及家庭與師長之信任';
    suggWhere = '家中書桌 / 學校教室';
    suggWhen = '平日放學後與學校課堂時段';
    suggD2 = '家長與學生共同清點缺漏作業或通知單，排定專注時段在家長陪伴下完成補寫與訂正';
    suggD3 = '課業遇到難題或貪玩分心，害怕被責怪或處罰，心存僥倖想要敷衍逃避隱瞞';
    suggD4 = '建立「遇到不懂主動發問、睡前依課表檢查書包」之習慣，書桌前張貼每日學習檢查卡';
    suggD5 = '每日課業誠實完成與睡前書包清點生活常規公約';
  } else if (isItemConflict) {
    suggWhy = '違反「非經所有人明確同意，不可擅自拿取他人私人物品，借用物品應妥善愛惜」之規範';
    suggHow = '物主發現物品遺失或受損並提出抗議，由師長或長輩介入了解實情';
    suggImpact = '造成物主心愛物品損壞與強烈不安全感，手足或同儕間互信關係受損';
    suggWhere = '學校教室 / 家中房間';
    suggWhen = '事發當日時段';
    suggD2 = '立即停止使用並將物品清理乾淨雙手歸還，由長輩陪同確認受損狀況並安撫物主情緒';
    suggD3 = '當下自己想玩或缺少工具圖一時方便，抱持「拿一下不會弄壞或不會被發現」之僥倖心態';
    suggD4 = '當面向物主正式鞠躬致歉，並以個人零用錢或勞動服務購置同規格全新物品賠償';
    suggD5 = '校園與家庭個人私人物品借用尊重與愛惜公物公約';
  } else if (isSiblingConflict) {
    suggWhy = '違反「公共資源排隊輪流、理性溝通表達，嚴禁爭搶推擠與言語攻擊」之人際相處公約';
    suggHow = '現場發出劇烈爭吵哭鬧聲響或同學通報，長輩與師長立即趕至現場制止';
    suggImpact = '破壞家庭與班級和諧氣氛，肢體推擠或言語衝突極易造成身心受傷';
    suggWhere = '家中客廳 / 學校活動場所';
    suggWhen = '事發當日互動時段';
    suggD2 = '立即暫停爭執活動並將雙方分開冷靜 15 分鐘，待情緒平復後再進行雙向溝通';
    suggD3 = '當下急於滿足個人需求缺乏同理心與耐心，直覺以爭搶或情緒言語作為解決手段';
    suggD4 = '雙方互相誠懇道歉握手言和，並使用計時器或猜拳輪流機制決定優先順序';
    suggD5 = '家庭與同儕理性溝通、輪流分享與情緒冷靜生活公約';
  }

  // 診斷所有缺漏資訊
  const questions = [];

  // 1. D1 基本事實缺口
  if (!reportData.lotNumber || !reportData.d1?.when) {
    questions.push({
      field: 'd1.when',
      category: 'D1 基本時段',
      title: '【第 1 步】發生的具體時段尚未填寫',
      q: '請問這件事情發生的具體時間是在何時？（例如：昨天晚上、今天早上出門前）',
      quickVal: suggWhen
    });
  }

  if (!reportData.customerLine || !reportData.d1?.where) {
    questions.push({
      field: 'd1.where',
      category: 'D1 事發場所',
      title: '【第 1 步】事發的地點或場合尚未填寫',
      q: '請問這件事情主要發生在什麼場所？（例如：家中房間、客廳、學校教室、放學路上）',
      quickVal: suggWhere
    });
  }

  if (!reportData.d1?.why || reportData.d1.why.trim() === '') {
    questions.push({
      field: 'd1.why',
      category: 'D1 約定規範',
      title: '【第 1 步】違反的規矩或生活約定待補充',
      q: '這項行為主要違反了什麼家庭規矩、生活常規或原本的約定？',
      quickVal: suggWhy
    });
  }

  if (!reportData.d1?.how || reportData.d1.how.trim() === '') {
    questions.push({
      field: 'd1.how',
      category: 'D1 察覺過程',
      title: '【第 1 步】事情是怎麼被發現的待補充',
      q: '這件事情是怎麼被察覺或發現的？（例如：早晨叫不醒、老師打電話通知、家人主動詢問）',
      quickVal: suggHow
    });
  }

  if (!reportData.d1?.impactScope || reportData.d1.impactScope.trim() === '') {
    questions.push({
      field: 'd1.impactScope',
      category: 'D1 影響後果',
      title: '【第 1 步】對大家心情或作息造成的影響待補充',
      q: '這件事對相關成員的心情、生活秩序或信任帶來了哪些具體影響或後果？',
      quickVal: suggImpact
    });
  }

  // 2. D2 當下緊急處置缺口（檢查是否至少有一筆非空白之實際處置內容）
  const hasValidD2 = Array.isArray(reportData.d2?.containmentActions) &&
    reportData.d2.containmentActions.some(a => a && a.action && a.action.trim().length > 0);
  if (!hasValidD2) {
    questions.push({
      field: 'd2.action',
      category: 'D2 當下應變',
      title: '【第 2 步】當下緊急處置尚未填寫',
      q: '事情發生的第一時間，大家採取了什麼緊急處置或應變作為？（例如：快速整裝送上學、暫時保管設備、雙方先分開冷靜等）',
      quickVal: suggD2
    });
  }

  // 3. D3 根本原因分析缺口（檢查是否至少有一層非空白之原因或提問）
  const hasValidD3 = Array.isArray(reportData.d3?.whyMadeChain) &&
    reportData.d3.whyMadeChain.some(w => w && ((w.answer && w.answer.trim().length > 0) || (w.question && w.question.trim().length > 0)));
  if (!hasValidD3) {
    questions.push({
      field: 'd3.why',
      category: 'D3 根本原因',
      title: '【第 3 步】深層原因 5 Why 尚未探討',
      q: '想一想：為什麼當初會做出這項行為？背後深層的心態或原因是什麼？（連問為什麼找出心裡真正的想法）',
      quickVal: suggD3
    });
  }

  // 4. D4 未來改善行動缺口（檢查是否至少有一筆非空白之改善作法）
  const hasValidD4 = Array.isArray(reportData.d4?.correctiveActions) &&
    reportData.d4.correctiveActions.some(c => c && c.action && c.action.trim().length > 0);
  if (!hasValidD4) {
    questions.push({
      field: 'd4.action',
      category: 'D4 改善行動',
      title: '【第 4 步】未來改善好方法尚未規劃',
      q: '接下來打算採取什麼具體改善對策？（例如：誠意致歉、實質補償、習慣調整、環境提醒標籤等）',
      quickVal: suggD4
    });
  }

  // 5. D5 防止再發公約缺口（檢查是否至少有一筆非空白之公約名稱）
  const hasValidD5 = Array.isArray(reportData.d5?.standardDocs) &&
    reportData.d5.standardDocs.some(d => d && d.docName && d.docName.trim().length > 0);
  if (!hasValidD5) {
    questions.push({
      field: 'd5.doc',
      category: 'D5 生活公約',
      title: '【第 5 步】防止再次發生的生活公約尚未訂定',
      q: '全家或班級要訂立什麼生活公約、日常自我檢查表或提醒標籤，防範同類事情再次發生？',
      quickVal: suggD5
    });
  }

  currentPendingQuestions = questions;
  if (selectedQuestionIndex >= questions.length) {
    selectedQuestionIndex = 0;
  }

  if (questions.length === 0) {
    badge.textContent = '資訊健全無缺口';
    badge.style.backgroundColor = 'var(--success-bg)';
    badge.style.color = 'var(--success)';
    container.innerHTML = `
      <div class="reminder-item success" style="padding: 14px 16px;">
        <div class="reminder-title" style="font-size: 14px; font-weight: 700; color: #166534; margin-bottom: 6px;">
          5D 分析報告架構完整健全！
        </div>
        <div style="font-size: 13px; color: var(--text-main); line-height: 1.6;">
          所有關鍵欄位（事實經過、當下處置、原因推導、改善行動、生活公約）均已齊備並顯示於上方看板。您可切換各分頁檢視微調，或直接點擊上方<strong>「產出 Word 報告」</strong>或<strong>「產出 PPT 簡報」</strong>。
        </div>
      </div>
    `;
    if (replyBox) replyBox.style.display = 'none';
  } else {
    badge.textContent = `待補充 ${questions.length} 項`;
    badge.style.backgroundColor = 'var(--warning-bg)';
    badge.style.color = 'var(--warning)';
    if (replyBox) replyBox.style.display = 'block';

    const currentTarget = questions[selectedQuestionIndex] || questions[0];
    const replyPrompt = document.querySelector('#interview-reply-box div');
    if (replyPrompt) {
      replyPrompt.innerHTML = `在下方輸入回答，小幫手會自動幫你補進上方報告看板裡（目前正在回答：<strong>${escapeHtml(currentTarget.title)}</strong>）：`;
    }

    container.innerHTML = `
      <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 8px; margin-bottom: 8px;">
        <div style="font-size: 13px; color: var(--text-main); font-weight: 700;">
          小幫手分析判定：尚有 ${questions.length} 項細節待補充（點選建議值或輸入回答後，將即時更新至上方 5D 看板）：
        </div>
        <button type="button" class="btn btn-primary btn-sm" onclick="applyAllQuickAnswers()">
          一鍵代入全部建議參考（共 ${questions.length} 項）
        </button>
      </div>
    ` + questions.map((item, idx) => {
      const isSelected = idx === selectedQuestionIndex;
      const borderColor = isSelected ? 'var(--accent)' : 'var(--warning)';
      const bgColor = isSelected ? '#eff6ff' : '#ffffff';
      return `
      <div class="why-card" style="border-left: 4px solid ${borderColor}; padding: 12px 14px; margin-bottom: 10px; background: ${bgColor}; box-shadow: 0 1px 3px rgba(0,0,0,0.05);">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 4px;">
          <span style="font-size: 13px; font-weight: 700; color: ${isSelected ? '#1e40af' : '#b45309'};">待補第 ${idx + 1} 題：${escapeHtml(item.title)}</span>
          <span style="font-size: 11px; padding: 2px 6px; border-radius: 4px; background: #fef3c7; color: #92400e; font-weight: 600;">${escapeHtml(item.category)}</span>
        </div>
        <div style="font-size: 13px; color: var(--text-main); margin-bottom: 8px; line-height: 1.5;">
          ${escapeHtml(item.q)}
        </div>
        <div style="display: flex; gap: 8px; align-items: center; flex-wrap: wrap; margin-bottom: 8px;">
          <button type="button" class="btn btn-secondary btn-sm" data-field="${escapeHtml(item.field)}" data-quick-val="${escapeHtml(item.quickVal)}" onclick="applyQuickAnswer(this.dataset.field, this.dataset.quickVal)">
            一鍵代入建議參考：${escapeHtml(item.quickVal)}
          </button>
        </div>
        <div style="display: flex; gap: 6px; align-items: center;">
          <input type="text" id="inline-reply-${idx}" class="form-control" style="padding: 5px 10px; font-size: 12.5px;" placeholder="或直接在此輸入本題的補充回答..." data-field="${escapeHtml(item.field)}" data-idx="${idx}" onfocus="selectedQuestionIndex = ${idx};" onkeydown="if(event.key === 'Enter'){ event.preventDefault(); submitInlineReply(this.dataset.field, Number(this.dataset.idx)); }">
          <button type="button" class="btn btn-primary btn-sm" data-field="${escapeHtml(item.field)}" data-idx="${idx}" onclick="submitInlineReply(this.dataset.field, Number(this.dataset.idx))">送出此題</button>
        </div>
      </div>
    `;
    }).join('');
  }
}

// 直接從單張問題卡片內的輸入框送出補充回答
window.submitInlineReply = function(fieldPath, idx) {
  const input = document.getElementById(`inline-reply-${idx}`);
  if (!input || !input.value.trim()) {
    alert('請先在輸入框內填寫要補充的內容，或點擊上方「一鍵代入建議參考」按鈕。');
    return;
  }
  const val = input.value.trim();
  input.value = '';
  selectedQuestionIndex = 0;
  applyQuickAnswer(fieldPath, val);
};

// 選擇指定題目於下方輸入框進行手動回答
window.selectQuestionForReply = function(idx) {
  selectedQuestionIndex = idx;
  generateClarificationQuestions();
  const input = document.getElementById('interview-reply-input');
  if (input) {
    input.focus();
  }
};

// 一鍵批次代入所有待補充建議參考值
window.applyAllQuickAnswers = function() {
  if (!currentPendingQuestions || currentPendingQuestions.length === 0) return;
  const toApply = [...currentPendingQuestions];
  toApply.forEach(item => {
    applyFieldUpdateSilent(item.field, item.quickVal);
  });
  lastSupplementedInfo = {
    label: `全部 ${toApply.length} 項待補充細節`,
    value: '已全數套用情境建議參考值',
    field: 'all'
  };
  selectedQuestionIndex = 0;
  populateFormFromData();
  renderAllDynamicFields();
  updateAuditAndScore();
  renderLivePreview();
  saveAutoDraft();
  generateClarificationQuestions();
  showToast(`已一鍵代入全部 ${toApply.length} 項建議參考並更新上方 5D 看板！`, 'success');
};

// 內部欄位更新核心邏輯
function applyFieldUpdateSilent(fieldPath, value) {
  if (!value || !value.trim()) return;
  const val = value.trim();

  lastSupplementedInfo = {
    label: FIELD_LABEL_MAP[fieldPath] || fieldPath,
    value: val,
    field: fieldPath
  };

  if (fieldPath === 'd1.when') {
    reportData.lotNumber = val;
    reportData.d1.when = val;
  } else if (fieldPath === 'd1.where') {
    reportData.customerLine = val;
    reportData.d1.where = val;
  } else if (fieldPath === 'd1.why') {
    reportData.d1.why = val;
  } else if (fieldPath === 'd1.how') {
    reportData.d1.how = val;
  } else if (fieldPath === 'd1.impactScope') {
    reportData.d1.impactScope = val;
  } else if (fieldPath === 'd2.action') {
    const emptyRow = reportData.d2.containmentActions.find(a => a && (!a.action || !a.action.trim()));
    if (emptyRow) {
      emptyRow.action = val;
      emptyRow.owner = emptyRow.owner || reportData.owner || '家長 / 當事人';
      emptyRow.dueDate = emptyRow.dueDate || reportData.dateCreated || new Date().toISOString().slice(0, 10);
      emptyRow.status = '已完成';
      emptyRow.result = emptyRow.result || '當下狀況已獲得妥善控制';
    } else {
      reportData.d2.containmentActions.push({
        action: val,
        owner: reportData.owner || '家長 / 當事人',
        dueDate: reportData.dateCreated || new Date().toISOString().slice(0, 10),
        status: '已完成',
        result: '當下狀況已獲得妥善控制'
      });
    }
    if (!reportData.d2.factoryStock) reportData.d2.factoryStock = '【現場處置】' + val;
    if (!reportData.d2.containmentVerification) {
      reportData.d2.containmentVerification = '當下事態已受到妥善控制，各方情緒平復，未衍生進一步問題。';
    }
  } else if (fieldPath === 'd3.why') {
    const emptyWhy = reportData.d3.whyMadeChain.find(w => w && (!w.answer || !w.answer.trim()) && (!w.question || !w.question.trim()));
    if (emptyWhy) {
      emptyWhy.question = '為什麼會發生這項情況？';
      emptyWhy.answer = val;
    } else {
      const nextLvl = reportData.d3.whyMadeChain.length + 1;
      reportData.d3.whyMadeChain.push({
        level: `Why ${nextLvl}`,
        question: '為什麼會發生這項情況？',
        answer: val
      });
    }
    if (!reportData.d3.rootCauseSummary) {
      reportData.d3.rootCauseSummary = '根本原因：' + val;
    }
  } else if (fieldPath === 'd4.action') {
    const defaultActor = reportData.d1.who ? reportData.d1.who.replace(/^行為人[：:]\s*/, '').split('；')[0] : '當事人';
    const defaultDue = reportData.targetCloseDate || getDefaultTargetDate(reportData.dateCreated, 7);
    const emptyD4 = reportData.d4.correctiveActions.find(c => c && (!c.action || !c.action.trim()));
    if (emptyD4) {
      emptyD4.action = val;
      emptyD4.category = emptyD4.category || '想法與習慣調整';
      emptyD4.owner = emptyD4.owner || defaultActor;
      emptyD4.dueDate = emptyD4.dueDate || defaultDue;
      emptyD4.status = '進行中';
      emptyD4.verification = emptyD4.verification || '日常持續落實並接受檢驗';
    } else {
      reportData.d4.correctiveActions.push({
        action: val,
        category: '想法與習慣調整',
        owner: defaultActor,
        dueDate: defaultDue,
        status: '進行中',
        verification: '日常持續落實並接受檢驗'
      });
    }
    if (!reportData.d4.beforeMetric) reportData.d4.beforeMetric = '改善前：曾發生生活常規異常或違規情形';
    if (!reportData.d4.afterMetric) reportData.d4.afterMetric = '改善後：落實新約定與自律檢核，成效良好';
    if (!reportData.d4.validationConclusion) {
      reportData.d4.validationConclusion = '改善好方法已確實排定落實，逐步修復信任與恢復生活常規。';
    }
  } else if (fieldPath === 'd5.doc') {
    const emptyDoc = reportData.d5.standardDocs.find(d => d && (!d.docName || !d.docName.trim()));
    if (emptyDoc) {
      emptyDoc.docType = emptyDoc.docType || '生活公約 / 家規';
      emptyDoc.docNumber = emptyDoc.docNumber || 'RULE-HOME-001';
      emptyDoc.docName = val;
      emptyDoc.revDate = emptyDoc.revDate || reportData.dateCreated || new Date().toISOString().slice(0, 10);
      emptyDoc.owner = emptyDoc.owner || '全體家庭成員';
    } else {
      const docNum = 'RULE-HOME-00' + (reportData.d5.standardDocs.length + 1);
      reportData.d5.standardDocs.push({
        docType: '生活公約 / 家規',
        docNumber: docNum,
        docName: val,
        revDate: reportData.dateCreated || new Date().toISOString().slice(0, 10),
        owner: '全體家庭成員'
      });
    }
  } else {
    setNestedValue(reportData, fieldPath, val);
  }

  // 若原始輸入為極短句（<= 8 字），當使用者透過小幫手補齊時間、地點或影響後，自動組合為完整事件描述句，確保評分與描述完整性一致
  if (reportData.d1 && (!reportData.d1.problemDesc || reportData.d1.problemDesc.trim().length <= 8)) {
    const baseWhat = (reportData.d1.what || reportData.d1.problemDesc || '').replace(/[。，！】]$/, '');
    const actor = reportData.d1.who ? reportData.d1.who.replace(/^行為人[：:]\s*/, '').split('；')[0] : '當事人';
    const whenPart = reportData.d1.when ? `於${reportData.d1.when}` : '';
    const wherePart = reportData.d1.where ? `在${reportData.d1.where}` : '';
    const impactPart = reportData.d1.impactScope ? `，${reportData.d1.impactScope}` : '';
    if (whenPart || wherePart || impactPart) {
      reportData.d1.problemDesc = `${actor}${whenPart}${wherePart}發生「${baseWhat}」之情況${impactPart}。`;
    }
  }
}

// 快速代入單項追問建議值或使用者補充回答
window.applyQuickAnswer = function(fieldPath, value) {
  if (!value || !value.trim()) return;
  applyFieldUpdateSilent(fieldPath, value);

  populateFormFromData();
  renderAllDynamicFields();
  updateAuditAndScore();
  renderLivePreview();
  saveAutoDraft();
  generateClarificationQuestions();

  const container = document.getElementById('interview-chat-container');
  if (container) container.scrollTop = 0;

  showToast(`已成功補充【${FIELD_LABEL_MAP[fieldPath] || '報告內容'}】並更新看板！`, 'success');
};

// 使用者直接在下方回覆補充文字
function submitInterviewReply() {
  const input = document.getElementById('interview-reply-input');
  if (!input || !input.value.trim()) return;

  const reply = input.value.trim();
  input.value = '';

  if (currentPendingQuestions.length > 0) {
    const targetQ = currentPendingQuestions[selectedQuestionIndex] || currentPendingQuestions[0];
    selectedQuestionIndex = 0;
    applyQuickAnswer(targetQ.field, reply);
  } else {
    showToast('目前所有關鍵項目均已補齊！', 'info');
  }
}

// 支援呼叫 Google Gemini API（若使用者填寫 API Key，透過 HTTP Header 安全傳遞金鑰並驗證模型名稱）
function callGeminiApi(rawText) {
  const apiKey = document.getElementById('llm-api-key')?.value.trim();
  const rawModelName = document.getElementById('llm-model-name')?.value.trim() || 'gemini-2.5-flash';
  const modelName = /^[a-zA-Z0-9._-]+$/.test(rawModelName) ? rawModelName : 'gemini-2.5-flash';

  if (!apiKey) {
    alert('使用 Gemini API 模式時，請在「進階 AI 模型設定」中輸入您的 API Key。系統將先切換回本機離線解析。');
    parseRawTextTo5D(rawText);
    return;
  }

  const safeText = String(rawText || '').slice(0, 4000);
  const prompt = `你是一位親切、具備教育同理心與邏輯分析能力的「5D 生活問題小幫手」（專為國小、國中生與家庭設計）。
請將以下事件描述拆解為標準「5D 生活問題解決分析報告」JSON 結構。
語言必須為繁體中文（台灣）。

原始描述：
${safeText}

請嚴格輸出符合以下 JSON 格式（不得輸出多餘 markdown 程式碼區塊標記，只輸出純 JSON）：
${JSON.stringify(reportData, null, 2)}`;

  const url = `https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(modelName)}:generateContent`;
  const controller = typeof AbortController !== 'undefined' ? new AbortController() : null;
  const timeoutId = controller ? setTimeout(() => controller.abort(), 30000) : null;

  fetch(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-goog-api-key': apiKey
    },
    signal: controller ? controller.signal : undefined,
    body: JSON.stringify({
      contents: [{ parts: [{ text: prompt }] }],
      generationConfig: { responseMimeType: "application/json" }
    })
  })
  .then(res => {
    if (timeoutId) clearTimeout(timeoutId);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return res.json();
  })
  .then(result => {
    try {
      const textOutput = result.candidates[0].content.parts[0].text;
      const parsedData = JSON.parse(textOutput);
      reportData = normalizeReportData(parsedData);
      populateFormFromData();
      renderAllDynamicFields();
      updateAuditAndScore();
      renderLivePreview();
      saveAutoDraft();
      showToast('Gemini AI 已成功生成高階 5D 分析報告！', 'success');
      generateClarificationQuestions();
    } catch (e) {
      console.warn('Gemini 回傳解析失敗，使用離線引擎替代:', e);
      parseRawTextTo5D(rawText);
    }
  })
  .catch(err => {
    if (timeoutId) clearTimeout(timeoutId);
    console.error('Gemini API 呼叫失敗:', err);
    alert('Gemini API 連線失敗或逾時，系統將自動以本機離線引擎進行解析。');
    parseRawTextTo5D(rawText);
  });
}

// 支援呼叫本機 Ollama 離線伺服器（http://localhost:11434）
function callOllamaApi(rawText) {
  const rawModelName = document.getElementById('llm-model-name')?.value.trim() || 'qwen2.5';
  const modelName = /^[a-zA-Z0-9._:-]+$/.test(rawModelName) ? rawModelName : 'qwen2.5';
  const url = 'http://localhost:11434/api/generate';
  const safeText = String(rawText || '').slice(0, 4000);
  const controller = typeof AbortController !== 'undefined' ? new AbortController() : null;
  const timeoutId = controller ? setTimeout(() => controller.abort(), 30000) : null;

  fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    signal: controller ? controller.signal : undefined,
    body: JSON.stringify({
      model: modelName,
      prompt: `將以下生活事件描述轉為 5D 生活問題解決分析 JSON：\n${safeText}\n請直接輸出純 JSON。`,
      stream: false,
      format: "json"
    })
  })
  .then(res => {
    if (timeoutId) clearTimeout(timeoutId);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return res.json();
  })
  .then(data => {
    try {
      const parsedData = JSON.parse(data.response);
      reportData = normalizeReportData(parsedData);
      populateFormFromData();
      renderAllDynamicFields();
      updateAuditAndScore();
      renderLivePreview();
      saveAutoDraft();
      showToast('本機 Ollama 模型已完成 5D 分析生成！', 'success');
      generateClarificationQuestions();
    } catch (e) {
      parseRawTextTo5D(rawText);
    }
  })
  .catch(err => {
    if (timeoutId) clearTimeout(timeoutId);
    console.warn('Ollama 連線失敗，切換回本機內建語意解析:', err);
    parseRawTextTo5D(rawText);
  });
}

