require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { createClient } = require('@supabase/supabase-js');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static('.'));
// Supabase client
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY
);

const JWT_SECRET = process.env.JWT_SECRET || 'buildflow_secret';

// ── Middleware: التحقق من التوكن ──────────────────────
const auth = async (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'غير مصرح' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'توكن غير صالح' });
  }
};

// ══════════════════════════════════════════════════════
// AUTH
// ══════════════════════════════════════════════════════

// تسجيل الدخول
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'البريد وكلمة المرور مطلوبان' });

  const { data: user, error } = await supabase
    .from('users')
    .select('*')
    .eq('email', email.toLowerCase())
    .eq('is_active', true)
    .single();

  if (error || !user) return res.status(401).json({ error: 'البريد أو كلمة المرور غير صحيحة' });

  // كلمة المرور 1234 للنموذج التجريبي
  const validPass = password === '1234' || await bcrypt.compare(password, user.password_hash);
  if (!validPass) return res.status(401).json({ error: 'البريد أو كلمة المرور غير صحيحة' });

  const token = jwt.sign(
    { id: user.id, name: user.name, email: user.email, role: user.role },
    JWT_SECRET,
    { expiresIn: '8h' }
  );

  res.json({ token, user: { id: user.id, name: user.name, email: user.email, role: user.role } });
});

// بيانات المستخدم الحالي
app.get('/api/auth/me', auth, async (req, res) => {
  res.json({ user: req.user });
});

// ══════════════════════════════════════════════════════
// PROJECTS
// ══════════════════════════════════════════════════════

// كل المشاريع
app.get('/api/projects', auth, async (req, res) => {
  let query = supabase.from('projects').select(`
    *,
    payments(*),
    project_alerts(*),
    checklists(*, checklist_items(*)),
    purchase_requests(*)
  `).order('created_at', { ascending: false });

  // العميل يشوف مشروعه فقط
  if (req.user.role === 'client') {
    const { data: client } = await supabase
      .from('clients')
      .select('id')
      .eq('portal_user_id', req.user.id)
      .single();
    if (client) query = query.eq('client_id', client.id);
  }

  const { data, error } = await query;
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

// مشروع واحد
app.get('/api/projects/:id', auth, async (req, res) => {
  const { data, error } = await supabase
    .from('projects')
    .select(`*, payments(*), project_alerts(*), checklists(*, checklist_items(*)), purchase_requests(*), daily_reports(*)`)
    .eq('id', req.params.id)
    .single();
  if (error) return res.status(404).json({ error: 'المشروع غير موجود' });
  res.json(data);
});

// إضافة مشروع
app.post('/api/projects', auth, async (req, res) => {
  if (!['general_manager', 'project_manager'].includes(req.user.role))
    return res.status(403).json({ error: 'غير مصرح' });

  const { data, error } = await supabase
    .from('projects')
    .insert({ ...req.body, created_by: req.user.id })
    .select()
    .single();
  if (error) return res.status(400).json({ error: error.message });
  res.json(data);
});

// تعديل مشروع
app.put('/api/projects/:id', auth, async (req, res) => {
  const { data, error } = await supabase
    .from('projects')
    .update({ ...req.body, updated_at: new Date() })
    .eq('id', req.params.id)
    .select()
    .single();
  if (error) return res.status(400).json({ error: error.message });
  res.json(data);
});

// ══════════════════════════════════════════════════════
// CHECKLISTS
// ══════════════════════════════════════════════════════

// تحديث بند في الـ Checklist
app.put('/api/checklists/items/:id', auth, async (req, res) => {
  if (!['site_engineer', 'project_manager', 'general_manager'].includes(req.user.role))
    return res.status(403).json({ error: 'المهندس فقط يعبئ الـ Checklist' });

  const { data, error } = await supabase
    .from('checklist_items')
    .update({ is_checked: req.body.is_checked, checked_by: req.user.id, checked_at: new Date() })
    .eq('id', req.params.id)
    .select()
    .single();
  if (error) return res.status(400).json({ error: error.message });
  res.json(data);
});

// اعتماد الـ Checklist — يفتح التالي تلقائياً
app.post('/api/checklists/:id/approve', auth, async (req, res) => {
  if (!['site_engineer', 'project_manager', 'general_manager'].includes(req.user.role))
    return res.status(403).json({ error: 'غير مصرح' });

  // اعتماد الحالي
  const { data: current, error } = await supabase
    .from('checklists')
    .update({ status: 'completed', approved_by: req.user.id, approved_at: new Date() })
    .eq('id', req.params.id)
    .select()
    .single();
  if (error) return res.status(400).json({ error: error.message });

  // فتح التالي تلقائياً
  await supabase
    .from('checklists')
    .update({ status: 'open' })
    .eq('project_id', current.project_id)
    .eq('sequence_order', current.sequence_order + 1)
    .eq('status', 'locked');

  res.json({ success: true, checklist: current });
});

// ══════════════════════════════════════════════════════
// DAILY REPORTS
// ══════════════════════════════════════════════════════

// تقارير مشروع
app.get('/api/projects/:id/reports', auth, async (req, res) => {
  const { data, error } = await supabase
    .from('daily_reports')
    .select('*, report_workers(*), report_work_items(*)')
    .eq('project_id', req.params.id)
    .order('report_date', { ascending: false });
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

// إنشاء / تحديث تقرير (مسودة)
app.post('/api/projects/:id/reports', auth, async (req, res) => {
  const { workers, work_items, notes, status } = req.body;
  const today = new Date().toISOString().slice(0, 10);

  // شوف لو في تقرير اليوم
  const { data: existing } = await supabase
    .from('daily_reports')
    .select('id')
    .eq('project_id', req.params.id)
    .eq('report_date', today)
    .single();

  let reportId;
  if (existing) {
    // تحديث الموجود
    await supabase.from('daily_reports').update({
      notes, status,
      workers_count: workers?.reduce((a, w) => a + w.count, 0) || 0,
      submitted_by: status === 'submitted' ? req.user.id : null,
      submitted_at: status === 'submitted' ? new Date() : null,
    }).eq('id', existing.id);
    reportId = existing.id;
    await supabase.from('report_workers').delete().eq('report_id', reportId);
    await supabase.from('report_work_items').delete().eq('report_id', reportId);
  } else {
    // إنشاء جديد
    const { data: proj } = await supabase.from('projects').select('current_phase, day_number').eq('id', req.params.id).single();
    const { data: rep } = await supabase.from('daily_reports').insert({
      project_id: req.params.id,
      report_date: today,
      current_phase: proj?.current_phase,
      day_number: proj?.day_number,
      notes, status,
      workers_count: workers?.reduce((a, w) => a + w.count, 0) || 0,
      submitted_by: status === 'submitted' ? req.user.id : null,
      submitted_at: status === 'submitted' ? new Date() : null,
    }).select().single();
    reportId = rep.id;
  }

  // إضافة العمال
  if (workers?.length) {
    await supabase.from('report_workers').insert(workers.map(w => ({ report_id: reportId, ...w })));
  }
  // إضافة الأعمال
  if (work_items?.length) {
    await supabase.from('report_work_items').insert(work_items.map(w => ({ report_id: reportId, ...w })));
  }

  res.json({ success: true, report_id: reportId });
});

// ══════════════════════════════════════════════════════
// PURCHASES
// ══════════════════════════════════════════════════════

// طلب مشتريات جديد
app.post('/api/purchases', auth, async (req, res) => {
  if (!['site_engineer', 'project_manager', 'general_manager'].includes(req.user.role))
    return res.status(403).json({ error: 'غير مصرح' });

  const { data, error } = await supabase
    .from('purchase_requests')
    .insert({ ...req.body, requested_by: req.user.id, requested_at: new Date() })
    .select()
    .single();
  if (error) return res.status(400).json({ error: error.message });
  res.json(data);
});

// اعتماد طلب مشتريات
app.put('/api/purchases/:id/approve', auth, async (req, res) => {
  if (!['project_manager', 'general_manager'].includes(req.user.role))
    return res.status(403).json({ error: 'مدير المشاريع فقط يعتمد' });

  const { data, error } = await supabase
    .from('purchase_requests')
    .update({ status: 'manager_approved', approved_by: req.user.id, approved_at: new Date(), expected_delivery: req.body.expected_delivery })
    .eq('id', req.params.id)
    .select()
    .single();
  if (error) return res.status(400).json({ error: error.message });
  res.json(data);
});

// تأكيد الاستلام
app.put('/api/purchases/:id/confirm', auth, async (req, res) => {
  if (!['site_supervisor', 'site_engineer', 'project_manager', 'general_manager'].includes(req.user.role))
    return res.status(403).json({ error: 'غير مصرح' });

  const { data, error } = await supabase
    .from('purchase_requests')
    .update({ status: 'delivered', received_confirmed_by: req.user.id, actual_delivery: new Date().toISOString().slice(0, 10) })
    .eq('id', req.params.id)
    .select()
    .single();
  if (error) return res.status(400).json({ error: error.message });
  res.json(data);
});

// ══════════════════════════════════════════════════════
// PAYMENTS
// ══════════════════════════════════════════════════════

app.get('/api/projects/:id/payments', auth, async (req, res) => {
  const { data, error } = await supabase
    .from('payments')
    .select('*')
    .eq('project_id', req.params.id)
    .order('due_date');
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.put('/api/payments/:id', auth, async (req, res) => {
  if (!['accountant', 'general_manager'].includes(req.user.role))
    return res.status(403).json({ error: 'المحاسب فقط يعدل الدفعات' });

  const { data, error } = await supabase
    .from('payments')
    .update(req.body)
    .eq('id', req.params.id)
    .select()
    .single();
  if (error) return res.status(400).json({ error: error.message });
  res.json(data);
});

// ══════════════════════════════════════════════════════
// MESSAGES
// ══════════════════════════════════════════════════════

// رسائل محادثة
app.get('/api/conversations/:key/messages', auth, async (req, res) => {
  let convId;
  if (req.params.key === 'general') {
    const { data } = await supabase.from('conversations').select('id').eq('type', 'general').single();
    convId = data?.id;
  } else {
    const { data } = await supabase.from('conversations').select('id').eq('project_id', req.params.key).single();
    if (!data) {
      // إنشاء المحادثة لو ما موجودة
      const { data: proj } = await supabase.from('projects').select('name').eq('id', req.params.key).single();
      const { data: newConv } = await supabase.from('conversations').insert({ type: 'project', project_id: req.params.key, name: proj?.name }).select().single();
      convId = newConv?.id;
    } else {
      convId = data.id;
    }
  }
  if (!convId) return res.json([]);

  const { data, error } = await supabase
    .from('messages')
    .select('*')
    .eq('conversation_id', convId)
    .order('created_at');
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

// إرسال رسالة
app.post('/api/conversations/:key/messages', auth, async (req, res) => {
  let convId;
  if (req.params.key === 'general') {
    const { data } = await supabase.from('conversations').select('id').eq('type', 'general').single();
    convId = data?.id;
  } else {
    let { data } = await supabase.from('conversations').select('id').eq('project_id', req.params.key).single();
    if (!data) {
      const { data: proj } = await supabase.from('projects').select('name').eq('id', req.params.key).single();
      const { data: newConv } = await supabase.from('conversations').insert({ type: 'project', project_id: req.params.key, name: proj?.name }).select().single();
      convId = newConv?.id;
    } else {
      convId = data.id;
    }
  }

  const { data, error } = await supabase
    .from('messages')
    .insert({ conversation_id: convId, sender_id: req.user.id, sender_name: req.user.name, content: req.body.content, type: req.body.type || 'text' })
    .select()
    .single();
  if (error) return res.status(400).json({ error: error.message });
  res.json(data);
});

// ══════════════════════════════════════════════════════
// NOTIFICATIONS
// ══════════════════════════════════════════════════════

app.get('/api/notifications', auth, async (req, res) => {
  const { data, error } = await supabase
    .from('notifications')
    .select('*')
    .eq('user_id', req.user.id)
    .order('created_at', { ascending: false })
    .limit(20);
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

// ══════════════════════════════════════════════════════
// USERS
// ══════════════════════════════════════════════════════

app.get('/api/users', auth, async (req, res) => {
  if (!['general_manager', 'hr', 'project_manager'].includes(req.user.role))
    return res.status(403).json({ error: 'غير مصرح' });

  const { data, error } = await supabase.from('users').select('id, name, email, role, is_active, created_at').order('name');
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

// ══════════════════════════════════════════════════════
// START SERVER
// ══════════════════════════════════════════════════════
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`
  ╔════════════════════════════════════╗
  ║   BuildFlow Server                 ║
  ║   http://localhost:${PORT}           ║
  ║   جاهز للاستخدام ✓                 ║
  ╚════════════════════════════════════╝
  `);
});
