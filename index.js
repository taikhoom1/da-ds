require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const fs = require('fs');
const path = require('path');
const { nanoid } = require('nanoid');

const app = express();
const port = process.env.PORT || 3000;

const DATA_DIR = path.join(__dirname, 'data');
const CSV_PATH = path.join(DATA_DIR, 'submissions.csv');

// Ensure data directory and CSV header exist
if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}
if (!fs.existsSync(CSV_PATH)) {
  fs.writeFileSync(CSV_PATH, 'id,timestamp,name,email,phone,origin,notes\n', 'utf8');
}

app.use(helmet());
app.use(cors());
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(morgan('combined'));
app.use(express.static(path.join(__dirname, 'public')));

// Simple honeypot field name
const HONEYPOT_FIELD = 'company';

function sanitize(input) {
  if (typeof input !== 'string') return '';
  return input.replace(/[\n\r,]/g, ' ').trim();
}

app.post('/submit', (req, res) => {
  // Basic honeypot check
  if (req.body && req.body[HONEYPOT_FIELD]) {
    return res.status(200).json({ ok: true });
  }

  const name = sanitize(req.body.name);
  const email = sanitize(req.body.email);
  const phone = sanitize(req.body.phone);
  const origin = sanitize(req.body.origin);
  const notes = sanitize(req.body.notes || '');

  if (!name || !email || !phone || !origin) {
    return res.status(400).json({ error: 'Missing required fields' });
  }

  const id = nanoid(12);
  const timestamp = new Date().toISOString();
  const line = `${id},${timestamp},${name},${email},${phone},${origin},${notes}\n`;
  fs.appendFile(CSV_PATH, line, (err) => {
    if (err) {
      return res.status(500).json({ error: 'Failed to save submission' });
    }
    return res.status(200).json({ ok: true, id });
  });
});

// Export CSV (optional token auth via ?token=...)
app.get('/export', (req, res) => {
  const token = process.env.EXPORT_TOKEN;
  const provided = req.query.token;
  if (token && provided !== token) {
    return res.status(403).send('Forbidden');
  }
  res.setHeader('Content-Type', 'text/csv');
  res.setHeader('Content-Disposition', 'attachment; filename="submissions.csv"');
  fs.createReadStream(CSV_PATH).pipe(res);
});

app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`);
});
