const express = require('express');
const expressEjsLayouts = require('express-ejs-layouts');
const multer = require('multer');
const path = require('path');
const fs = require('fs');

const app = express();

// Ensure upload folder exists
const uploadFolder = path.join(__dirname, 'uploads');
fs.mkdirSync(uploadFolder, { recursive: true });

// Set up multer storage
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadFolder),
  filename: (req, file, cb) => cb(null, `${Date.now()}-${file.originalname}`)
});
const upload = multer({ storage });

// Set view engine
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, '..', 'Public', 'views'));
app.use(expressEjsLayouts);
app.set('layout', 'layout');

// Static files
app.use(express.static(path.join(__dirname, '..', 'Public')));

// Pages
app.get('/', (req, res) => res.render('index', { title: 'GoSpoof - Home' }));
app.get('/attackers', (req, res) => res.render('attackers', { title: 'GoSpoof - Attackers', includeChartJS: true }));
app.get('/payloads', (req, res) => res.render('payloads', { title: 'GoSpoof - Payloads' }));

// Utils
function getLatestLogFilePath() {
  const files = fs.readdirSync(uploadFolder).filter(f => f.endsWith('.log'));
  if (!files.length) return null;

  return path.join(uploadFolder, files.sort((a, b) => {
    return fs.statSync(path.join(uploadFolder, b)).mtime - fs.statSync(path.join(uploadFolder, a)).mtime;
  })[0]);
}

// API: Attackers
app.get('/api/attackers', (req, res) => {
  const logPath = getLatestLogFilePath();
  if (!logPath) return res.json([]);

  fs.readFile(logPath, 'utf8', (err, data) => {
    if (err) return res.status(500).send('Error reading log');

    const ipPayloadMap = {};
    data.split('\n').forEach(line => {
      const match = line.match(/\[HONEYPOT\] .*? \| IP: ([\d.]+):\d+ \| Port: \d+ \| Data: "(.*?)"/);
      if (match) {
        const [_, ip, payload] = match;
        if (!ipPayloadMap[ip]) ipPayloadMap[ip] = new Set();
        ipPayloadMap[ip].add(payload || 'Probing Scan');
      }
    });

    const result = Object.entries(ipPayloadMap).map(([ip, payloadSet]) => ({
      ip,
      payloadCount: payloadSet.size
    }));

    res.json(result);
  });
});

// API: Payloads
app.get('/api/payloads', (req, res) => {
  const logPath = getLatestLogFilePath();
  if (!logPath) return res.json({});

  fs.readFile(logPath, 'utf8', (err, data) => {
    if (err) return res.status(500).send('Error reading log');

    const result = {};
    data.split('\n').forEach(line => {
      const match = line.match(/\[HONEYPOT\] (\d{4}-\d{2}-\d{2}) (\d{2}:\d{2}:\d{2}) \| IP: ([\d.]+):\d+ \| Port: \d+ \| Data: "(.*?)"/);
      if (match) {
        let [_, date, time, ip, payload] = match;
        payload = payload.trim() || 'Probing Scan';

        if (!result[ip]) {
          result[ip] = { total: 0, payloads: {} };
        }

        result[ip].total++;
        result[ip].payloads[payload] = (result[ip].payloads[payload] || 0) + 1;
      }
    });

    res.json(result);
  });
});

// Upload endpoint
app.post('/upload-log', upload.single('logFile'), (req, res) => {
  if (!req.file) return res.status(400).send('No file uploaded');
  console.log('Uploaded:', req.file.path);
  res.redirect('/attackers');
});

// Start
app.listen(3000);
