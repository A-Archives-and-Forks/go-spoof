const express = require('express');
const expressEjsLayouts = require('express-ejs-layouts');
const multer = require('multer');
const path = require('path');
const fs = require('fs');


// First create the app
const app = express();
app.use(express.json());


// Then wrap it with HTTP and attach socket.io
const http = require('http').createServer(app);
const io = require('socket.io')(http);

// Ensure upload folder exists
const uploadFolder = path.join(__dirname, 'uploads');
fs.mkdirSync(uploadFolder, { recursive: true });

// Multer config
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadFolder),
  filename: (req, file, cb) => cb(null, `${Date.now()}-${file.originalname}`)
});
const upload = multer({ storage });

// View engine setup
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
app.get('/live', (req, res) => res.render('live', { title: 'GoSpoof - Live' })); // Live page

// Util: Get latest log
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

// Upload Endpoint
app.post('/upload-log', upload.single('logFile'), (req, res) => {
  if (!req.file) return res.status(400).send('No file uploaded');
  console.log('Uploaded:', req.file.path);

  fs.readFile(req.file.path, 'utf8', (err, data) => {
    if (err) return res.status(500).send('Error reading uploaded log');

    const lines = data.split('\n');
    lines.forEach(line => {
      const match = line.match(/\[HONEYPOT\].*? \| IP: ([\d.]+):\d+ \| Port: \d+ \| Data: "(.*?)"/);
      if (match) {
        const [_, ip, payloadRaw] = match;
        const payload = payloadRaw.trim() || 'Probing Scan';

        io.emit('new_attack', { ip, payload });
      }
    });

    // Optional: go to live dashboard after upload
    res.redirect('/live');
  });
});


// Socket.IO
io.on('connection', (socket) => {
  console.log('Client connected:', socket.id);
  socket.emit('welcome', 'You are now connected to GoSpoof Live Feed');
});

app.get('/live', (req, res) => {
  res.render('live', { title: 'GoSpoof - Live' });
});
const logPath = path.join(__dirname, 'uploads', 'live.log'); // Adjust filename if needed

app.post('/live-capture', (req, res) => {
  const { ip, payload } = req.body;

  if (ip && payload) {
    io.emit('new_attack', { ip, payload: payload.trim() || 'Probing Scan' });
    res.status(200).send('ok');
  } else {
    res.status(400).send('missing ip or payload');
  }
});



let PORT = process.env.PORT || 3000;

http.listen(PORT)
  .on('listening', () => {
    console.log(`Web UI launched on http://localhost:${PORT}`);
  })
  .on('error', err => {
    if (err.code === 'EADDRINUSE') {
      PORT = PORT + 1;
      console.warn('Port in use. Retrying on http://localhost:${PORT}...');
      http.listen(PORT);
    } else {
      throw err;
    }
  });

