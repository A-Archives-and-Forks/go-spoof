const express = require('express');
const expressEjsLayouts = require('express-ejs-layouts');
const multer = require('multer');
const upload = multer({ dest: 'uploads/' });
const path = require('path');
const fs = require('fs');
const logDest = path.join(__dirname, '..', 'honeypot.log');

const app = express();

// Set EJS as the view engine
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, '..', 'Public', 'views'));

// Use express-ejs-layouts
app.use(expressEjsLayouts);
app.set('layout', 'layout');

// Serve static files from the actual Public directory
app.use(express.static(path.join(__dirname, '..', 'Public')));


// Routes
app.get('/', (req, res) => {
  res.render('index',{
    title: 'GoSpoof - Home',
  });
});

app.get('/attackers', (req, res) => {
  res.render('attackers', {
    title: 'GoSpoof - Attackers',
    includeChartJS: true
  });
});

app.get('/payloads', (req, res) => {
  res.render('payloads', {
    title: 'GoSpoof - Payloads',
  });
});

const logPath = path.join(__dirname, '..', 'honeypot.log');

app.get('/api/attackers', (req, res) => {
  fs.readFile(path.join(__dirname, '..', 'honeypot.log'), 'utf8', (err, data) => {
    if (err) return res.status(500).send('Could not read log file.');

    const lines = data.trim().split('\n');
    const ipPayloadMap = {};

    lines.forEach(line => {
      const match = line.match(/\[HONEYPOT\] \d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} \| IP: ([\d.]+):\d+ \| Port: \d+ \| Data: "(.*)"/);
      if (match) {
        const [_, ip, payload] = match;
        if (!ipPayloadMap[ip]) ipPayloadMap[ip] = new Set();
        ipPayloadMap[ip].add(payload); // only count unique payloads
      }
    });

    const result = Object.entries(ipPayloadMap).map(([ip, payloadSet]) => ({
      ip,
      payloadCount: payloadSet.size
    }));

    res.json(result);
  });
});

app.get('/api/payloads', (req, res) => {
  fs.readFile(path.join(__dirname, '..', 'honeypot.log'), 'utf8', (err, data) => {
    if (err) return res.status(500).send('Could not read log file.');

    const lines = data.trim().split('\n');
    const payloads = lines.map(line => {
      const match = line.match(/\[HONEYPOT\] (\d{4}-\d{2}-\d{2}) (\d{2}:\d{2}:\d{2}) \| IP: ([\d.]+):\d+ \| Port: \d+ \| Data: "(.*)"/);
      if (match) {
        let [_, date, time, ip, payload] = match;

        // Clean it up and label as Nmap if empty or just whitespace
        payload = payload.trim();
        if (payload === '') payload = 'Nmap Scan';

        return { ip, date, time, payload };
      }
      return null;
    }).filter(Boolean);

    res.json(payloads);
  });
});

app.post('/upload-log', upload.single('logFile'), (req, res) => {
  const tempPath = req.file.path;

  // Replace the existing honeypot.log file with uploaded one
  fs.rename(tempPath, logDest, err => {
    if (err) {
      console.error(err);
      return res.status(500).send('Failed to save log.');
    }
    res.send('✅ honeypot.log uploaded successfully!');
  });
});






app.listen(3000)