const express = require('express');
const path = require('path');

const app = express();
const PORT = 3000; 

app.use(express.static(path.join(__dirname, 'public')));

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
    console.log('----------------------------------------------------');
    console.log(`Node.js Frontend: http://localhost:${PORT}`);
    console.log(`Python Backend:   http://127.0.0.1:8001`);
    console.log('----------------------------------------------------');
});