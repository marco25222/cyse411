const escapeHtml = s => s
  .replace(/&/g, '&amp;')
  .replace(/</g, '&lt;')
  .replace(/>/g, '&gt;')
  .replace(/"/g, '&quot;')
  .replace(/'/g, '&#x27;');

app.get('/search', (req, res) => {
  const q = escapeHtml(req.query.q || '');
  res.send(`<h1>Results for ${q}</h1>`);
});

