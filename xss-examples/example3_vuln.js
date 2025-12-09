function escapeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

app.get('/search', (req, res) => {
  const q = req.query.q || '';
  const safeQ = escapeHtml(q);

  res.send(`<h1>Results for ${safeQ}</h1>`);
});

