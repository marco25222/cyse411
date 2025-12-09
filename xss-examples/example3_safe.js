app.get('/search-safe', (req, res) => {
  const q = String(req.query.q || '');

  res.json({ resultsFor: q });
});
