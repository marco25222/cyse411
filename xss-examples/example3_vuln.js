app.get('/search', (req, res) => {
  const q = req.query.q || '';

  res.json({ resultsFor: q });
});


