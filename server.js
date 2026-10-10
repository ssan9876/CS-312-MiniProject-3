const express = require('express');
const session = require('express-session');
const db = require('./db');
const { hashUserId, hashPassword, verifyPassword } = require('./hash');

const app = express();
const PORT = process.env.PORT || 3000;

app.set('view engine', 'ejs');

app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));

app.use(session({
  secret: process.env.SESSION_SECRET || 'dev-only-secret',
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: 'lax' },
}));

app.use((req, res, next) => {
  res.locals.user = req.session.user || null;
  next();
});

function requireAuth(req, res, next) {
  if (!req.session.user) {
    return res.redirect('/signin');
  }
  next();
}

const wrap = (fn) => (req, res, next) => fn(req, res, next).catch(next);

app.get('/signup', (req, res) => {
  res.render('signup', { error: null, values: {} });
});

app.post('/signup', wrap(async (req, res) => {
  const userId = (req.body.user_id || '').trim();
  const name = (req.body.name || '').trim();
  const password = req.body.password || '';
  const values = { user_id: userId, name };

  if (!userId || !name || !password) {
    return res.status(400).render('signup', { error: 'All fields are required.', values });
  }

  const hashedId = hashUserId(userId);

  const existing = await db.query('SELECT 1 FROM users WHERE user_id = $1', [hashedId]);
  if (existing.rowCount > 0) {
    return res.status(409).render('signup', {
      error: `The user ID "${userId}" is already taken. Please choose a different one.`,
      values,
    });
  }

  await db.query(
    'INSERT INTO users (user_id, password, name) VALUES ($1, $2, $3)',
    [hashedId, await hashPassword(password), name]
  );

  req.session.notice = 'Account created! Please sign in.';
  res.redirect('/signin');
}));


app.get('/signin', (req, res) => {
  const notice = req.session.notice || null;
  delete req.session.notice;
  res.render('signin', { error: null, notice, values: {} });
});

app.post('/signin', wrap(async (req, res, next) => {
  const userId = (req.body.user_id || '').trim();
  const password = req.body.password || '';

  const result = await db.query(
    'SELECT user_id, password, name FROM users WHERE user_id = $1',
    [hashUserId(userId)]
  );
  const row = result.rows[0];

  if (!row || !(await verifyPassword(password, row.password))) {
    return res.status(401).render('signin', {
      error: 'Incorrect user ID or password. Please try again.',
      notice: null,
      values: { user_id: userId },
    });
  }

  req.session.regenerate((err) => {
    if (err) return next(err);
    req.session.user = { user_id: row.user_id, login: userId, name: row.name };
    res.redirect('/');
  });
}));

app.post('/signout', (req, res) => {
  req.session.destroy(() => res.redirect('/signin'));
});


app.get('/account', requireAuth, (req, res) => {
  res.render('account', { error: null, notice: null, values: { user_id: req.session.user.login } });
});

app.post('/account', requireAuth, wrap(async (req, res) => {
  const newUserId = (req.body.user_id || '').trim();
  const newPassword = req.body.new_password || '';
  const currentPassword = req.body.current_password || '';
  const values = { user_id: newUserId };
  const fail = (status, error) => res.status(status).render('account', { error, notice: null, values });

  if (!newUserId) {
    return fail(400, 'User ID cannot be empty.');
  }

  const current = await db.query('SELECT password FROM users WHERE user_id = $1', [req.session.user.user_id]);
  if (current.rowCount === 0 || !(await verifyPassword(currentPassword, current.rows[0].password))) {
    return fail(401, 'Your current password is incorrect.');
  }

  const newHashedId = hashUserId(newUserId);
  if (newHashedId !== req.session.user.user_id) {
    const taken = await db.query('SELECT 1 FROM users WHERE user_id = $1', [newHashedId]);
    if (taken.rowCount > 0) {
      return fail(409, `The user ID "${newUserId}" is already taken. Please choose a different one.`);
    }
  }

  const passwordHash = newPassword ? await hashPassword(newPassword) : current.rows[0].password;

  try {
    await db.query(
      'UPDATE users SET user_id = $1, password = $2 WHERE user_id = $3',
      [newHashedId, passwordHash, req.session.user.user_id]
    );
  } catch (err) {
    if (err.code === '23505') {
      return fail(409, `The user ID "${newUserId}" is already taken. Please choose a different one.`);
    }
    throw err;
  }

  req.session.user = { ...req.session.user, user_id: newHashedId, login: newUserId };
  res.locals.user = req.session.user;
  res.render('account', { error: null, notice: 'Your account has been updated.', values });
}));


app.get('/', requireAuth, wrap(async (req, res) => {
  const result = await db.query(
    `SELECT blog_id, creator_name, creator_user_id, title, body, date_created, date_updated
       FROM blogs
      ORDER BY date_created DESC`
  );
  const notice = req.session.notice || null;
  delete req.session.notice;
  res.render('index', { posts: result.rows, notice });
}));


app.post('/create', requireAuth, wrap(async (req, res) => {
  const title = (req.body.title || '').trim();
  const body = (req.body.body || '').trim();

  if (title && body) {
    await db.query(
      `INSERT INTO blogs (creator_name, creator_user_id, title, body, date_created)
       VALUES ($1, $2, $3, $4, CURRENT_TIMESTAMP)`,
      [req.session.user.name, req.session.user.user_id, title, body]
    );
  }
  res.redirect('/');
}));


async function findOwnPost(req, res) {
  const blogId = Number(req.params.id);
  if (!Number.isInteger(blogId)) {
    res.redirect('/');
    return null;
  }

  const result = await db.query('SELECT * FROM blogs WHERE blog_id = $1', [blogId]);
  const post = result.rows[0];
  if (!post) {
    res.redirect('/');
    return null;
  }
  if (post.creator_user_id !== req.session.user.user_id) {
    req.session.notice = 'You can only edit or delete posts that you created.';
    res.redirect('/');
    return null;
  }
  return post;
}

app.get('/edit/:id', requireAuth, wrap(async (req, res) => {
  const post = await findOwnPost(req, res);
  if (post) {
    res.render('edit', { post });
  }
}));

app.post('/edit/:id', requireAuth, wrap(async (req, res) => {
  const post = await findOwnPost(req, res);
  if (!post) return;

  const title = (req.body.title || '').trim();
  const body = (req.body.body || '').trim();

  if (title && body) {
    await db.query(
      `UPDATE blogs
          SET title = $1, body = $2, date_updated = CURRENT_TIMESTAMP
        WHERE blog_id = $3 AND creator_user_id = $4`,
      [title, body, post.blog_id, req.session.user.user_id]
    );
  }
  res.redirect('/');
}));

app.post('/delete/:id', requireAuth, wrap(async (req, res) => {
  const post = await findOwnPost(req, res);
  if (!post) return;

  await db.query(
    'DELETE FROM blogs WHERE blog_id = $1 AND creator_user_id = $2',
    [post.blog_id, req.session.user.user_id]
  );
  res.redirect('/');
}));

app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).render('error', {
    message: 'Something went wrong talking to the database. Check that PostgreSQL is running and your .env settings are correct.',
  });
});

app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});
