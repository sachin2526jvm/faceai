async function loadNav() {
  try {
    const res = await fetch('/api/me');
    const data = await res.json();
    const navAuth = document.getElementById('nav-auth');
    const navUser = document.getElementById('nav-user');
    if (data.loggedIn) {
      if (navAuth) navAuth.style.display = 'none';
      if (navUser) {
        navUser.style.display = 'flex';
        const el = navUser.querySelector('.username-text');
        if (el) el.textContent = data.username;
      }
    } else {
      if (navAuth) navAuth.style.display = 'flex';
      if (navUser) navUser.style.display = 'none';
    }
  } catch {}
}

async function logout() {
  await fetch('/api/logout', { method: 'POST' });
  window.location.href = '/login';
}

document.addEventListener('DOMContentLoaded', loadNav);
