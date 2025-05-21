const fs = require('fs'); // 파일 저장을 위한 모듈
const express = require('express');
const bodyParser = require('body-parser');
const session = require('express-session'); // 🔧 세션 모듈 추가
const path = require('path');
const bcrypt = require('bcrypt');
const app = express();
const PORT = 3000;



// 🔧 세션 설정
app.use(session({
  secret: 'mySecretKey123', // 아무 문자열 가능
  resave: false,
  saveUninitialized: true
}));

app.use(bodyParser.urlencoded({ extended: false }));
app.use(express.static(path.join(__dirname, '/')));

// 🔧 로그인 라우터
app.post('/login', (req, res) => {
  const { username, password } = req.body;

  const users = JSON.parse(fs.readFileSync('users.json', 'utf-8'));
const matchedUser = users.find(user => user.username === username);

if (matchedUser && bcrypt.compareSync(password, matchedUser.password)) {
  req.session.user = username;

  if (matchedUser.isAdmin) {
    return res.redirect('/admin');
  }
  return res.redirect('/courses');
} else {
  res.send('<h3>로그인 실패. <a href="login.html">다시 시도</a></h3>');
}
});

// 🔧 강의 페이지 접근 제한
app.get('/courses', (req, res) => {
  if (!req.session.user) {
    return res.send('<h3>접근 불가. <a href="login.html">로그인</a> 해주세요.</h3>');
  }

  const users = JSON.parse(fs.readFileSync('users.json', 'utf-8'));
  const currentUser = users.find(user => user.username === req.session.user);

  if (!currentUser) {
    return res.send('<h3>사용자 정보를 찾을 수 없습니다.</h3>');
  }

  const courseList = currentUser.courses
    .map(course => `<li>${course}</li>`)
    .join('');

  const html = `
    <h2>${currentUser.username}님의 강의실</h2>
    <ul>${courseList}</ul>
<p><a href="/change-password">비밀번호 변경</a></p>
    <form method="POST" action="/logout">
      <button type="submit">로그아웃</button>
    </form>
  `;
  res.send(html);
});

// 🔧 로그아웃 처리
app.post('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.send('로그아웃 중 오류 발생');
    }
    res.redirect('/');
  });
});

// 서버 시작
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`서버 실행 중: http://localhost:${PORT}`);
});

app.post('/signup', (req, res) => {
  const { username, password } = req.body;
  const users = JSON.parse(fs.readFileSync('users.json', 'utf-8'));

  const userExists = users.find(user => user.username === username);
  if (userExists) {
    return res.send('<h3>이미 존재하는 아이디입니다. <a href="signup.html">다시 시도</a></h3>');
  }

  // 🔧 회원가입, 기본 강의 목록 포함
// 회원가입 라우터 내부에서
const hashedPassword = bcrypt.hashSync(password, 10); // 암호화
  const newUser = {
    username,
    password: hashedPassword,
  isAdmin: false,
    courses: ["기초 수학", "응용 문제풀이"]
  };

  users.push(newUser);
  fs.writeFileSync('users.json', JSON.stringify(users, null, 2));

  res.send('<h3>회원가입 완료! <a href="login.html">로그인하러 가기</a></h3>');
});

//🔧 관리자 페이지 열기 (GET)
app.get('/admin', (req, res) => {
  if (!req.session.user) {
    return res.send('<h3>로그인 먼저 해주세요. <a href="/login.html">로그인</a></h3>');
  }

  const users = JSON.parse(fs.readFileSync('users.json', 'utf-8'));
  const currentUser = users.find(user => user.username === req.session.user);

  if (!currentUser || !currentUser.isAdmin) {
    return res.send('<h3>관리자만 접근 가능합니다.</h3>');
  }

  res.sendFile(path.join(__dirname, 'admin.html'));
});

//🔧 강의 추가 처리 (POST)
app.post('/admin/add-course', (req, res) => {
  const { targetUser, courseName } = req.body;

  const users = JSON.parse(fs.readFileSync('users.json', 'utf-8'));
  const adminUser = users.find(user => user.username === req.session.user);

  if (!adminUser || !adminUser.isAdmin) {
    return res.send('<h3>관리자만 강의를 추가할 수 있습니다.</h3>');
  }

  const target = users.find(user => user.username === targetUser);
  if (!target) {
    return res.send('<h3>해당 학생을 찾을 수 없습니다.</h3>');
  }

  // 강의 중복 없이 추가
  if (!target.courses.includes(courseName)) {
    target.courses.push(courseName);
  }

  fs.writeFileSync('users.json', JSON.stringify(users, null, 2));
  res.send(`<h3>${targetUser}에게 '${courseName}' 강의를 추가했습니다. <a href="/admin">돌아가기</a></h3>`);
});

//🔧강의 삭제
app.post('/admin/delete-course', (req, res) => {
  const { targetUser, courseName } = req.body;

  const users = JSON.parse(fs.readFileSync('users.json', 'utf-8'));
  const adminUser = users.find(user => user.username === req.session.user);

  if (!adminUser || !adminUser.isAdmin) {
    return res.send('<h3>관리자만 강의를 삭제할 수 있습니다.</h3>');
  }

  const target = users.find(user => user.username === targetUser);
  if (!target) {
    return res.send('<h3>해당 학생을 찾을 수 없습니다.</h3>');
  }

  // 강의가 있을 경우 삭제
  target.courses = target.courses.filter(course => course !== courseName);

  fs.writeFileSync('users.json', JSON.stringify(users, null, 2));
  res.send(`<h3>${targetUser}에게서 '${courseName}' 강의를 삭제했습니다. <a href="/admin">돌아가기</a></h3>`);
});

//🔧비밀번호변경
app.get('/change-password', (req, res) => {
  if (!req.session.user) {
    return res.send('<h3>로그인 먼저 해주세요. <a href="/login.html">로그인</a></h3>');
  }

  res.sendFile(path.join(__dirname, 'change-password.html'));
});


//🔧비번변경 POST 처리
app.post('/change-password', (req, res) => {
  const { oldPassword, newPassword } = req.body;
  const users = JSON.parse(fs.readFileSync('users.json', 'utf-8'));
  const userIndex = users.findIndex(user => user.username === req.session.user);

  if (userIndex === -1) {
    return res.send('<h3>사용자 정보를 찾을 수 없습니다.</h3>');
  }

  const currentUser = users[userIndex];

  if (!bcrypt.compareSync(oldPassword, currentUser.password)) {
    return res.send('<h3>현재 비밀번호가 일치하지 않습니다. <a href="/change-password">다시 시도</a></h3>');
  }

  const newHashed = bcrypt.hashSync(newPassword, 10);
  currentUser.password = newHashed;

  users[userIndex] = currentUser;
  fs.writeFileSync('users.json', JSON.stringify(users, null, 2));

  req.session.destroy(() => {
    res.send('<h3>비밀번호가 변경되었습니다. 다시 <a href="/login.html">로그인</a> 해주세요.</h3>');
  });
});