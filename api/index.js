// -------------------------- 环境配置 --------------------------
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const mysql = require('mysql2/promise');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const Redis = require('ioredis');
const dayjs = require('dayjs');
const { v4: uuidv4 } = require('uuid');
const crypto = require('crypto');

// 初始化Express应用
const app = express();
const PORT = process.env.PORT || 80;
const ENV = process.env.ENV || 'production';

// 中间件配置
app.use(cors({ origin: '*' }));
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true }));

// -------------------------- 常量配置 --------------------------
// 数据库配置
const DB_CONFIG = {
  host: process.env.DB_HOST || 'localhost',
  port: parseInt(process.env.DB_PORT) || 3306,
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || '',
  database: process.env.DB_NAME || 'score_db',
  charset: 'utf8mb4',
  connectTimeout: 20000,
  ssl: { rejectUnauthorized: false }
};

// JWT配置
const SECRET_KEY = process.env.SECRET_KEY || 'your-strong-secret-key-here-1234567890';
const TOKEN_EXPIRE_HOURS = parseInt(process.env.TOKEN_EXPIRE_HOURS) || 24;

// 安全配置
const BCRYPT_ROUNDS = parseInt(process.env.BCRYPT_ROUNDS) || 12;
const LOCK_THRESHOLD = parseInt(process.env.LOCK_THRESHOLD) || 5;
const LOCK_WINDOW_SECONDS = parseInt(process.env.LOCK_WINDOW_SECONDS) || 300;
const ATTEMPT_WINDOW = parseInt(process.env.ATTEMPT_WINDOW) || 600;

// Redis配置
const REDIS_CONFIG = {
  host: process.env.REDIS_HOST || '',
  port: parseInt(process.env.REDIS_PORT) || 6379,
  db: parseInt(process.env.REDIS_DB) || 0,
  password: process.env.REDIS_PASSWORD || '',
  ssl: process.env.REDIS_SSL === 'True'
};

// -------------------------- 工具初始化 --------------------------
// Redis客户端（无配置则禁用）
let redisClient = null;
try {
  if (REDIS_CONFIG.host) {
    redisClient = new Redis({
      host: REDIS_CONFIG.host,
      port: REDIS_CONFIG.port,
      db: REDIS_CONFIG.db,
      password: REDIS_CONFIG.password,
      ssl: REDIS_CONFIG.ssl,
      connectTimeout: 5000,
      retryStrategy: (times) => Math.min(times * 100, 3000)
    });
    console.log('Redis连接成功');
  } else {
    console.log('未配置Redis，禁用缓存');
  }
} catch (err) {
  console.error('Redis连接失败：', err.message);
  redisClient = null;
}

// 防暴力登录存储（内存版，单实例有效）
const loginAttempts = new Map();

// -------------------------- 日志工具 --------------------------
const logAudit = (operation, userId, username, remoteAddr, details = "", level = "INFO") => {
  const logObj = {
    time: dayjs().format('YYYY-MM-DD HH:mm:ss'),
    level,
    operation,
    userId: userId || -1,
    username: username || 'unknown',
    remoteAddr: remoteAddr || 'unknown',
    details
  };
  console.log(JSON.stringify(logObj));
};

// -------------------------- 数据库工具 --------------------------
// 获取数据库连接
const getDbConnection = async () => {
  try {
    console.log(`尝试连接数据库：${DB_CONFIG.host}:${DB_CONFIG.port}`);
    const connection = await mysql.createConnection({
      ...DB_CONFIG,
      waitForConnections: true,
      connectionLimit: 10,
      queueLimit: 0
    });
    console.log('数据库连接成功');
    return connection;
  } catch (err) {
    console.error('数据库连接失败：', err.message);
    throw new Error(`数据库连接失败：${err.message}`);
  }
};

// 初始化数据库表结构
const initializeDatabase = async () => {
  let connection = null;
  try {
    // 先连接服务器创建数据库（使用普通query，不使用execute）
    connection = await mysql.createConnection({
      host: DB_CONFIG.host,
      port: DB_CONFIG.port,
      user: DB_CONFIG.user,
      password: DB_CONFIG.password,
      charset: 'utf8mb4',
      ssl: DB_CONFIG.ssl
    });

    // 修复：用query代替execute执行CREATE DATABASE（避免预处理语句报错）
    await connection.query(`CREATE DATABASE IF NOT EXISTS ${DB_CONFIG.database} CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;`);
    await connection.query(`USE ${DB_CONFIG.database};`);

    // 创建用户表（继续用execute，表结构语句不受影响）
    const createUserTable = `
      CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY COMMENT '用户ID',
        username VARCHAR(100) NOT NULL UNIQUE COMMENT '用户账号',
        password VARCHAR(255) NOT NULL COMMENT 'bcrypt哈希密码',
        role ENUM('student', 'teacher', 'admin') NOT NULL COMMENT '用户角色：学生/教师/管理员',
        id_card VARCHAR(18) UNIQUE COMMENT '身份证号（学生唯一标识）',
        class_name VARCHAR(50) COMMENT '班级名称',
        bind_time TIMESTAMP COMMENT '绑定时间',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP COMMENT '记录创建时间'
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='用户表';
    `;
    await connection.execute(createUserTable);

    // 创建成绩表
    const createScoreTable = `
      CREATE TABLE IF NOT EXISTS scores (
        id INT AUTO_INCREMENT PRIMARY KEY COMMENT '成绩ID',
        user_id INT NOT NULL COMMENT '关联学生ID',
        subject VARCHAR(50) NOT NULL COMMENT '科目名称',
        score FLOAT NOT NULL COMMENT '分数（0-100）',
        exam_date DATE NOT NULL COMMENT '考试日期',
        created_by INT NOT NULL COMMENT '创建者（教师ID）',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE CASCADE,
        UNIQUE KEY uk_user_subject_date (user_id, subject, exam_date)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='成绩表';
    `;
    await connection.execute(createScoreTable);

    console.log('数据库表结构初始化完成');
  } catch (err) {
    console.error('数据库初始化失败：', err.message);
    logAudit('数据库初始化', -1, 'system', 'localhost', `错误：${err.message}`, 'ERROR');
  } finally {
    if (connection) {
      await connection.end();
    }
  }
};

// -------------------------- 安全工具 --------------------------
// 密码哈希
const hashPassword = (plainPassword) => {
  const salt = bcrypt.genSaltSync(BCRYPT_ROUNDS);
  return bcrypt.hashSync(plainPassword, salt);
};

// 验证密码
const verifyPassword = (plainPassword, hashedPassword) => {
  return bcrypt.compareSync(plainPassword, hashedPassword);
};

// 生成JWT
const generateJwt = (userId, username, role) => {
  const expire = dayjs().add(TOKEN_EXPIRE_HOURS, 'hour').unix();
  return jwt.sign(
    { user_id: userId, username, role, exp: expire, iat: dayjs().unix() },
    SECRET_KEY,
    { algorithm: 'HS256' }
  );
};

// 验证JWT
const verifyJwt = (token) => {
  try {
    const payload = jwt.verify(token, SECRET_KEY);
    return {
      user_id: payload.user_id,
      username: payload.username,
      role: payload.role
    };
  } catch (err) {
    if (err.name === 'TokenExpiredError') {
      logAudit('验证JWT', -1, 'unknown', 'unknown', 'Token已过期', 'WARNING');
    } else {
      logAudit('验证JWT', -1, 'unknown', 'unknown', `Token无效：${err.message}`, 'WARNING');
    }
    return null;
  }
};

// XSS过滤
const xssEscape = (data) => {
  if (typeof data === 'string') {
    return data
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  } else if (Array.isArray(data)) {
    return data.map(xssEscape);
  } else if (typeof data === 'object' && data !== null) {
    const result = {};
    for (const key in data) {
      result[key] = xssEscape(data[key]);
    }
    return result;
  }
  return data;
};

// 密码强度验证
const validatePasswordStrength = (password) => {
  if (password.length < 8) {
    return { valid: false, message: '密码长度至少8位' };
  }
  
  const hasUpper = /[A-Z]/.test(password);
  const hasLower = /[a-z]/.test(password);
  const hasDigit = /\d/.test(password);
  const hasSpecial = /[^A-Za-z0-9]/.test(password);
  const ruleCount = [hasUpper, hasLower, hasDigit, hasSpecial].filter(Boolean).length;
  
  if (ruleCount < 3) {
    return { valid: false, message: '密码需包含大小写字母、数字、特殊字符中的至少3种' };
  }
  
  return { valid: true, message: '密码复杂度符合要求' };
};

// 防暴力登录
const recordFailedAttempt = (key) => {
  const now = Date.now() / 1000;
  let record = loginAttempts.get(key) || { fails: [], blockedUntil: 0 };
  
  // 清理过期记录
  record.fails = record.fails.filter(t => now - t < ATTEMPT_WINDOW);
  
  // 添加新失败记录
  record.fails.push(now);
  
  // 检查锁定状态
  if (record.blockedUntil > now) {
    loginAttempts.set(key, record);
    return { blocked: true, remain: Math.ceil(record.blockedUntil - now) };
  }
  
  // 达到失败阈值，锁定账号
  if (record.fails.length >= LOCK_THRESHOLD) {
    record.blockedUntil = now + LOCK_WINDOW_SECONDS;
    loginAttempts.set(key, record);
    return { blocked: true, remain: LOCK_WINDOW_SECONDS };
  }
  
  loginAttempts.set(key, record);
  return { blocked: false, remain: 0 };
};

// 清除登录尝试记录
const clearAttempts = (key) => {
  loginAttempts.delete(key);
};

// -------------------------- 缓存工具 --------------------------
// 缓存装饰器
const cacheResult = (expire = 300) => {
  return (target, propertyKey, descriptor) => {
    const originalMethod = descriptor.value;
    
    descriptor.value = async function (...args) {
      // Redis不可用则直接执行
      if (!redisClient) {
        return await originalMethod.apply(this, args);
      }
      
      try {
        // 生成缓存键
        const argsStr = args.map(arg => {
          if (typeof arg === 'object') {
            return JSON.stringify({
              user_id: arg.user_id,
              username: arg.username
            });
          }
          return String(arg);
        }).join('_');
        
        const key = `cache:${propertyKey}:${crypto.createHash('md5').update(argsStr).digest('hex')}`;
        
        // 获取缓存
        const cached = await redisClient.get(key);
        if (cached) {
          return JSON.parse(cached);
        }
        
        // 执行原方法
        const result = await originalMethod.apply(this, args);
        
        // 设置缓存
        await redisClient.setex(key, expire, JSON.stringify(result));
        return result;
      } catch (err) {
        console.error('缓存操作失败：', err.message);
        return await originalMethod.apply(this, args);
      }
    };
    
    return descriptor;
  };
};

// -------------------------- 成绩统计工具 --------------------------
// 计算级部排名
const calculateGradeRank = async (examDate, subject, score) => {
  const connection = await getDbConnection();
  try {
    const [rows] = await connection.execute(`
      SELECT COUNT(DISTINCT user_id) as count
      FROM scores 
      WHERE exam_date = ? AND subject = ? AND score > ?
    `, [examDate, subject, score]);
    
    return (rows[0].count || 0) + 1;
  } catch (err) {
    logAudit('计算级部排名', -1, 'system', 'unknown', `错误：${err.message}`, 'WARNING');
    return 0;
  } finally {
    await connection.end();
  }
};

// 计算班级排名
const calculateClassRank = async (userId, examDate, subject, score) => {
  const connection = await getDbConnection();
  try {
    // 获取学生班级
    const [userRows] = await connection.execute(`
      SELECT class_name FROM users WHERE id = ? LIMIT 1
    `, [userId]);
    
    if (!userRows[0]?.class_name) return 0;
    const className = userRows[0].class_name;
    
    // 计算排名
    const [rows] = await connection.execute(`
      SELECT COUNT(DISTINCT s.user_id) as count
      FROM scores s
      JOIN users u ON s.user_id = u.id
      WHERE s.exam_date = ? AND s.subject = ? AND s.score > ? AND u.class_name = ?
    `, [examDate, subject, score, className]);
    
    return (rows[0].count || 0) + 1;
  } catch (err) {
    logAudit('计算班级排名', userId, 'unknown', 'unknown', `错误：${err.message}`, 'WARNING');
    return 0;
  } finally {
    await connection.end();
  }
};

// 判断是否级部前十
const isGradeTopTen = async (examDate, subject, score) => {
  const connection = await getDbConnection();
  try {
    const [rows] = await connection.execute(`
      SELECT COUNT(DISTINCT user_id) as count
      FROM scores 
      WHERE exam_date = ? AND subject = ? AND score > ?
    `, [examDate, subject, score]);
    
    return (rows[0].count || 0) < 10;
  } catch (err) {
    logAudit('判断级部前十', -1, 'system', 'unknown', `错误：${err.message}`, 'WARNING');
    return false;
  } finally {
    await connection.end();
  }
};

// 获取历史总分（带缓存）
const getExamHistoryScores = async (userId) => {
  if (!redisClient) {
    return await getExamHistoryScoresImpl(userId);
  }
  
  try {
    const key = `cache:getExamHistoryScores:${userId}`;
    const cached = await redisClient.get(key);
    
    if (cached) {
      return JSON.parse(cached);
    }
    
    const result = await getExamHistoryScoresImpl(userId);
    await redisClient.setex(key, 600, JSON.stringify(result));
    return result;
  } catch (err) {
    console.error('缓存获取历史总分失败：', err.message);
    return await getExamHistoryScoresImpl(userId);
  }
};

// 历史总分实现
const getExamHistoryScoresImpl = async (userId) => {
  const connection = await getDbConnection();
  try {
    const [rows] = await connection.execute(`
      SELECT 
        exam_date,
        SUM(score) AS total_score
      FROM scores 
      WHERE user_id = ? 
      GROUP BY exam_date 
      ORDER BY exam_date ASC
    `, [userId]);
    
    return rows.map(row => ({
      exam_date: dayjs(row.exam_date).format('YYYY-MM-DD'),
      total_score: Math.round(Number(row.total_score) * 10) / 10
    }));
  } catch (err) {
    logAudit('获取历史总分', userId, 'unknown', 'unknown', `错误：${err.message}`, 'WARNING');
    return [];
  } finally {
    await connection.end();
  }
};

// 获取单科历史成绩（带缓存）
const getSubjectHistoryScores = async (userId) => {
  if (!redisClient) {
    return await getSubjectHistoryScoresImpl(userId);
  }
  
  try {
    const key = `cache:getSubjectHistoryScores:${userId}`;
    const cached = await redisClient.get(key);
    
    if (cached) {
      return JSON.parse(cached);
    }
    
    const result = await getSubjectHistoryScoresImpl(userId);
    await redisClient.setex(key, 600, JSON.stringify(result));
    return result;
  } catch (err) {
    console.error('缓存获取单科历史成绩失败：', err.message);
    return await getSubjectHistoryScoresImpl(userId);
  }
};

// 单科历史成绩实现
const getSubjectHistoryScoresImpl = async (userId) => {
  const connection = await getDbConnection();
  try {
    const [rows] = await connection.execute(`
      SELECT 
        subject,
        exam_date,
        score
      FROM scores 
      WHERE user_id = ? 
      ORDER BY subject ASC, exam_date ASC
    `, [userId]);
    
    const subjectData = {};
    rows.forEach(row => {
      const subject = row.subject;
      if (!subjectData[subject]) {
        subjectData[subject] = {
          subject,
          history: []
        };
      }
      
      subjectData[subject].history.push({
        exam_date: dayjs(row.exam_date).format('YYYY-MM-DD'),
        score: Math.round(Number(row.score) * 10) / 10
      });
    });
    
    return Object.values(subjectData);
  } catch (err) {
    logAudit('获取单科历史成绩', userId, 'unknown', 'unknown', `错误：${err.message}`, 'WARNING');
    return [];
  } finally {
    await connection.end();
  }
};

// 计算总分排名
const calculateExamTotalRank = async (userId, examDate, totalScore) => {
  const connection = await getDbConnection();
  try {
    // 获取学生班级
    const [userRows] = await connection.execute(`
      SELECT class_name FROM users WHERE id = ? LIMIT 1
    `, [userId]);
    const className = userRows[0]?.class_name;
    
    // 级部排名
    const [gradeRows] = await connection.execute(`
      SELECT COUNT(DISTINCT s1.user_id) AS rank_count
      FROM (
        SELECT user_id, SUM(score) AS total
        FROM scores 
        WHERE exam_date = ? 
        GROUP BY user_id
      ) s1
      WHERE s1.total > ?
    `, [examDate, totalScore]);
    
    const gradeRank = (gradeRows[0].rank_count || 0) + 1;
    
    // 班级排名
    let classRank = 0;
    if (className) {
      const [classRows] = await connection.execute(`
        SELECT COUNT(DISTINCT s1.user_id) AS rank_count
        FROM (
          SELECT s.user_id, SUM(s.score) AS total
          FROM scores s
          JOIN users u ON s.user_id = u.id
          WHERE s.exam_date = ? AND u.class_name = ?
          GROUP BY s.user_id
        ) s1
        WHERE s1.total > ?
      `, [examDate, className, totalScore]);
      
      classRank = (classRows[0].rank_count || 0) + 1;
    }
    
    return { grade_rank: gradeRank, class_rank: classRank };
  } catch (err) {
    logAudit('计算总分排名', userId, 'unknown', 'unknown', `错误：${err.message}`, 'WARNING');
    return { grade_rank: 0, class_rank: 0 };
  } finally {
    await connection.end();
  }
};

// 获取排名变化
const getRankChange = async (userId, examDate, currentGradeRank) => {
  const history = await getExamHistoryScores(userId);
  if (history.length < 2) {
    return { type: 'same', desc: '首次考试，无排名变化', change: 0 };
  }
  
  const examDates = history.map(item => item.exam_date);
  if (!examDates.includes(examDate)) {
    return { type: 'same', desc: '无排名变化', change: 0 };
  }
  
  const currentIdx = examDates.indexOf(examDate);
  if (currentIdx === 0) {
    return { type: 'same', desc: '首次考试，无排名变化', change: 0 };
  }
  
  const lastExamDate = history[currentIdx - 1].exam_date;
  const lastTotalScore = history[currentIdx - 1].total_score;
  const lastRankData = await calculateExamTotalRank(userId, lastExamDate, lastTotalScore);
  const lastGradeRank = lastRankData.grade_rank;
  
  const change = lastGradeRank - currentGradeRank;
  if (change > 0) {
    return { type: 'up', desc: `进步${change}名`, change };
  } else if (change < 0) {
    return { type: 'down', desc: `退步${Math.abs(change)}名`, change: Math.abs(change) };
  } else {
    return { type: 'same', desc: '排名不变', change: 0 };
  }
};

// -------------------------- 中间件 --------------------------
// 认证中间件
const authRequired = (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json(xssEscape({
        code: 401,
        message: '未登录，请先登录'
      }));
    }
    
    const token = authHeader.split(' ')[1].trim();
    const userInfo = verifyJwt(token);
    
    if (!userInfo) {
      return res.status(401).json(xssEscape({
        code: 401,
        message: '登录已过期或Token无效，请重新登录'
      }));
    }
    
    // 检查角色权限
    if (req.roleRequired && userInfo.role !== req.roleRequired) {
      logAudit('权限校验', userInfo.user_id, userInfo.username, req.ip, 
               `无${req.roleRequired}角色权限，操作被拒绝`, 'WARNING');
      
      return res.status(403).json(xssEscape({
        code: 403,
        message: `权限不足，仅支持${req.roleRequired}角色操作`
      }));
    }
    
    req.userInfo = userInfo;
    next();
  } catch (err) {
    logAudit('认证中间件异常', -1, 'unknown', req.ip, `错误：${err.message}`, 'ERROR');
    return res.status(500).json(xssEscape({
      code: 500,
      message: '认证失败'
    }));
  }
};

// 角色要求中间件
const requireRole = (role) => {
  return (req, res, next) => {
    req.roleRequired = role;
    authRequired(req, res, next);
  };
};

// 管理员权限中间件
const requireAdmin = (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json(xssEscape({
        code: 401,
        message: '未登录，请先登录'
      }));
    }
    
    const token = authHeader.split(' ')[1].trim();
    const userInfo = verifyJwt(token);
    
    if (!userInfo || userInfo.role !== 'admin') {
      logAudit('管理员权限校验', userInfo?.user_id || -1, userInfo?.username || 'unknown', req.ip, 
               '无管理员权限，操作被拒绝', 'WARNING');
      
      return res.status(403).json(xssEscape({
        code: 403,
        message: '权限不足，仅管理员可操作'
      }));
    }
    
    req.userInfo = userInfo;
    next();
  } catch (err) {
    logAudit('管理员认证异常', -1, 'unknown', req.ip, `错误：${err.message}`, 'ERROR');
    return res.status(500).json(xssEscape({
      code: 500,
      message: '认证失败'
    }));
  }
};

// 异常处理中间件
const handleException = (apiName) => {
  return (req, res, next) => {
    try {
      next();
    } catch (err) {
      const userId = req.userInfo?.user_id || -1;
      const username = req.userInfo?.username || 'unknown';
      
      logAudit(apiName, userId, username, req.ip, `异常：${err.message}`, 'ERROR');
      console.error(err.stack);
      
      return res.status(500).json(xssEscape({
        code: 500,
        message: '服务器内部错误，请稍后重试'
      }));
    }
  };
};

// -------------------------- API接口 --------------------------
// 健康检查
app.get('/api/health', (req, res) => {
  res.json({
    code: 200,
    message: '服务正常',
    env: ENV,
    time: dayjs().format('YYYY-MM-DD HH:mm:ss')
  });
});

// 登录接口
app.route('/login')
  .options((req, res) => res.json({ code: 200, message: 'OK' }))
  .get((req, res) => {
    res.json(xssEscape({
      code: 200,
      message: '登录接口正常，请使用POST提交JSON数据'
    }));
  })
  .post(handleException('用户登录'), async (req, res) => {
    try {
      const data = req.body;
      if (!data) {
        return res.status(415).json(xssEscape({
          code: 400,
          message: '请提交JSON数据（Content-Type: application/json）'
        }));
      }
      
      const username = (data.username || data.account || '').trim();
      const password = (data.password || '').trim();
      
      // 防暴力登录
      const clientKey = username || req.ip;
      const { blocked, remain } = recordFailedAttempt(clientKey);
      
      if (blocked) {
        logAudit('用户登录', -1, username, req.ip, 
                 `登录失败次数过多，锁定${remain}秒`, 'WARNING');
        
        return res.status(429).json(xssEscape({
          code: 429,
          message: `登录失败次数过多，已锁定${remain}秒`
        }));
      }
      
      // 参数验证
      if (!username || !/^[\u4e00-\u9fa5A-Za-z0-9_]{1,50}$/.test(username)) {
        return res.status(400).json(xssEscape({
          code: 400,
          message: '用户名仅支持中文、英文、数字、下划线'
        }));
      }
      
      if (!password) {
        return res.status(400).json(xssEscape({
          code: 400,
          message: '请输入密码'
        }));
      }
      
      // 查询用户
      const connection = await getDbConnection();
      const [rows] = await connection.execute(`
        SELECT id, username, password, role, id_card, class_name FROM users WHERE username = ? LIMIT 1
      `, [username]);
      
      await connection.end();
      
      if (!rows[0]) {
        logAudit('用户登录', -1, username, req.ip, '账号不存在', 'WARNING');
        return res.status(401).json(xssEscape({
          code: 401,
          message: '账号或密码错误'
        }));
      }
      
      const user = rows[0];
      if (verifyPassword(password, user.password)) {
        clearAttempts(clientKey);
        const token = generateJwt(user.id, user.username, user.role);
        
        logAudit('用户登录', user.id, user.username, req.ip, 
                 `角色：${user.role}，登录成功`);
        
        return res.json(xssEscape({
          code: 200,
          message: '登录成功',
          token,
          user: {
            id: user.id,
            username: user.username,
            role: user.role,
            id_card: user.id_card,
            class_name: user.class_name
          }
        }));
      } else {
        logAudit('用户登录', user.id, username, req.ip, '密码错误', 'WARNING');
        return res.status(401).json(xssEscape({
          code: 401,
          message: '账号或密码错误'
        }));
      }
    } catch (err) {
      logAudit('登录接口异常', -1, 'unknown', req.ip, `错误：${err.message}`, 'ERROR');
      console.error(err.stack);
      return res.status(500).json(xssEscape({
        code: 500,
        message: '登录失败'
      }));
    }
  });

// -------------------------- 管理员接口 --------------------------
// 查询所有教师
app.route('/api/admin/teachers')
  .options((req, res) => res.json({ code: 200, message: 'OK' }))
  .get(requireAdmin, handleException('管理员查询所有教师'), async (req, res) => {
    const connection = await getDbConnection();
    const [rows] = await connection.execute(`
      SELECT id, username, role, created_at 
      FROM users 
      WHERE role = 'teacher' 
      ORDER BY created_at DESC;
    `);
    await connection.end();
    
    const teachers = rows.map(teacher => ({
      ...teacher,
      created_at: teacher.created_at ? dayjs(teacher.created_at).format('YYYY-MM-DD HH:mm:ss') : null
    }));
    
    logAudit('管理员查询所有教师', req.userInfo.user_id, req.userInfo.username, req.ip, 
             `查询到${teachers.length}名教师`);
    
    res.json(xssEscape({
      code: 200,
      message: '查询成功',
      data: teachers
    }));
  });

// 新增教师
app.route('/api/admin/teacher/add')
  .options((req, res) => res.json({ code: 200, message: 'OK' }))
  .post(requireAdmin, handleException('管理员新增教师'), async (req, res) => {
    const data = req.body;
    
    if (!data || !data.username || !data.password) {
      return res.status(400).json(xssEscape({
        code: 400,
        message: '用户名和密码不能为空'
      }));
    }
    
    if (!/^[\u4e00-\u9fa5A-Za-z0-9_]{1,50}$/.test(data.username)) {
      return res.status(400).json(xssEscape({
        code: 400,
        message: '用户名仅支持中文、英文、数字、下划线'
      }));
    }
    
    const { valid, message } = validatePasswordStrength(data.password);
    if (!valid) {
      return res.status(400).json(xssEscape({
        code: 400,
        message
      }));
    }
    
    // 检查用户名是否存在
    const connection = await getDbConnection();
    let [rows] = await connection.execute(`
      SELECT id FROM users WHERE username = ?;
    `, [data.username]);
    
    if (rows[0]) {
      await connection.end();
      return res.status(400).json(xssEscape({
        code: 400,
        message: '用户名已存在'
      }));
    }
    
    // 添加教师
    const hashedPwd = hashPassword(data.password);
    await connection.execute(`
      INSERT INTO users (username, password, role, id_card, class_name) 
      VALUES (?, ?, 'teacher', NULL, NULL);
    `, [data.username, hashedPwd]);
    
    // 获取新增教师信息
    [rows] = await connection.execute(`
      SELECT id, username FROM users WHERE username = ?;
    `, [data.username]);
    
    await connection.commit();
    await connection.end();
    
    const newTeacher = rows[0];
    logAudit('管理员新增教师', req.userInfo.user_id, req.userInfo.username, req.ip, 
             `新增教师：${data.username}（ID：${newTeacher.id}）`);
    
    res.json(xssEscape({
      code: 200,
      message: '教师添加成功',
      data: newTeacher
    }));
  });

// 删除教师
app.route('/api/admin/teacher/delete/:teacherId')
  .options((req, res) => res.json({ code: 200, message: 'OK' }))
  .delete(requireAdmin, handleException('管理员删除教师'), async (req, res) => {
    const teacherId = parseInt(req.params.teacherId);
    
    const connection = await getDbConnection();
    let [rows] = await connection.execute(`
      SELECT id, username FROM users WHERE id = ? AND role = 'teacher';
    `, [teacherId]);
    
    if (!rows[0]) {
      await connection.end();
      return res.status(400).json(xssEscape({
        code: 400,
        message: '教师不存在'
      }));
    }
    
    const teacher = rows[0];
    await connection.execute(`
      DELETE FROM users WHERE id = ? AND role = 'teacher';
    `, [teacherId]);
    
    await connection.commit();
    await connection.end();
    
    logAudit('管理员删除教师', req.userInfo.user_id, req.userInfo.username, req.ip, 
             `删除教师：${teacher.username}（ID：${teacherId}）`);
    
    res.json(xssEscape({
      code: 200,
      message: '教师删除成功'
    }));
  });

// -------------------------- 教师接口 --------------------------
// 搜索学生
app.route('/api/teacher/student/search')
  .options((req, res) => res.json({ code: 200, message: 'OK' }))
  .get(requireRole('teacher'), handleException('教师搜索学生'), async (req, res) => {
    const keyword = req.query.keyword?.trim() || '';
    
    if (!keyword) {
      return res.status(400).json(xssEscape({
        code: 400,
        message: '搜索关键词不能为空'
      }));
    }
    
    const connection = await getDbConnection();
    const [rows] = await connection.execute(`
      SELECT id, username AS name, id_card AS idCard, class_name AS className 
      FROM users 
      WHERE role = 'student' 
      AND (username LIKE ? OR id LIKE ? OR id_card LIKE ?)
      ORDER BY created_at DESC;
    `, [`%${keyword}%`, `%${keyword}%`, `%${keyword}%`]);
    
    await connection.end();
    
    const students = rows.map(student => ({
      id: student.id,
      name: student.name,
      no: student.id,
      idCard: student.idCard || '',
      className: student.className || ''
    }));
    
    logAudit('教师搜索学生', req.userInfo.user_id, req.userInfo.username, req.ip, 
             `关键词：${keyword}，搜索到${students.length}名学生`);
    
    res.json(xssEscape({
      code: 200,
      message: '搜索成功',
      data: students
    }));
  });

// 查询学生列表
app.route('/api/teacher/student/list')
  .options((req, res) => res.json({ code: 200, message: 'OK' }))
  .get(requireRole('teacher'), handleException('教师查询学生列表'), async (req, res) => {
    const connection = await getDbConnection();
    const [rows] = await connection.execute(`
      SELECT id, username, class_name, created_at 
      FROM users 
      WHERE role = 'student' 
      ORDER BY created_at DESC;
    `);
    await connection.end();
    
    const students = rows.map(student => ({
      ...student,
      created_at: student.created_at ? dayjs(student.created_at).format('YYYY-MM-DD HH:mm:ss') : null
    }));
    
    logAudit('教师查询学生列表', req.userInfo.user_id, req.userInfo.username, req.ip, 
             `查询到${students.length}名学生`);
    
    res.json(xssEscape({
      code: 200,
      message: '查询学生列表成功',
      data: students
    }));
  });

// 添加学生
app.route('/api/teacher/student/add')
  .options((req, res) => res.json({ code: 200, message: 'OK' }))
  .post(requireRole('teacher'), handleException('教师添加学生'), async (req, res) => {
    const data = req.body;
    
    if (!data) {
      return res.status(400).json(xssEscape({
        code: 400,
        message: '请提交JSON数据'
      }));
    }
    
    const studentName = data.username?.trim() || '';
    const studentIdCard = data.id_card?.trim() || '';
    const className = data.class_name?.trim() || '';
    
    if (!studentName) {
      return res.status(400).json(xssEscape({
        code: 400,
        message: '请输入学生姓名'
      }));
    }
    
    if (!studentIdCard || !/^\d{17}[\dXx]$/.test(studentIdCard)) {
      return res.status(400).json(xssEscape({
        code: 400,
        message: '请输入18位有效身份证号'
      }));
    }
    
    if (!className) {
      return res.status(400).json(xssEscape({
        code: 400,
        message: '请输入班级名称'
      }));
    }
    
    const connection = await getDbConnection();
    
    // 检查身份证号是否已绑定
    let [rows] = await connection.execute(`
      SELECT id FROM users WHERE id_card = ? LIMIT 1
    `, [studentIdCard]);
    
    if (rows[0]) {
      await connection.end();
      return res.status(400).json(xssEscape({
        code: 400,
        message: '该身份证号已绑定学生'
      }));
    }
    
    // 检查用户名是否存在
    [rows] = await connection.execute(`
      SELECT id FROM users WHERE username = ? LIMIT 1
    `, [studentName]);
    
    if (rows[0]) {
      await connection.end();
      return res.status(400).json(xssEscape({
        code: 400,
        message: '该学生姓名已存在'
      }));
    }
    
    // 添加学生
    const initialPwd = studentIdCard.slice(-6);
    const hashedPwd = hashPassword(initialPwd);
    
    await connection.execute(`
      INSERT INTO users (username, password, role, id_card, class_name, bind_time)
      VALUES (?, ?, 'student', ?, ?, NOW())
    `, [studentName, hashedPwd, studentIdCard, className]);
    
    const [insertRows] = await connection.execute(`
      SELECT LAST_INSERT_ID() as id
    `);
    const studentId = insertRows[0].id;
    
    await connection.commit();
    await connection.end();
    
    logAudit('教师添加学生', req.userInfo.user_id, req.userInfo.username, req.ip, 
             `新增学生：${studentName}（ID：${studentId}，班级：${className}）`);
    
    res.json(xssEscape({
      code: 200,
      message: '学生添加成功',
      data: {
        student_id: studentId,
        student_name: studentName,
        class_name: className,
        initial_password: initialPwd
      }
    }));
  });

// 添加成绩
app.route('/api/teacher/add-score')
  .options((req, res) => res.json({ code: 200, message: 'OK' }))
  .post(requireRole('teacher'), handleException('教师添加成绩'), async (req, res) => {
    const data = req.body;
    
    if (!data) {
      return res.status(400).json(xssEscape({
        code: 400,
        message: '请提交JSON数据'
      }));
    }
    
    const studentId = data.student_id;
    const subject = data.subject?.trim() || '';
    const score = data.score;
    const examDate = data.exam_date?.trim() || '';
    
    if (!studentId || typeof studentId !== 'number') {
      return res.status(400).json(xssEscape({
        code: 400,
        message: '请选择有效学生'
      }));
    }
    
    if (!subject) {
      return res.status(400).json(xssEscape({
        code: 400,
        message: '请输入科目名称'
      }));
    }
    
    if (score === undefined || typeof score !== 'number' || score < 0 || score > 100) {
      return res.status(400).json(xssEscape({
        code: 400,
        message: '请输入0-100的有效分数'
      }));
    }
    
    if (!examDate || !/^\d{4}-\d{2}-\d{2}$/.test(examDate)) {
      return res.status(400).json(xssEscape({
        code: 400,
        message: '请输入正确格式的考试日期（如2024-06-30）'
      }));
    }
    
    const connection = await getDbConnection();
    
    // 检查学生是否存在
    let [rows] = await connection.execute(`
      SELECT id, username FROM users WHERE id = ? AND role = 'student' LIMIT 1
    `, [studentId]);
    
    if (!rows[0]) {
      await connection.end();
      return res.status(400).json(xssEscape({
        code: 400,
        message: '所选学生不存在'
      }));
    }
    
    const student = rows[0];
    
    // 检查成绩是否已存在
    [rows] = await connection.execute(`
      SELECT id FROM scores 
      WHERE user_id = ? AND subject = ? AND exam_date = ? 
      LIMIT 1
    `, [studentId, subject, examDate]);
    
    if (rows[0]) {
      await connection.end();
      return res.status(400).json(xssEscape({
        code: 400,
        message: `该学生${examDate}的${subject}成绩已存在`
      }));
    }
    
    // 添加成绩
    await connection.execute(`
      INSERT INTO scores (user_id, subject, score, exam_date, created_by)
      VALUES (?, ?, ?, ?, ?)
    `, [studentId, subject, score, examDate, req.userInfo.user_id]);
    
    await connection.commit();
    await connection.end();
    
    // 清除缓存
    if (redisClient) {
      try {
        await redisClient.del(`cache:getExamHistoryScores:${studentId}`);
        await redisClient.del(`cache:getSubjectHistoryScores:${studentId}`);
      } catch (err) {
        console.error('清除缓存失败：', err.message);
      }
    }
    
    logAudit('教师添加成绩', req.userInfo.user_id, req.userInfo.username, req.ip, 
             `为学生${student.username}（ID：${studentId}）添加${examDate}的${subject}成绩：${score}`);
    
    res.json(xssEscape({
      code: 200,
      message: `成功添加${student.username}的${subject}成绩`,
      data: {
        student_name: student.username,
        subject,
        score,
        exam_date: examDate
      }
    }));
  });

// 教师修改密码
app.route('/api/teacher/change-password')
  .options((req, res) => res.json({ code: 200, message: 'OK' }))
  .post(requireRole('teacher'), handleException('教师修改密码'), async (req, res) => {
    const data = req.body;
    
    if (!data) {
      return res.status(400).json(xssEscape({
        code: 400,
        message: '请提交JSON数据'
      }));
    }
    
    const oldPassword = data.old_password?.trim() || '';
    const newPassword = data.new_password?.trim() || '';
    const userId = req.userInfo.user_id;
    
    if (!oldPassword) {
      return res.status(400).json(xssEscape({
        code: 400,
        message: '请输入原密码'
      }));
    }
    
    const { valid, message } = validatePasswordStrength(newPassword);
    if (!valid) {
      return res.status(400).json(xssEscape({
        code: 400,
        message
      }));
    }
    
    if (oldPassword === newPassword) {
      return res.status(400).json(xssEscape({
        code: 400,
        message: '新密码不能与原密码相同'
      }));
    }
    
    // 验证原密码
    const connection = await getDbConnection();
    const [rows] = await connection.execute(`
      SELECT password FROM users WHERE id = ? LIMIT 1
    `, [userId]);
    
    if (!rows[0]) {
      await connection.end();
      return res.status(400).json(xssEscape({
        code: 400,
        message: '用户不存在'
      }));
    }
    
    const user = rows[0];
    if (!verifyPassword(oldPassword, user.password)) {
      await connection.end();
      logAudit('教师修改密码', userId, req.userInfo.username, req.ip, '原密码错误', 'WARNING');
      
      return res.status(400).json(xssEscape({
        code: 400,
        message: '原密码错误'
      }));
    }
    
    // 修改密码
    const hashedNewPwd = hashPassword(newPassword);
    await connection.execute(`
      UPDATE users SET password = ? WHERE id = ?
    `, [hashedNewPwd, userId]);
    
    await connection.commit();
    await connection.end();
    
    logAudit('教师修改密码', userId, req.userInfo.username, req.ip, '密码修改成功');
    
    res.json(xssEscape({
      code: 200,
      message: '密码修改成功，请重新登录'
    }));
  });

// -------------------------- 学生接口 --------------------------
// 查询自身成绩
app.route('/api/student/score/my')
  .options((req, res) => res.json({ code: 200, message: 'OK' }))
  .post(requireRole('student'), handleException('学生查询自身成绩'), async (req, res) => {
    const userId = req.userInfo.user_id;
    const connection = await getDbConnection();
    
    const [rows] = await connection.execute(`
      SELECT 
        subject,
        score,
        exam_date
      FROM scores 
      WHERE user_id = ? 
      ORDER BY exam_date DESC, subject ASC
    `, [userId]);
    
    await connection.end();
    
    // 按考试日期分组
    const examGroup = {};
    for (const item of rows) {
      const examDate = dayjs(item.exam_date).format('YYYY-MM-DD');
      
      if (!examGroup[examDate]) {
        examGroup[examDate] = {
          exam_date: examDate,
          subjects: [],
          total_score: 0.0,
          subject_count: 0
        };
      }
      
      // 判断是否级部前十
      const isTopTen = await isGradeTopTen(examDate, item.subject, item.score);
      
      examGroup[examDate].subjects.push({
        subject: item.subject,
        score: Math.round(Number(item.score) * 10) / 10,
        exam_date: examDate,
        is_grade_top_ten: isTopTen
      });
      
      examGroup[examDate].total_score += Number(item.score);
      examGroup[examDate].subject_count += 1;
    }
    
    // 计算排名
    const examList = [];
    for (const [examDate, data] of Object.entries(examGroup)) {
      const rankData = await calculateExamTotalRank(userId, examDate, data.total_score);
      
      examList.push({
        exam_date: data.exam_date,
        total_score: Math.round(data.total_score * 10) / 10,
        subject_count: data.subject_count,
        grade_rank: rankData.grade_rank,
        class_rank: rankData.class_rank,
        subjects: data.subjects
      });
    }
    
    // 按考试日期倒序排序
    examList.sort((a, b) => dayjs(b.exam_date).unix() - dayjs(a.exam_date).unix());
    
    // 获取历史成绩
    const historyScores = await getExamHistoryScores(userId);
    const subjectHistory = await getSubjectHistoryScores(userId);
    
    logAudit('学生查询自身成绩', userId, req.userInfo.username, req.ip, 
             `查询到${examList.length}次考试成绩`);
    
    res.json(xssEscape({
      code: 200,
      message: '成绩查询成功',
      data: {
        exam_list: examList,
        history_scores: historyScores,
        subject_history: subjectHistory
      }
    }));
  });

// 查询考试详情
app.route('/api/student/score/detail')
  .options((req, res) => res.json({ code: 200, message: 'OK' }))
  .post(requireRole('student'), handleException('学生查询考试详情'), async (req, res) => {
    const data = req.body;
    
    if (!data || !data.exam_date) {
      return res.status(400).json(xssEscape({
        code: 400,
        message: '请传入考试日期'
      }));
    }
    
    const examDate = data.exam_date.trim();
    const userId = req.userInfo.user_id;
    
    const connection = await getDbConnection();
    const [rows] = await connection.execute(`
      SELECT 
        subject,
        score,
        exam_date
      FROM scores 
      WHERE user_id = ? AND exam_date = ?
      ORDER BY subject ASC
    `, [userId, examDate]);
    
    await connection.end();
    
    if (rows.length === 0) {
      return res.status(400).json(xssEscape({
        code: 400,
        message: '该考试日期无成绩数据'
      }));
    }
    
    // 计算总分和排名
    const totalScore = rows.reduce((sum, item) => sum + Number(item.score), 0);
    const rankData = await calculateExamTotalRank(userId, examDate, totalScore);
    const rankChange = await getRankChange(userId, examDate, rankData.grade_rank);
    
    // 处理单科数据
    const subjectList = [];
    for (const item of rows) {
      const subject = item.subject;
      const score = Number(item.score);
      
      subjectList.push({
        subject,
        score: Math.round(score * 10) / 10,
        exam_date: examDate,
        is_grade_top_ten: await isGradeTopTen(examDate, subject, score),
        grade_rank: await calculateGradeRank(examDate, subject, score),
        class_rank: await calculateClassRank(userId, examDate, subject, score)
      });
    }
    
    // 获取历史成绩
    const historyScores = await getExamHistoryScores(userId);
    const subjectHistory = await getSubjectHistoryScores(userId);
    
    logAudit('学生查询考试详情', userId, req.userInfo.username, req.ip, 
             `查询${examDate}考试详情，共${subjectList.length}科成绩`);
    
    res.json(xssEscape({
      code: 200,
      message: '考试详情查询成功',
      data: {
        exam_date: examDate,
        total_score: Math.round(totalScore * 10) / 10,
        grade_rank: rankData.grade_rank,
        class_rank: rankData.class_rank,
        rank_change: rankChange,
        subjects: subjectList,
        history_scores: historyScores,
        subject_history: subjectHistory
      }
    }));
  });

// 学生修改密码
app.route('/api/student/change-password')
  .options((req, res) => res.json({ code: 200, message: 'OK' }))
  .post(requireRole('student'), handleException('学生修改密码'), async (req, res) => {
    const data = req.body;
    
    if (!data) {
      return res.status(400).json(xssEscape({
        code: 400,
        message: '请提交JSON数据'
      }));
    }
    
    const oldPassword = data.old_password?.trim() || '';
    const newPassword = data.new_password?.trim() || '';
    const userId = req.userInfo.user_id;
    
    if (!oldPassword) {
      return res.status(400).json(xssEscape({
        code: 400,
        message: '请输入原密码'
      }));
    }
    
    const { valid, message } = validatePasswordStrength(newPassword);
    if (!valid) {
      return res.status(400).json(xssEscape({
        code: 400,
        message
      }));
    }
    
    if (oldPassword === newPassword) {
      return res.status(400).json(xssEscape({
        code: 400,
        message: '新密码不能与原密码相同'
      }));
    }
    
    // 验证原密码
    const connection = await getDbConnection();
    const [rows] = await connection.execute(`
      SELECT password FROM users WHERE id = ? LIMIT 1
    `, [userId]);
    
    if (!rows[0]) {
      await connection.end();
      return res.status(400).json(xssEscape({
        code: 400,
        message: '用户不存在'
      }));
    }
    
    const user = rows[0];
    if (!verifyPassword(oldPassword, user.password)) {
      await connection.end();
      logAudit('学生修改密码', userId, req.userInfo.username, req.ip, '原密码错误', 'WARNING');
      
      return res.status(400).json(xssEscape({
        code: 400,
        message: '原密码错误'
      }));
    }
    
    // 修改密码
    const hashedNewPwd = hashPassword(newPassword);
    await connection.execute(`
      UPDATE users SET password = ? WHERE id = ?
    `, [hashedNewPwd, userId]);
    
    await connection.commit();
    await connection.end();
    
    logAudit('学生修改密码', userId, req.userInfo.username, req.ip, '密码修改成功');
    
    res.json(xssEscape({
      code: 200,
      message: '密码修改成功，请重新登录'
    }));
  });

// -------------------------- 静态网页托管 --------------------------
// 托管api文件夹下的静态文件
app.use('/api', express.static('api'));

// 首页路由
app.get('/', (req, res) => {
  res.sendFile('index.html', { root: 'api' });
});

// -------------------------- 启动服务 --------------------------
// 初始化数据库并启动服务
const startServer = async () => {
  try {
    // 初始化数据库
    await initializeDatabase();
    
    // 启动HTTP服务
    app.listen(PORT, () => {
      console.log('='.repeat(60));
      console.log('成绩管理系统后端服务启动成功！');
      console.log(`服务环境：${ENV}`);
      console.log(`服务地址：http://localhost:${PORT}`);
      console.log('='.repeat(60));
    });
  } catch (err) {
    console.error('服务启动失败：', err.message);
    process.exit(1);
  }
};

// Vercel Serverless适配
if (process.env.VERCEL) {
  module.exports = app;
} else {
  // 本地启动
  startServer();
}
