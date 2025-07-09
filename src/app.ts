import express, { Request, Response, NextFunction } from 'express';
import cors from 'cors';
import { PrismaClient } from '@prisma/client';
import bcrypt from 'bcrypt';
import jwt, { JwtPayload } from 'jsonwebtoken';

const app = express();
const prisma = new PrismaClient();
const JWT_SECRET = 'your_jwt_secret_key'; // 生产环境应使用环境变量

// 扩展 Express Request 类型
declare global {
  namespace Express {
    interface Request {
      user?: { userId: number };
    }
  }
}

app.use(cors());
app.use(express.json());

// 基础路由
app.get('/', (req: Request, res: Response) => {
  res.send('后端服务已启动');
});

// 获取所有盲盒
app.get('/api/boxes', async (req: Request, res: Response) => {
  try {
    const boxes = await prisma.box.findMany();
    res.json(boxes);
  } catch (error) {
    res.status(500).json({ error: '获取盲盒失败' });
  }
});

// 用户注册
app.post('/api/register', async (req: Request, res: Response) => {
  try {
    const { username, password }: { username: string; password: string } = req.body;
    
    // 验证输入
    if (!username || !password) {
      return res.status(400).json({ error: '用户名和密码不能为空' });
    }
    
    // 检查用户名是否已存在
    const existingUser = await prisma.user.findUnique({
      where: { username },
    });
    
    if (existingUser) {
      return res.status(400).json({ error: '用户名已存在' });
    }
    
    // 哈希密码
    const hashedPassword = await bcrypt.hash(password, 10);
    
    // 创建用户
    const user = await prisma.user.create({
      data: {
        username,
        password: hashedPassword
      }
    });
    
    res.status(201).json({ 
      id: user.id, 
      username: user.username 
    });
  } catch (error) {
    console.error('注册失败:', error);
    res.status(500).json({ error: '注册失败' });
  }
});

// 用户登录
app.post('/api/login', async (req: Request, res: Response) => {
  try {
    const { username, password }: { username: string; password: string } = req.body;
    
    // 验证输入
    if (!username || !password) {
      return res.status(400).json({ error: '用户名和密码不能为空' });
    }
    
    // 查找用户
    const user = await prisma.user.findUnique({ 
      where: { username },
    });
    
    // 验证用户和密码
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ error: '用户名或密码错误' });
    }
    
    // 生成JWT令牌
    const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '1h' });
    
    res.json({ 
      token, 
      user: {
        id: user.id,
        username: user.username
      }
    });
  } catch (error) {
    console.error('登录失败:', error);
    res.status(500).json({ error: '登录失败' });
  }
});

// JWT验证中间件
function authenticateToken(req: Request, res: Response, next: NextFunction) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ error: '未提供认证令牌' });
  }
  
  jwt.verify(token, JWT_SECRET, (err: jwt.VerifyErrors | null, decoded: string | JwtPayload | undefined) => {
    if (err) {
      return res.status(403).json({ error: '无效的认证令牌' });
    }
    
    if (typeof decoded === 'object' && decoded !== null) {
      req.user = { userId: (decoded as JwtPayload).userId };
    }
    next();
  });
}

// 受保护的盲盒抽取路由
app.post('/api/draw', authenticateToken, async (req: Request, res: Response) => {
  const { boxId } = req.body;
  const userId = req.user?.userId;

  if (!userId) {
    return res.status(401).json({ error: '未认证用户' });
  }

  try {
    // 验证盲盒
    const box = await prisma.box.findUnique({ where: { id: boxId } });
    if (!box) {
      return res.status(404).json({ error: '盲盒不存在' });
    }
    if (box.claimed) {
      return res.status(400).json({ error: '该盲盒已被抽取' });
    }

    // 创建抽取记录
    const drawRecord = await prisma.drawRecord.create({
      data: {
        userId,
        boxId,
      },
      include: {
        box: true,
        user: {
          select: {
            id: true,
            username: true
          }
        }
      }
    });

    // 更新盲盒状态
    await prisma.box.update({
      where: { id: boxId },
      data: { claimed: true }
    });

    res.json({
      success: true,
      box: drawRecord.box,
      user: drawRecord.user
    });
  } catch (error) {
    console.error('抽取失败:', error);
    res.status(500).json({ error: '抽取失败' });
  }
});

// 初始化数据
async function initializeData() {
  try {
    // 清空现有数据
    await prisma.drawRecord.deleteMany();
    await prisma.box.deleteMany();
    await prisma.user.deleteMany();

    // 创建测试用户
    const hashedPassword = await bcrypt.hash('test123', 10);
    await prisma.user.create({
      data: { 
        username: 'testuser',
        password: hashedPassword
      },
    });

    // 创建9个盲盒
    const boxData = [
      { name: "神秘盲盒 #1", description: "破🥚壳而出的蛋黄猫", imageUrl: "public/img/hi.gif", claimed: false },
      { name: "神秘盲盒 #2", description: "扮演大圣的蛋黄猫", imageUrl: "public/img/swk.gif", claimed: false },
      { name: "神秘盲盒 #3", description: "因太肥胖而头被卡住的蛋黄猫", imageUrl: "public/img/chongya.gif", claimed: false },
      { name: "神秘盲盒 #4", description: "专心摸🐟的蛋黄猫", imageUrl: "public/img/moyu.gif", claimed: false },
      { name: "神秘盲盒 #5", description: "惊喜隐藏款！嘿嘿～我是奶龙😉", imageUrl: "public/img/nl.gif", claimed: false },
      { name: "神秘盲盒 #6", description: "边听歌🎵边写oj的蛋黄猫", imageUrl: "public/img/tingge.gif", claimed: false },
      { name: "神秘盲盒 #7", description: "正在嘚瑟地看着你的蛋黄猫", imageUrl: "public/img/dese.gif", claimed: false },
      { name: "神秘盲盒 #8", description: "爱打篮球🏀的蛋黄猫", imageUrl: "public/img/dalanqiu.gif", claimed: false },
      { name: "神秘盲盒 #9", description: "展示美妙舞姿的蛋黄猫", imageUrl: "public/img/tiaowu.gif", claimed: false }
    ];

    await prisma.box.createMany({ data: boxData });
    console.log('数据初始化完成');
  } catch (error) {
    console.error('初始化失败:', error);
  }
}

// 启动服务器
const PORT = process.env.PORT || 3000;
app.listen(PORT, async () => {
  await initializeData();
  console.log(`服务器运行在 http://localhost:${PORT}`);
});