const express = require('express');
const path = require('path');
const bodyParser = require('body-parser');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const { connectToDatabase, getUsersCollection } = require('./models/db.js');
const { ObjectId } = require('mongodb');
const userRoutes = require('./routes/userRoutes.js');
const postRoutes = require('./routes/postRoutes.js');
const commentRoutes = require('./routes/commentRoutes.js');
const PingRoutes = require('./routes/PingRoutes.js');
const randomstring = require('randomstring');
require('dotenv').config();

const app = express();
const http = require('http').createServer(app);
const port = process.env.PORT || 3001;
const jwtSecret = process.env.JWT_SECRET;

if (!jwtSecret) {
    throw new Error('JWT_SECRET 환경 변수가 설정되지 않았습니다.');
}

app.set('trust proxy', 1);

(async () => {
    try {
        await connectToDatabase();
    } catch (err) {
        console.error('❌ MongoDB 연결 실패:', err);
        process.exit(1); // 서버 종료
    }
})();

// 미들웨어 설정
app.use(express.json());
app.use(cors());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

app.use(express.static(path.join(__dirname, 'client/dist')));

async function generateUniqueUserHandle(usersCollection) {
    let userHandle;
    let isUnique = false;

    while (!isUnique) {
        userHandle = `user-${randomstring.generate({ length: 6, charset: 'numeric' })}`;
        const existingUser = await usersCollection.findOne({ userHandle });
        if (!existingUser) {
            isUnique = true;
        }
    }
    return userHandle;
}

async function generateRandomDisplayName() {
    return `User_${randomstring.generate({ length: 8, charset: 'alphabetic' })}`;
}

// JWT 토큰 검증 미들웨어
const verifyToken = async (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1];
    
    if (!token) {
        return next();
    }

    try {
        const decoded = jwt.verify(token, jwtSecret);
        req.user = decoded;
        next();
    } catch (error) {
        return res.status(401).json({ error: '유효하지 않은 토큰입니다.' });
    }
};

// 유저 정보 업데이트 미들웨어
app.use(verifyToken);
app.use(async (req, res, next) => {
    if (req.user && req.user.id) {
        try {
            const usersCollection = getUsersCollection();
            if (!usersCollection) throw new Error('MongoDB 연결이 설정되지 않음.');

            const updatedUser = await usersCollection.findOne({ _id: new ObjectId(req.user.id) });

            if (!updatedUser) {
                return res.status(401).json({ error: '사용자를 찾을 수 없습니다. 다시 로그인하세요.' });
            }

            // user.DisplayName 없으면 생성
            if (!updatedUser.DisplayName) {
                updatedUser.DisplayName = await generateRandomDisplayName();
                await usersCollection.updateOne(
                    { _id: updatedUser._id },
                    { $set: { DisplayName: updatedUser.DisplayName } }
                );
            }

            // user.userHandle 없으면 생성
            if (!updatedUser.userHandle) {
                updatedUser.userHandle = await generateUniqueUserHandle(usersCollection);
                await usersCollection.updateOne(
                    { _id: updatedUser._id },
                    { $set: { userHandle: updatedUser.userHandle } }
                );
            }

            // user.rank가 없으면 기본값 0 설정
            if (updatedUser.rank === undefined) {
                updatedUser.rank = 0;
                await usersCollection.updateOne(
                    { _id: updatedUser._id },
                    { $set: { rank: updatedUser.rank } }
                );
            }

            // req.user 업데이트
            req.user = {
                id: updatedUser._id.toString(),
                display_name: updatedUser.DisplayName,
                user_handle: updatedUser.userHandle,
                rank: updatedUser.rank,
            };

        } catch (error) {
            console.error('유저 조회 중 오류 발생:', error);
            return res.status(500).json({ error: '서버 오류' });
        }
    }
    next();
});

// JWT 토큰 생성 헬퍼 함수 (다른 파일로 분리해도 좋음)
app.locals.generateToken = (user) => {
    return jwt.sign(
        {
            id: user._id.toString(),
            display_name: user.DisplayName,
            user_handle: user.userHandle,
            rank: user.rank || 0
        },
        jwtSecret,
        { expiresIn: '14d' } // 14일 유효기간
    );
};

// API 라우트 등록
app.use('/', userRoutes);
app.use('/', postRoutes);
app.use('/', commentRoutes);
app.use('/', PingRoutes);

// 서버 실행
http.listen(port, () => {
    console.log(`✅ Server running at http://localhost:${port}/`);
});