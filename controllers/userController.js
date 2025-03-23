const bcrypt = require('bcrypt');
const { getUsersCollection, getIdUsedCollection } = require('../models/db.js');
const rateLimit = require('express-rate-limit');
const { ObjectId } = require('mongodb');

const jwt = require('jsonwebtoken');
const jwtSecret = process.env.JWT_SECRET;

if (!jwtSecret) {
    throw new Error('JWT_SECRET 환경 변수가 설정되지 않았습니다.');
}

const saltRounds = 10;

function generateToken(user) {
    return jwt.sign(
        { 
            id: user._id.toString(), 
            display_name: user.DisplayName,
            user_handle: user.userHandle, 
            rank: user.rank 
        },
        jwtSecret,
        { expiresIn: '14d' }  // 14일 동안 유효
    );
}

const requestLimiter = rateLimit({
    windowMs: 10 * 60 * 1000, 
    max: 100,
    message: '요청이 너무 많습니다. 잠시 후 다시 시도해주세요.',
    statusCode: 429,
    headers: true,
    keyGenerator: (req) => req.ip,
});

// 유효성 검사 함수
function validateSignupData(DisplayName, userHandle, password) {
    if (DisplayName.length > 30) {
        return '이름은 최대 30자까지 가능합니다.';
    }

    const userHandleRegex = /^[a-zA-Z0-9가-힣_]{1,15}$/;
    if (!userHandleRegex.test(userHandle)) {
        return '아이디는 영문, 숫자, 한글, 밑줄(_)만 사용 가능하며 최대 15자입니다.';
    }

    const passwordRegex = /^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!%*#?&]{8,}$/;
    if (!passwordRegex.test(password)) {
        return '비밀번호는 최소 8자, 영문/숫자/특수문자(@$!%*#?&)를 포함해야 합니다.';
    }

    return null;
}

// 회원가입 API
async function signup(req, res) {
    let { DisplayName, userHandle, password } = req.body;
    userHandle = userHandle.toLowerCase();  // 소문자 변환

    try {
        const validationError = validateSignupData(DisplayName, userHandle, password);
        if (validationError) {
            return res.status(400).json({ message: validationError });
        }

        const usersCollection = getUsersCollection();
        const idUsedCollection = getIdUsedCollection();

        const existingUser = await usersCollection.findOne({ userHandle: userHandle.toLowerCase() });
        const idUsed = await idUsedCollection.findOne({ userHandle: userHandle.toLowerCase() });

        if (existingUser) {
            return res.status(400).json({ message: '이미 존재하는 사용자명입니다.' });
        }

        if (idUsed) {
            return res.status(400).json({ message: '해당 아이디는 사용할 수 없습니다.' });
        }

        const hashedPassword = await bcrypt.hash(password, saltRounds);
        const newUser = await usersCollection.insertOne({ 
            DisplayName, 
            userHandle,
            password: hashedPassword, 
            rank: 0, 
            registeredAt: new Date() 
        });

        await idUsedCollection.insertOne({ 
            user_id: newUser.insertedId, 
            DisplayName,
            userHandle, 
            registeredAt: new Date() 
        });

        res.status(200).json({ message: '회원가입이 완료되었습니다.' });
    } catch (error) {
        console.error('Signup error:', error);
        res.status(500).json({ message: '서버 오류가 발생했습니다.' });
    }
}

async function deleteUser(req, res) {
    try {
        if (!req.user) {
            return res.status(401).json({ message: '로그인 상태가 아닙니다.' });
        }

        const { password } = req.body;
        if (!password) {
            return res.status(400).json({ message: '필수 데이터가 누락되었습니다.' }); 
        }
        const usersCollection = getUsersCollection();
        const idUsedCollection = getIdUsedCollection();

        const userId = new ObjectId(req.user.id);
        const user = await usersCollection.findOne({ _id: userId });

        if (!user) {
            return res.status(404).json({ message: '사용자를 찾을 수 없습니다.' });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(401).json({ message: '비밀번호가 일치하지 않습니다.' });
        }

        await idUsedCollection.updateOne(
            { user_id: user._id },
            {
                $set: {
                    DisplayName: user.DisplayName,
                    userHandle: user.userHandle,
                    rank: user.rank,
                    deletedAt: new Date(),
                },
            }
        );

        // 계정 삭제
        await usersCollection.deleteOne({ _id: user._id });

        res.status(200).json({ message: '회원 탈퇴가 완료되었습니다.' });
    } catch (error) {
        console.error('Delete user error:', error);
        res.status(500).json({ message: '서버 오류가 발생했습니다.' });
    }
}

// 로그인 API
async function login(req, res) {
    const { userHandle, password } = req.body;

    try {
        const usersCollection = getUsersCollection();
        let user = await usersCollection.findOne({ userHandle });

        if (!user) {
            return res.status(401).json({ message: '사용자를 찾을 수 없습니다.' });
        }
        
        if (!user.password || user.rank === undefined || !user.DisplayName || !user.userHandle) {
            return res.status(404).json({ message: '로그인 할 수 없습니다.' });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(401).json({ message: '비밀번호가 일치하지 않습니다.' });
        }

        const token = generateToken(user);

        res.status(200).json({
            message: '로그인 성공',
            token,  // JWT 토큰을 응답으로 전달
            user: { display_name: user.DisplayName, user_handle: user.userHandle, rank: user.rank },
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ message: '알 수 없는 오류가 발생했습니다.' });
    }
}

// 로그아웃 API (클라이언트 측에서 토큰 제거)
async function logout(req, res) {
    // JWT는 서버 측에서 특별히 처리할 필요가 없음
    // 클라이언트에서 토큰을 삭제하는 방식으로 구현됨
    res.status(200).json({ message: '로그아웃 되었습니다.' });
}

// JWT 인증 미들웨어
function authenticateJWT(req, res, next) {
    const token = req.header("Authorization")?.split(" ")[1];

    if (!token) {
        return res.status(401).json({ message: '인증이 필요합니다.' });
    }

    jwt.verify(token, jwtSecret, (err, user) => {
        if (err) return res.status(403).json({ message: '토큰이 유효하지 않습니다.' });
        req.user = user;
        next();
    });
}

// 사용자 정보 조회 API
function getClientUserInfo(req, res) {
    if (req.user) {
        res.status(200).json({ isAuthenticated: true, user: req.user });
    } else {
        res.status(401).json({ isAuthenticated: false, message: '인증되지 않은 사용자입니다.' });
    }    
}

module.exports = { 
    signup: [requestLimiter, signup],
    login: [requestLimiter, login],
    logout,
    deleteUser: [authenticateJWT, deleteUser],
    getClientUserInfo: [authenticateJWT, getClientUserInfo],
    authenticateJWT
};