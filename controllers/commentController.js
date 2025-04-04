const { getCommentsCollection, getUsersCollection, getPostsCollection } = require('../models/db.js');
const { ObjectId } = require('mongodb');
const jwt = require('jsonwebtoken');
const jwtSecret = process.env.JWT_SECRET;

if (!jwtSecret) {
    throw new Error('JWT_SECRET 환경 변수가 설정되지 않았습니다.');
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

async function getComments(req, res) {
   const { postId } = req.params;
   const commentsCollection = getCommentsCollection();
   const usersCollection = getUsersCollection();

   try {
       const comments = await commentsCollection.find({ postId: new ObjectId(postId) }).toArray();

       for (let comment of comments) {
           const user = await usersCollection.findOne({ _id: new ObjectId(comment.userId) });
           
           if (user) {
               comment.author = user.userHandle;
               comment.displayname = user.DisplayName;
           } else {
               comment.author = "Deleted User";
               comment.displayname = "Deleted User";
           }
       }

       res.status(200).json(comments);
   } catch (error) {
       console.error('Error fetching comments:', error);
       res.status(500).json({ message: '서버 오류가 발생했습니다.' });
   }
}

async function createComment(req, res) {
   const { postId, content } = req.body;
   const { user } = req;

   if (!user || user.rank === undefined) {
       return res.status(404).json({ message: 'Forbidden' });
   }

   const userId = new ObjectId(user.id);
   const commentsCollection = getCommentsCollection();
   const usersCollection = getUsersCollection();
   const postsCollection = getPostsCollection();

   try {
       const userData = await usersCollection.findOne({ _id: userId });
       const post = await postsCollection.findOne({ _id: new ObjectId(postId) });
       
       if (!post) {
           return res.status(404).json({ message: '게시물을 찾을 수 없습니다.' });
       }
       
       const comment_up = post ? post.comment_up : 1;

       if (typeof comment_up === 'undefined') {
           await postsCollection.updateOne({ _id: new ObjectId(postId) }, { $set: { comment_up: 1 } });
       }

       if (!userData) {
           return res.status(404).json({ message: 'User not found' });
       }

       if (userData.rank !== 5) {
           if (comment_up !== 1) {
               return res.status(401).json({ message: '관리자 외 댓글 게시 불가 게시물'});
           }
       }

       const newComment = {
           postId: new ObjectId(postId),
           author: userData.userHandle,
           displayname: userData.DisplayName,
           userId: userData._id,
           content,
           createdAt: new Date(),
       };

       await commentsCollection.insertOne(newComment);
       res.status(201).json(newComment);
   } catch (error) {
       console.error('Error adding comment:', error);
       res.status(500).json({ message: '서버 오류가 발생했습니다.' });
   }
}

module.exports = { 
   getComments, 
   createComment: [authenticateJWT, createComment],
   authenticateJWT
};