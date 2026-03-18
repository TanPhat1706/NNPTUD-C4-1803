let userController = require('../controllers/users');
let jwt = require('jsonwebtoken');
let fs = require('fs');
let path = require('path');

// Đọc Public Key 1 lần duy nhất trên RAM
const publicKey = fs.readFileSync(path.join(__dirname, '../publicKey.pem'), 'utf8');

module.exports = {
    CheckLogin: async function (req, res, next) {
        try {
            let token = req.headers.authorization;
            
            // Xử lý token chuẩn có tiền tố 'Bearer '
            if (token && token.startsWith('Bearer ')) {
                token = token.split(' ')[1];
            }

            if (!token) {
                return res.status(401).send({ message: "Bạn chưa đăng nhập" });
            }

            // Verify bằng Public Key với thuật toán RS256
            let result = jwt.verify(token, publicKey, { algorithms: ['RS256'] });

            let user = await userController.GetAnUserById(result.id);
            if (!user) {
                return res.status(401).send({ message: "Người dùng không tồn tại hoặc đã bị xóa" });
            }
            
            req.user = user;
            next();
        } catch (error) {
            // Tách biệt lỗi hết hạn và lỗi sai token để client dễ xử lý (ví dụ: gọi api refresh token)
            if (error.name === 'TokenExpiredError') {
                return res.status(401).send({ message: "Token đã hết hạn" });
            }
            return res.status(401).send({ message: "Token không hợp lệ" });
        }
    }
}