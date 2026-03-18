let express = require('express');
let router = express.Router();
let userController = require('../controllers/users');
let bcrypt = require('bcrypt');
const { CheckLogin } = require('../utils/authHandler'); // Sửa lại đường dẫn cho đúng với cấu trúc của bạn
let jwt = require('jsonwebtoken');
let fs = require('fs');
let path = require('path');

const privateKey = fs.readFileSync(path.join(__dirname, '../privateKey.pem'), 'utf8');

router.post('/register', async function (req, res, next) {
    try {
        let { username, password, email } = req.body;
        
        // const salt = bcrypt.genSaltSync(10);
        // const hashedPassword = bcrypt.hashSync(password, salt);
        
        let newUser = await userController.CreateAnUser(
            username, 
            password,
            email,
            "69b1265c33c5468d1c85aad8"
        );
        res.status(201).send(newUser);
    } catch (error) {
        res.status(400).send({ message: error.message });
    }
});

router.post('/login', async function (req, res, next) {
    try {
        let { username, password } = req.body;
        let user = await userController.GetAnUserByUsername(username);
        
        if (!user) {
            return res.status(401).send({ message: "Thông tin đăng nhập không đúng" });
        }
        if (user.lockTime && user.lockTime > Date.now()) {
            return res.status(403).send({ message: "Tài khoản của bạn đang bị khóa tạm thời" });
        }

        if (bcrypt.compareSync(password, user.password)) {
            user.loginCount = 0;
            user.lockTime = null;
            await user.save();
            
            let token = jwt.sign(
                { id: user._id }, 
                privateKey, 
                { algorithm: 'RS256', expiresIn: '1d' }
            );
            return res.send({ token: token });
        } else {
            user.loginCount = (user.loginCount || 0) + 1;
            if (user.loginCount >= 3) {
                user.loginCount = 0;
                user.lockTime = Date.now() + 3600 * 1000; // Khóa 1 tiếng
            }
            await user.save();
            return res.status(401).send({ message: "Thông tin đăng nhập không đúng" });
        }
    } catch (error) {
        return res.status(500).send({ message: error.message });
    }
});

router.get('/me', CheckLogin, function (req, res, next) {
    res.send(req.user);
});

router.post('/change-password', CheckLogin, async function (req, res, next) {
    try {
        let { oldpassword, newpassword } = req.body;
        let user = req.user; // Đã được CheckLogin gán vào req

        // 1. Kiểm tra có truyền đủ 2 field không
        if (!oldpassword || !newpassword) {
            return res.status(400).send({ message: "Vui lòng cung cấp đủ mật khẩu cũ và mật khẩu mới" });
        }

        // 2. Mật khẩu mới không được trùng mật khẩu cũ
        if (oldpassword === newpassword) {
            return res.status(400).send({ message: "Mật khẩu mới không được trùng với mật khẩu cũ" });
        }

        // 3. Xác thực mật khẩu cũ xem user nhập đúng không
        if (!bcrypt.compareSync(oldpassword, user.password)) {
            return res.status(401).send({ message: "Mật khẩu cũ không chính xác" });
        }

        // 4. Mã hóa mật khẩu mới (Bắt buộc để API Login còn chạy được) và lưu
        const salt = bcrypt.genSaltSync(10);
        const hashedNewPassword = bcrypt.hashSync(newpassword, salt);

        user.password = hashedNewPassword;
        await user.save();

        return res.send({ message: "Đổi mật khẩu thành công" });
    } catch (error) {
        return res.status(500).send({ message: error.message });
    }
});

module.exports = router;