const crypto = require('crypto');
const fs = require('fs');

console.log("Đang tạo cặp khóa RSA 2048-bit. Vui lòng đợi vài giây...");

// Sử dụng module crypto có sẵn của Node.js để sinh khóa
const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: {
        type: 'spki',
        format: 'pem'
    },
    privateKeyEncoding: {
        type: 'pkcs8',
        format: 'pem'
    }
});

// Lưu ra file
fs.writeFileSync('publicKey.pem', publicKey);
fs.writeFileSync('privateKey.pem', privateKey);

console.log("✅ Xong! Đã tạo thành công 'privateKey.pem' và 'publicKey.pem' tại thư mục hiện tại.");