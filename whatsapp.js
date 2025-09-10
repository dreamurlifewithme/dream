
const ultramsg = require('ultramsg-whatsapp-api');

const instance_id = process.env.ULTRAMSG_INSTANCE_ID; // Get from your Ultramsg account
const ultramsg_token = process.env.ULTRAMSG_TOKEN; // Get from your Ultramsg account

const api = new ultramsg(instance_id, ultramsg_token);

async function sendCouponNotification(userName, couponCode) {
    const to = '+918341569495';
    const body = `New user registered: ${userName}, Coupon Number: ${couponCode}`;

    try {
        const response = await api.sendChatMessage(to, body);
        console.log('WhatsApp notification sent:', response);
    } catch (error) {
        console.error('Error sending WhatsApp notification:', error);
    }
}

async function sendCouponRequestNotification(user) {
    const to = '+918341569495'; // Admin's WhatsApp number
    const body = `Coupon Request from User:\nName: ${user.name}\nUser ID: ${user.id}\nContact: ${user.contact}\nEmail: ${user.email}`;

    try {
        const response = await api.sendChatMessage(to, body);
        console.log('WhatsApp coupon request sent:', response);
    } catch (error) {
        console.error('Error sending WhatsApp coupon request:', error);
    }
}

module.exports = { sendCouponNotification, sendCouponRequestNotification };
