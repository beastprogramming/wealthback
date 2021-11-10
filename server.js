require('dotenv').config();
const port = process.env.PORT || 8888;
const senderid = process.env.SENDER_ID;
const authToken = process.env.AUTH_TOKEN;
const jwt = require('jsonwebtoken');
const JWT_AUTH_TOKEN = process.env.JWT_AUTH_TOKEN;
const JWT_REFRESH_TOKEN = process.env.JWT_REFRESH_TOKEN;
const express = require('express')
const app = express();
app.use(express.json());
const cors = require('cors');
const cookieParser = require('cookie-parser');
const SendOtp = require('sendotp');
const sendOtp = new SendOtp(authToken);
sendOtp.setOtpExpiry('3'); //in minutes
app.use(cors({ origin: 'http://localhost:3000', credentials: true }));
app.use(cookieParser())
app.post('/sendOtp', (req, res) => {
	const phone = req.body.phone;
	sendOtp.send(phone,senderid,function(err,res){
        console.log(err)
        console.log(res)
  
    })
	res.status(200).send({ phone});  
      
});

app.post('/verifyOtp',(req,res)=>{
    const phone = req.body.phone;
    const otp = req.body.otp;
    sendOtp.verify(phone,otp, function (error, data) {
        console.log(data); // data object with keys 'message' and 'type'
        if(data.type == 'success')
        {
        const accessToken = jwt.sign({ data: phone }, JWT_AUTH_TOKEN, { expiresIn: '30s' });
		const refreshToken = jwt.sign({ data: phone }, JWT_REFRESH_TOKEN, { expiresIn: '1y' });
		// refreshTokens.push(refreshToken);
		res
			.status(202)
			.cookie('accessToken', accessToken, {
				expires: new Date(new Date().getTime() + 30 * 1000),
				sameSite: 'strict',
				httpOnly: true
			})
			.cookie('refreshToken', refreshToken, {
				expires: new Date(new Date().getTime() + 31557600000),
				sameSite: 'strict',
				httpOnly: true
			})
			.cookie('authSession', true, { expires: new Date(new Date().getTime() + 30 * 1000), sameSite: 'strict' })
			.cookie('refreshTokenID', true, {
				expires: new Date(new Date().getTime() + 31557600000),
				sameSite: 'strict'
			})
			.send({ msg: 'Device verified' });
        }
        else{console.log('OTP verification failed')}
      });
})

app.post('/refresh', (req, res) => {
	const refreshToken = req.cookies.refreshToken;
	jwt.verify(refreshToken, JWT_REFRESH_TOKEN, (err, phone) => {
		if (!err) {
			const accessToken = jwt.sign({ data: phone }, JWT_AUTH_TOKEN, {
				expiresIn: '30s'
			});
			return res
				.status(200)
				.cookie('accessToken', accessToken, {
					expires: new Date(new Date().getTime() + 30 * 1000),
					sameSite: 'strict',
					httpOnly: true
				})
				.cookie('authSession', true, {
					expires: new Date(new Date().getTime() + 30 * 1000),
					sameSite: 'strict'
				})
				.send({ previousSessionExpired: true, success: true });
		} else {
			return res.status(403).send({
				success: false,
				msg: 'Invalid refresh token'
			});
		}
	});
});

app.get('/logout', (req, res) => {
	console.log('loggedout')
	res
		.clearCookie('refreshToken')
		.clearCookie('accessToken')
		.clearCookie('authSession')
		.clearCookie('refreshTokenID')
		.send('logout');
});
app.get("/test", (req,res)=>{
	res.send({test:"successfull"})
})
app.listen(port)