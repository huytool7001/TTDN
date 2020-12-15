//Dependencies
var express = require('express');
var path = require('path');//thao tác với đường dẫn của các tập tin
var logger = require('morgan');//hiển thị các thông tin yêu cầu từ client
var cookieParser = require('cookie-parser');//hỗ trợ việc sử dụng cookie (những tập tin một trang web gửi đến máy người dùng và được lưu lại thông qua trình duyệt khi người dùng truy cập trang web đó)
var bodyParser = require('body-parser');//Lấy được dữ liệu nhập vào
var session = require('express-session');//quản lý session (lưu thông tin người dùng hiện hành trên server)
var mongoose = require('mongoose');//thao tác với mongoose database
var nodemailer = require('nodemailer');//thao tác với mail
var passport = require('passport');//hỗ trợ authentication (xác thực đăng nhập, đăng ký)
var LocalStrategy = require('passport-local').Strategy;//đăng nhập, đăng ký bằng tài khoản local
var bcrypt = require('bcrypt-nodejs');//mã hóa mật khẩu
var async = require('async');//kiểm soát các luồng không đồng bộ
var crypto = require('crypto');//tạo mã ngẫu nhiên để đặt lại mật khẩu
var flash = require('express-flash');//hiển thị các thông báo trên web cho người dùng
//Tạo các phương thức để xác thực
passport.use(new LocalStrategy({passReqToCallback : true },
  function(req, username, password, done) {  
    User.findOne({ username: username }, function(err, user) {//tìm user thông qua username
      if (err) return done(err);
      //Không có user
      if (!user) return done(null, false, req.flash('error', 'Tài khoản không tồn tại!!!'));//Thông báo
      //Nếu có thì kiểm tra mật khẩu
      user.comparePassword(password, function(err, isMatch) {
        if (isMatch) {
          return done(null, user);
        } else {
          return done(null, false, req.flash('error', 'Sai mật khẩu!!!'));//Thông báo
        }
      });
    });
}));
  
passport.serializeUser(function(user, done) {
  done(null, user.id);//lưu vào session id của user
});

passport.deserializeUser(function(id, done) {
  User.findById(id, function(err, user) {
    done(err, user);//tìm kiếm theo id
  });
});
  
//Khởi tạo đối tượng user
var userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  resetPasswordToken: String,
  resetPasswordExpires: Date
});
//Phương thức save cho user
userSchema.pre('save', function(next) {
  var user = this;
  var SALT_FACTOR = 5;
  
  if (!user.isModified('password')) return next();
  //Mã hóa mật khẩu 
  bcrypt.genSalt(SALT_FACTOR, function(err, salt) {
    if (err) return next(err);
    
    bcrypt.hash(user.password, salt, null, function(err, hash) {
      if (err) return next(err);
      user.password = hash;
      next();
    });
  });
});
//Phương thức so sánh mật khẩu
userSchema.methods.comparePassword = function(candidatePassword, cb) {
  bcrypt.compare(candidatePassword, this.password, function(err, isMatch) {
    if (err) return cb(err);
    cb(null, isMatch);
  });
};
//tạo một Document trong MongoDB với các thuộc tính như đã được định nghĩa từ schema trên
var User = mongoose.model('User', userSchema);
//Kết nối Database
mongoose.connect('mongodb+srv://test:huy2882001@cluster0.rrjne.mongodb.net/test?retryWrites=true&w=majority',{useNewUrlParser:true, useUnifiedTopology: true });
var app = express();
// Middleware
app.set('port', process.env.PORT || 3000);//node sẽ chạy trên cổng môi trường hoặc nếu không có sẽ là cổng 3000.
app.set('views', path.join(__dirname, 'views'));//các giao diện với người dùng sẽ nằm trong thư mục views
app.set('view engine', 'jade');//thiết lập view engine là jade
app.use(logger('dev'));//sử dụng module morgan 
app.use(bodyParser.json());//mã hóa dữ liệu nhập vào kiểu json (Định dạng JSON sử dụng các cặp key – value để lưu dữ liệu)
app.use(bodyParser.urlencoded({//mã hóa dữ liệu nhập vào kiểu url
  extended: true  //phân tích các đối tượng lồng nhau
}));
app.use(cookieParser());//sử dụng module cookieParser
app.use(session({ resave: true, saveUninitialized: true, secret: 'session secret key' }));//sử dụng module session
app.use(flash());//sử dụng module express-flash
app.use(passport.initialize());//khởi tạo passport với các yêu cầu để xác thực
app.use(passport.session());//cho passport sử dụng thông tin của session
app.use(express.static(path.join(__dirname, 'public')));//thiết lập thư mục public sẽ lưu trữ các file tĩnh
// Routes
//Trang chủ
app.get('/', function(req, res){
  res.render('index', {
    title: 'Việt Nam tươi đẹp',
    user: req.user
  });
});
//Trang đăng nhập
app.get('/login', function(req, res) {
  res.render('login', {
    title: 'Đăng nhập',
    user: req.user
  });
});
app.post('/login', function(req, res, next) {
  passport.authenticate('local', function(err, user, info) {
    if (err) return next(err)
    //Nếu đăng nhập thành công sẽ chuyển hướng trang chủ còn nếu không sẽ ở lại trang
    if (!user) {
      return res.redirect('/login')
    }
    req.logIn(user, function(err) {
      if (err) return next(err);
      return res.redirect('/');
    });
  })(req, res, next);
});
//Trang đăng ký
app.get('/signup', function(req, res) {
  res.render('signup', {
    title: 'Đăng ký',
    user: req.user
  });
});
app.post('/signup', function(req, res) {
//Khởi tạo user mới với các thông tin người dùng nhập vào
  var user = new User({
      username: req.body.username,
      email: req.body.email,
      password: req.body.password
  });

  user.save(function(err) {
    req.logIn(user, function(err) {
      res.redirect('/');
    });
  });
});
//Đăng xuất
app.get('/logout', function(req, res){
  req.logout();
  res.redirect('/'); 
});
//Quên mật khẩu
app.get('/forgot', function(req, res) {
  res.render('forgot', {
    title: 'Quên mật khẩu',
    user: req.user
  });
});
app.post('/forgot', function(req, res, next) {
  async.waterfall([//cho các hoạt động phải được chạy theo chuỗi, với mỗi thao tác tùy thuộc vào kết quả của các phép toán trước đó.
    function(done) {
      //Tạo một chuỗi ngẫu nhiên khác biệt kiểu hex
      crypto.randomBytes(20, function(err, buf) {
        var token = buf.toString('hex');
        done(err, token);
      });
    },
    function(token, done) {
      //Xác thực email người dùng nhập vào để đổi mật khẩu
      User.findOne({ email: req.body.email }, function(err, user) {
        if (!user) {
          req.flash('error', 'Tài khoản không tồn tại!!!');
          return res.redirect('/forgot');
        }
        //Sự dụng token khởi tạo trên để đưa vào link gửi cho người dùng
        user.resetPasswordToken = token;
        user.resetPasswordExpires = Date.now() + 3600000; //thời hạn link là 1h

        user.save(function(err) {
          done(err, token, user);
        });
      });
    },
    function(token, user, done) {
      //Gửi mail
      var smtpTransport = nodemailer.createTransport({
        host: 'smtp.gmail.com',        
        auth: {          
            user: 'turwig234@gmail.com',
            pass: 'passwordofmine'          
        }
      });
      var mailOptions = {
        to: user.email,
        from: 'resetpassword@gmail.com',
        subject: 'Đổi mật khẩu',
        text: 'Bạn nhận được thông báo này vì bạn (hoặc người khác) đã yêu cầu đặt lại mật khẩu cho tài khoản của bạn.\n\n' +
          'Vui lòng nhấp vào liên kết sau hoặc dán liên kết này vào trình duyệt của bạn để hoàn tất quá trình:\n\n' +
          'http://' + req.headers.host + '/reset/' + token + '\n\n' +
          'Nếu bạn không yêu cầu điều này, vui lòng bỏ qua email này và mật khẩu của bạn sẽ không thay đổi.\n'
      };
      smtpTransport.sendMail(mailOptions, function(err) {
        req.flash('info', 'Một email vừa được gửi tới ' + user.email + ' với hướng dẫn chi tiết hơn.');
        done(err, 'done');
      });
    }
  ], function(err) {
      if (err) return next(err);
      res.redirect('/forgot');
  });
});
//Đổi mật khẩu
app.get('/reset/:token', function(req, res) {
  //Xác thực lại token của người dùng và thời hạn
  User.findOne({ resetPasswordToken: req.params.token, resetPasswordExpires: { $gt: Date.now() } }, function(err, user) {
    if (!user) {
      req.flash('error', 'Mã thông báo đặt lại mật khẩu không hợp lệ hoặc đã hết hạn.');
      return res.redirect('/forgot');
    }
    res.render('reset', {
      title: 'Đổi mật khẩu',
      user: req.user
    });
  });
});
app.post('/reset/:token', function(req, res) {
async.waterfall([
  function(done) {
    User.findOne({ resetPasswordToken: req.params.token, resetPasswordExpires: { $gt: Date.now() } }, function(err, user) {
      if (!user) {
        req.flash('error', 'Mã thông báo đặt lại mật khẩu không hợp lệ hoặc đã hết hạn');
        return res.redirect('back');
      }
      
      user.password = req.body.password;
      user.resetPasswordToken = undefined;
      user.resetPasswordExpires = undefined;

      user.save(function(err) {
        req.logIn(user, function(err) {
          done(err, user);
        });
      });
    });
  },
  //Gửi lại mail xác nhận đã thay đổi mật khẩu
  function(user, done) {
    var smtpTransport = nodemailer.createTransport( {
      host: 'smtp.gmail.com',        
      auth: {
          user: 'turwig234@gmail.com',
          pass: 'passwordofmine'        
      }
    });
    var mailOptions = {
      to: user.email,
      from: 'resetpassword@gmail.com',
      subject: 'Mật khẩu của bạn đã được thay đổi',
      text: 'Xin chào,\n\n' +
        'Đây là email xác nhận mật khẩu cho tài khoản ' + user.email + '  của bạn vừa được thay đổi.\n'
    };
    smtpTransport.sendMail(mailOptions, function(err) {
      req.flash('success', 'Thành công! Mật khẩu của bạn đã được thay đổi.');
      done(err);
    });
  }
], function(err) {
  res.redirect('back');
  });
});
//Kiểm tra cổng đang chạy trên console
app.listen(app.get('port'), function() {
  console.log('Express server listening on port ' + app.get('port'));
});