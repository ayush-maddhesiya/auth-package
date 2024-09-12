import mongoose from 'mongoose';
import bcrypt from 'bcrypt'
import jwt from 'jsonwebtoken'

const userSchema = new user.Schema({
  username: {
    type: String,
    required: true,
    unique: true,
    lowercase: true
  },
  fullName: {
    type: String,
    required: true
  },
  email: {
    type: String,
    required: true,
    unique: true,
    lowercase: true
  },
  role: {
    type: String,
    enum: ['user', 'admin'],
    default: 'user'
  },
  password: {
    type: String,
    required: true,
    select: false,
    minlength: 6,
    validate: {
      validator: function (v) {
        return /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{6,1024}$/.test(v);
      },
      message: "Password must contain at least one lowercase letter, one uppercase letter and one number"
    }
  },
  isVerified: {
    type: Boolean,
    default: false
  },
  verificationToken: {
    type: String
  },
  passwordResetToken: {
    type: String
  },
  passwordResetExpires: {
    type: Date
  }
}, {
  timestamps: true 
});

userSchema.methods.isPasswordCorrect = async function isPasswordCorrect(password) {
  return await bcrypt.compare(password,this.password)
}

userSchema.methods.generateAccessToken = function () {
  return jwt.sign({
    _id : this._id,
    username : this.username,
    email: this.email,
    fullName: this.fullName,
    },
    process.env.ACCESS_TOKEN_SECRET,
    {
      expiresIn : process.env.ACCESS_TOKEN_EXPIRES
    }
  )
}


userSchema.methods.generateRefreshToken = function (){
  return jwt.sign({
    _id: this.id
  },
  process.env.REFRESH_TOKEN_SECRET,
  {
    expiresIn : process.env.REFRESH_TOKEN_EXPIRES
  }
)
}

user.methods.createPasswordResetToken = function (){
  const resetToken = (Math.random() + 1).toString(36).substring(7);
  this.passwordResetToken = resetToken
  return resetToken;
}

export default mongoose.model('User', userSchema);