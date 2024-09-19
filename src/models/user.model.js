import mongoose,{Schema} from 'mongoose';
import bcrypt from 'bcrypt'
import jwt from 'jsonwebtoken'
import dotenv from 'dotenv'
dotenv.config();

const userSchema = new Schema({
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
    type: String,
    required: false
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

userSchema.pre('save',async function (next){
  if(!this.isModified('password')) return;

  this.password = await bcrypt.hash(this.password,10);
  next();
})

userSchema.methods.isPasswordCorrect = async function(password) {
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

userSchema.methods.createPasswordResetToken = function (){
  const resetToken = (Math.random() + 1).toString(36).substring(7);
  this.passwordResetToken = resetToken
  this.passwordResetExpires = Date.now() + 3600000;
  return resetToken;
}

export const User = mongoose.model("User", userSchema)