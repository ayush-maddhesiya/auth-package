
import mongoose from 'mongoose';
import {User} from '../models/user.model.js';

import {ApiError} from '../utils/ApiError.js';
import {ApiResponse} from '../utils/ApiResponse.js';
import {asyncHandler} from '../utils/AsyncHandler.js';
import bcrypt from 'bcrypt';
// import {} from '../models/user.model.js'



const loginUser = (username, password, usersDB) => {
  const user = usersDB.find(u => u.username === username);
  if (!user) throw new Error('User not found');

  const isPasswordValid = bcrypt.compareSync(password, user.password);
  if (!isPasswordValid) throw new Error('Invalid password');

  console.log('Secret Key:', config.secretKey); // Use local config

  return `Token for user: ${user.username}`;
};

const generateAccessTokenandRefreshToken = async (userId) => {
  try {
    console.log("userId", userId);
    
    const user = await User.findById(userId);
    console.log("user form generate tokens", user);
    if (!user) throw new ApiError(404, "User not found");

    console.log("you are there after the user find form Db");
    
    const accessToken =  await user.generateAccessToken();
    const refreshToken =  await user.generateRefreshToken();
    console.log("you are there after the user find form Db ALSO THIETE ");

    console.log("accessToken", accessToken);
    console.log("refreshToken", refreshToken);
    user.refreshToken = refreshToken;
    user.accessToken = accessToken;
    await user.save({ validateBeforeSave: false });

    return { accessToken, refreshToken };
  } catch (error) {
    throw new ApiError(500, error.message || "Something went wrong while generating the JWT tokens");
  }
};

const login = asyncHandler(async (req, res, next) => {
  const { email, username, password } = req.body;
  console.log("email, username, password", email, username, password);
  
  try {
    if (username === undefined || password === undefined || email === undefined) {
      throw new ApiError(400, 'Please provide username,email and password , it is undefined');
    }
  
    const user = await User.findOne({
      $or: [{ email }, { username }]
    }).select('+password +isVerified');
    console.log("user", user);
    
    if (!user) {
      throw new ApiError(400, "User Not found")
    }  
    
    if (!user.isVerified) {
      throw new ApiError(400, "Please verify your email") 
    }
    
    const isPasswordCorrector = await user.isPasswordCorrect(password) 
    
    if (!isPasswordCorrector) {
      throw new ApiError(404, "Incorrect Password")
    }
    
    // console.log("user._id", user._id.toString());
    console.log(await generateAccessTokenandRefreshToken(user._id.toString()));
    
    const { accessToken, refreshToken } = await generateAccessTokenandRefreshToken(user._id.toString());
    console.log("accessToken, refreshToken", accessToken, refreshToken);
    console.log("you are here");
    
    
    res.cookies("refreshToken", refreshToken, {
      httpOnly: true,
      secure: true,
      sameSite: "none",
    })
  
    res.cookie("accessToken", accessToken, {
      httpOnly: true,
      secure: true,
      sameSite: "none",
    })
    
    return res.status(200).json(new ApiResponse(200, "Logged in successfully", { accessToken, refreshToken }));
  
  } catch (error) {
    throw new ApiError(500, error.message || "Something went wrong while logging in"); 
  }
});

const registerUser = asyncHandler(async (req, res) => {
  const { fullName, email, password, role,username } = req.body;

  if (fullName === undefined || email === undefined || password === undefined || role === undefined) { 
    throw new ApiError(400, 'Please provide username,email and password , it is undefined');
  }

  if(role !== "user" && role !== "admin"){
    throw new ApiError(400, "Invalid role")
  }

  const userexits = await User.findOne({
    $or: [{ email }, { username }]}
  );
  console.log(userexits);
  

  if(userexits){
    throw new ApiError(400, "User already exists")
  }

  // console.debug(`Creating user with email: ${email}, username: ${username}`);

  
  const hashedPassword = await bcrypt.hash(password, 10);
  const user = await User.create({
    fullName, 
    email, 
    password, 
    role, 
    username,
    password: hashedPassword,
    // verificationToken:  verifyEmailToken
  });
  console.log("User ID: ",user.role);
  
  const { accessToken, refreshToken } = await generateAccessTokenandRefreshToken(user._id);
  // const verifyEmailToken = user.createPasswordResetToken();
  res.cookie("refreshToken", refreshToken, {  
    httpOnly: true,
    secure: true,
    sameSite: "none",
  })  

  res.cookie("accessToken", accessToken, {
    httpOnly: true,
    secure: true,
    sameSite: "none",
  })

  return res.status(200).json(new ApiResponse(200, "Registered successfully", { accessToken, refreshToken }));
});

const logOut = asyncHandler(async (req, res) => {
  res.cookie("refreshToken", "", {
    httpOnly: true,
    secure: true,
    sameSite: "none",
  })
  res.cookie("accessToken", "", {
    httpOnly: true,
    secure: true,
    sameSite: "none",
  })
  res.status(200).json(
    new ApiResponse(200, "Logged Out successfully", { accessToken: "", refreshToken: "" }),
  )
})

const forgetPassword = asyncHandler(async (req, res) => {
  const { email } = req.body;
  if(!email){
    throw new ApiError(400, "Please provide email")
  }

  const user = await user.findOne({email})

  if(!user){
    throw new ApiError(400, "User not found")
  }

  const resetToken = user.createPasswordResetToken();
  await user.save({ validateBeforeSave: false });

  const resetURL = `${process.env.FRONTEND_URL}/reset-password?resetToken=${resetToken}`;
  
  const message = `Click on the link below to reset your password. \n\n ${resetURL}`;
  try {
    await sendEmail({
      email: user.email,
      subject: "Reset Password",
      message
    });
    return res.status(200).json(
      new ApiResponse(200, "Password reset token sent to your email"),
    );
  } catch (error) {
    user.passwordResetToken = undefined;
    user.passwordResetExpires = undefined;
    await user.save({ validateBeforeSave: false });
    throw new ApiError(500, error.message || "Something went wrong while sending the email");
  }

})


const resetPassword = asyncHandler(async (req, res) => {
  
  const { oldPassword , newPassword} = req.body;
  try {
    if(oldPassword === undefined ||  newPassword === undefined){
      throw new ApiError(301,"Please provide old password and new password")
    }
    if(oldPassword === newPassword){
      throw new ApiError(403,"New password cannot be same as old password")
    }
  
    const isPasswordCorrect = user.isPasswordCorrect(oldPassword);
    if(!isPasswordCorrect){
      throw new ApiError(401,"Password is incorrect")
    }
    const newHashedPassword = await bcrypt.hash(newPassword,10);
    const user = req.user._id;
    const updatedUser = User.findByIdAndUpdate(user, {
      password: newHashedPassword
    })

    return res.status(200).json(new ApiResponse(200, "Password reset successfully", updatedUser)
    )
  } catch (error) {
    new ApiError(500, error.message || "Something went wrong while resetting the password");
  }

}) 

export const verifyEmail = (req, res) => {
  // Logic to verify the user's email

};

export {
  login,
  registerUser,
  logOut,
  resetPassword,
  forgetPassword,
  loginUser
}
