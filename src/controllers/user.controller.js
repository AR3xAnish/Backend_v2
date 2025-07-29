import { asyncHandler } from "../utils/asyncHandler.js";
import { ApiError } from "../utils/ApiError.js";
import { User } from "../models/user.models.js"
import { uploadOnCloudinary } from "../utils/cloudinary.js";
import { ApiResponse } from "../utils/ApiResponse.js";
import jwt from "jsonwebtoken"

const generateAccessAndRefreshTokens = async(userId)=>{
    try {
        const user = await User.findById(userId)
        const accessToken = user.generateAccessToken()
        const refreshToken = user.generateRefreshToken()

        user.refreshToken = refreshToken
        await user.save({validateBeforeSave:false})

        return {accessToken,refreshToken}
    } catch (error) {    
        throw new ApiError(500,"Something went Wrong while generation of refresh and access token")
    }
}

const registerUser = asyncHandler(async(req,res)=>{
    // get user details from frontend
    // validation - not empty
    // check if user already exists: username, email
    // check for images, check for avatar
    // upload them to cloudinary, avatar
    // create user object - create entry in db
    // remove password and refresh token field from response
    // check for user creation
    // return res

    //get user details
    const {fullName,email,username,password}=req.body
    console.log("email:",email);


    //validation
    //noobs
    // if(fullName===""){
    //     throw new ApiError(400,"fullname is required")
    // }

    //proffesional
    if(
        [fullName,email,username,password].some((field)=>{
            field?.trim()===""
        })
    ){
        throw new ApiError(400,"all fields are required")  
    }

    //check user if exists
    const existUser = await User.findOne({
        $or:[{ username },{ email }]
    })
    if(existUser){
       throw new ApiError(409,"Username or Email already exist")  

    }

    //check for images, check for avatar
    const avatarLocalPath=req.files?.avatar[0]?.path;
    const coverImageLocalPath=req.files?.coverImage[0]?.path;
    
    console.log(req.files);
    

    if(!avatarLocalPath){
        throw new ApiError(400,"Avatar file is required")
    }

    //upload them on cloudinary
    const avatar = await uploadOnCloudinary(avatarLocalPath)
    const coverImage = await uploadOnCloudinary(coverImageLocalPath)
    
    if(!avatar){
        throw new ApiError(400,"Cloudinary upload failed")
    }

    //create user Object - create entry in db
    const user = await User.create({
        fullName,
        avatar:avatar.url,
        coverImage:coverImage?.url || "",
        email,
        password,
        username: username.toLowerCase()
    })

    //remove password & refresh Token & check if user created
    const createdUser = await User.findById(user._id).select(
        "-password -refreshToken"
    )

    if(!createdUser){
        throw new ApiError(500,"Something wnt wrong while registering the user")
    }

    //return response
    return res.status(201).json(
        new ApiResponse(200,createdUser,"User registered")
    )

})

//login user
const loginUser = asyncHandler(async (req,res) => {
    //get data from request body
    //username base access or email base
    //find the user
    //if yes then password check
    //access and refresh token
    //if yes send cookies and send success response
    
    //get body from request body
    const {email,username,password} = req.body

    if (!(username || email)) {
        throw new ApiError(400,"username or email is required")
    }

    //find user
    const user = await User.findOne({
        $or:[{username},{email}]
    })

    if(!user){
        throw new ApiError(400,"User does not exist")
    }

    //if yesthen password check
    const isPasswordValid = await user.isPasswordCorrect(password)
    if(!isPasswordValid){
        throw new ApiError(401,"Invalid Password")
    }

    //access refresh token
    //creating a separate method as we gonna use it multiple times
    const {accessToken,refreshToken} = await generateAccessAndRefreshTokens(user._id)

    //send in cookies
    const loggedInUser = await User.findById(user._id).select("-password -refreshToken")

    //when we send cookies we have to design some options
    const options = {
        httpOnly: true,
        secure: true
    }//modifyable only from server not from frontend

    return res
    .status(200)
    .cookie("accessToken",accessToken,options)
    .cookie("refreshToken",refreshToken,options)
    .json(
        new ApiResponse(200,{
            user:loggedInUser,accessToken,refreshToken
        }),
        "User logged in successfully"
    )
}) 

//logout user
const logoutUser = asyncHandler(async(req,res)=>{
    //clear cookies
    //refreshtoken must disappear
    //create a middleware
    User.findByIdAndUpdate(
        await req.user._id,
        {
            $set:{
                refreshToken:undefined
            }
        },
        {
            new:true
        }
    )

    const options = {
        httpOnly: true,
        secure: true
    }

    return res
    .status(200)
    .clearCookie("accessToken",options)
    .clearCookie("refreshToken",options)
    .json(new ApiResponse(200,{},"User logged out"))
})

//controller for endpoint of refresf access token
const refreshAccessToken = asyncHandler(async(req,res)=>{
    //access the refresh token from cookies
    const incomingRefreshToken = req.cookies.refreshToken || req.body.refreshToken

    if(!incomingRefreshToken){
        throw new ApiError(401,"unauthorized access")
    }

    try {
        //verify the token
        const decodedToken = jwt.verify(incomingRefreshToken,
            process.env.REFRESH_TOKEN_SECRET,
        )
    
        const user = await User.findById(decodedToken?._id)
        if(!user){
            throw new ApiError(401,"invalid refresh token")
        }
        
        //match the refresh token
        if(incomingRefreshToken !== user?.refreshToken){
            throw new ApiError(401,"Refresh token is expired or used")
        }
    
        //so now generate a new token
        const options = {
            httpOnly:true,
            secure:true
        }
    
        const { accessToken, newRefreshToken }=await generateAccessAndRefreshTokens(user._id)
    
        return res
        .status(200)
        .cookie("accessToken",accessToken,options)
        .cookie("refreshToken",newRefreshToken,options)
        .json(
            new ApiResponse(
                200,
                {accessToken,refreshToken:newRefreshToken},
                "Access token refreshed"
            )
        )
    } catch (error) {
        throw new ApiError(401,error?.message || "Invalid refresh Token")

    }

})

const changeCurrentPassword = asyncHandler(async (req,res) => {
    const {oldPassword,newPassword} = req.body

    //we know that user is loged in means middlewar is used so we can use req.user
    const user = await User.findById(req.user?._id)
    //isPasswordCorrect method createdin user model
    const isPasswordCorrect = await user.isPasswordCorrect(oldPassword)
    if(!isPasswordCorrect){
        throw new ApiError(400,"Invalid old password")
    }

    user.password = newPassword
    await user.save({validateBeforeSave:false})

    return res
    .status(200)
    .json(new ApiResponse(
        200,{},"password changed successfully"
    ))
})

//controller to hit endpoint to get current user
const getCurrentUser = asyncHandler(async (req,res) => {
    return res
    .status(200)
    .json(200,req.user,"current user fetched successfully")
})

//code to update text based userdetails
const updateAccountDetails = asyncHandler(async (req,res) => {
    const {fullName,email} = req.body
    if(!fullName || !email){
        throw new ApiError(400,"All fields are required")
    }
    const user = await User.findByIdAndUpdate(
        req.user?._id,
        {
            $set:{
                fullName,
                email:email
            }
        },
        {new:true}
    ).select("-password")

    return res
    .status(200)
    .json(200,user,"Account details updated successfully")
})

//code to update file based userdetails
const updateUserAvatar = asyncHandler(async (req,res) => {
    //get req.file by using multer middleware
    const avatarLocalPath = req.file?.path
    if(!avatarLocalPath){
        throw new ApiError(400,"Avatar file is missing")
    }

    const avatar = await uploadOnCloudinary(avatarLocalPath)
    if(!avatar.url){
        throw new ApiError(400,"Error while uploading on avatar")
    }

    //update avatar
    const user = await User.findByIdAndUpdate(
        req.user?._id,
        {$set:{
            avatar:avatar.url
        }},
        {new:true}
    ).select("-password")

    return res
    .status(200)
    .json(new ApiResponse(200,user,"Avatar image updated"))

})
const updateUserCoverImage = asyncHandler(async (req,res) => {
    //get req.file by using multer middleware
    const coverImageLocalPath = req.file?.path
    if(!coverImageLocalPath){
        throw new ApiError(400,"cover image file is missing")
    }

    const coverImage = await uploadOnCloudinary(coverImageLocalPath)
    if(!coverImage.url){
        throw new ApiError(400,"Error while uploading on avatar")
    }
    const user = await User.findByIdAndUpdate(
        req.user?._id,
        {$set:{
            coverImage:coverImage.url
        }},
        {new:true}
    ).select("-password")

    return res
    .status(200)
    .json(new ApiResponse(200,user,"cover image updated"))
})


export {
    registerUser,
    loginUser,
    logoutUser,
    refreshAccessToken,
    changeCurrentPassword,
    getCurrentUser,
    updateAccountDetails,
    updateUserAvatar,
    updateUserCoverImage
}