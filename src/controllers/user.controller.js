import { asyncHandler } from "../utils/asyncHandler.js";
import { ApiError } from "../utils/ApiError.js";
import { User } from "../models/user.models.js"
import { uploadOnCloudinary } from "../utils/cloudinary.js";
import { ApiResponse } from "../utils/ApiResponse.js";

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
    const existUser = User.findOne({
        $or:[{ username },{ email }]
    })
    if(existUser){
       throw new ApiError(409,"Username or Email already exist")  

    }

    //check for images, check for avatar
    const avatarLocalPath=req.files?.avatar[0]?.path;
    const coverImageLocalPath=req.files?.coverImage[0]?.path;
    
    if(!avatarLocalPath){
        throw new ApiError(400,"Avatar file is required")
    }

    //upload them on cloudinary
    const avatar = await uploadOnCloudinary(avatarLocalPath)
    const coverImage = await uploadOnCloudinary(coverImageLocalPathLocalPath)
    
    if(!avatar){
        throw new ApiError(400,"Avatar file is required")
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

export {registerUser}