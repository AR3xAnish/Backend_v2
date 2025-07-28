import mongoose from "mongoose";

const subscriptionSchema = new mongoose.SchemaTypeOptions({
    subsciber: {
        type: mongoose.Types.ObjectId,//one who is subscribing
        ref:"User"
    },
    channel: {
        type: mongoose.Types.ObjectId,// one to who subscriber is subscribing
        ref:"User"
    }
},{timestamp:true})

export const Subscription = mongoose.model("Subscription",subscriptionSchema)