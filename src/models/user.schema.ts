import mongoose from "mongoose";

export interface UserDocument extends mongoose.Document {
    toObject: any;
    _id: string;
    first_name: string;
    last_name: string;
    username: string;
    email: string;
    password: string;
    tfa_secret: string;
}

export const UserSchema = new mongoose.Schema({
    first_name: { type: String },
    last_name: { type: String },
    username: { type: String},
    email: { type: String, unique: true },
    password: { type: String },
    tfa_secret: { type: String, default: "" }
});

const User = mongoose.model<UserDocument>("User", UserSchema);

export default User;
