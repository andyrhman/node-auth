import mongoose from "mongoose";

export interface TokenDocument extends mongoose.Document {
    _id: string;
    user_id: string;
    token: string;
    created_at: Date;
    expired_at: Date;
}

export const TokenSchema = new mongoose.Schema({
    user_id: { type: String },
    token: { type: String },
    expired_at: { type: Date }
}, {
    timestamps: {
        createdAt: "created_at"
    }
});

const Token = mongoose.model<TokenDocument>("Token", TokenSchema);

export default Token;