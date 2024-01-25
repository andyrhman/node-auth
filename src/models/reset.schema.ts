import mongoose from 'mongoose';

export interface ResetDocument extends mongoose.Document {
    _id: string;
    email: string;
    token: string;
    expiresAt: number;
    used: boolean;
}

export const ResetSchema = new mongoose.Schema({
    email: { type: String },
    token: { type: String, unique: true },
    expiresAt: { type: BigInt },
    used: { type: Boolean, default: false }
})

const Reset = mongoose.model<ResetDocument>("Reset", ResetSchema);

export default Reset;