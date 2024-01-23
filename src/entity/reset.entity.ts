import { Entity, PrimaryGeneratedColumn, Column } from 'typeorm';

@Entity()
export class Reset {
    @PrimaryGeneratedColumn('uuid')
    id: string;

    @Column()
    email: string;

    @Column({
        unique: true,
    })
    token: string;

    @Column({ type: 'bigint' }) // Store timestamp as bigint
    expiresAt: number; // Store the expiration timestamp in milliseconds

    @Column({ default: false }) // Default to false, indicating token is not used
    used: boolean
}