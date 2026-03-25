import { Column, Entity, OneToMany, PrimaryGeneratedColumn } from 'typeorm';
import { UserWallet } from '../auth/entities/user-wallet.entity';

@Entity('users')
export class User {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ unique: true })
  address: string;

  @Column({ nullable: true })
  username?: string;

  @Column({ type: 'text', nullable: true })
  bio?: string;

  @Column({ nullable: true })
  avatarUrl?: string;

  @Column({ name: 'wallet_address', length: 56, nullable: true, unique: true })
  walletAddress?: string;

  @Column({ name: 'wallet_public_key', length: 56, nullable: true })
  walletPublicKey?: string;

  @Column({ name: 'wallet_provider', length: 50, nullable: true })
  walletProvider?: string;

  @Column({ name: 'wallet_connected_at', type: 'timestamp', nullable: true })
  walletConnectedAt?: Date;

  @OneToMany(() => UserWallet, (wallet) => wallet.user)
  wallets?: UserWallet[];
}
