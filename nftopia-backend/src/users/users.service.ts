import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { User } from './user.entity';
import { UpdateProfileDto } from './dto/update-profile.dto';
import { UserWallet } from '../auth/entities/user-wallet.entity';

@Injectable()
export class UsersService {
  constructor(
    @InjectRepository(User)
    private repo: Repository<User>,
    @InjectRepository(UserWallet)
    private readonly walletRepo: Repository<UserWallet>,
  ) {}

  findById(id: string) {
    return this.repo.findOne({ where: { id } });
  }

  findByAddress(address: string) {
    return this.repo.findOne({ where: { address } });
  }

  async updateProfile(address: string, data: UpdateProfileDto) {
    const user = await this.findByAddress(address);
    if (!user) throw new NotFoundException('User not found');

    Object.assign(user, data);
    return this.repo.save(user);
  }

  listWallets(userId: string) {
    return this.walletRepo.find({
      where: { userId },
      order: { isPrimary: 'DESC', createdAt: 'ASC' },
    });
  }
}
