import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { AdminController } from './admin.controller';
import { AdminAiFlagsController } from './admin-ai-flags.controller';
import { AdminService } from './admin.service';
import { User } from '../users/user.entity';
import { Collection } from '../modules/collection/entities/collection.entity';
import { ContentFlag } from '../modules/ai-agent/entities/content-flag.entity';
import { ContentFlagService } from '../modules/ai-agent/content-flag.service';
import { AuditModule } from '../common/audit/audit.module';

@Module({
  imports: [
    TypeOrmModule.forFeature([User, Collection, ContentFlag]),
    AuditModule,
  ],
  controllers: [AdminController, AdminAiFlagsController],
  providers: [AdminService, ContentFlagService],
})
export class AdminModule {}
