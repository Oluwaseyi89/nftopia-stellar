import { IsIn } from 'class-validator';
import type { ContentFlagStatus } from '../../modules/ai-agent/entities/content-flag.entity';

export class ResolveContentFlagDto {
  @IsIn(['reviewed', 'dismissed'])
  status: Exclude<ContentFlagStatus, 'pending'>;
}
