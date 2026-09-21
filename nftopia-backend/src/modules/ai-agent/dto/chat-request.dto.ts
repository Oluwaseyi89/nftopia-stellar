import {
  IsArray,
  IsIn,
  IsNotEmpty,
  IsOptional,
  IsString,
  IsUUID,
  MaxLength,
  ValidateNested,
} from 'class-validator';
import { Type } from 'class-transformer';

export class ChatTurnDto {
  @IsIn(['user', 'assistant'])
  role: 'user' | 'assistant';

  @IsString()
  @IsNotEmpty()
  @MaxLength(8000)
  content: string;
}

export class ChatRequestDto {
  @IsString()
  @IsNotEmpty()
  @MaxLength(4000)
  message: string;

  /**
   * @deprecated Superseded by `sessionId` (#487) — conversation history is
   * now loaded from the database, never trusted from the client. Kept
   * optional (and simply ignored) rather than removed, so an older client
   * that still sends it doesn't get rejected by the global
   * forbidNonWhitelisted ValidationPipe.
   */
  @IsOptional()
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => ChatTurnDto)
  history?: ChatTurnDto[];

  /**
   * Id of a previously started chat session to continue. Omit to start a
   * new session — the response returns its id so the client can pass it on
   * the next call.
   */
  @IsOptional()
  @IsUUID()
  sessionId?: string;
}
