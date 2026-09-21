import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { EventEmitterModule } from '@nestjs/event-emitter';
import { Listing } from './entities/listing.entity';
import { ListingService } from './listing.service';
import { ListingController } from './listing.controller';
import { StellarNft } from '../../nft/entities/stellar-nft.entity';
import { NftMetadata } from '../../nft/entities/nft-metadata.entity';
import { StellarModule } from '../stellar/stellar.module';
import { TransactionModule } from '../transaction/transaction.module';

@Module({
  imports: [
    EventEmitterModule,
    TypeOrmModule.forFeature([Listing, StellarNft, NftMetadata]),
    StellarModule,
    TransactionModule,
  ],
  providers: [ListingService],
  controllers: [ListingController],
  exports: [ListingService],
})
export class ListingModule {}
