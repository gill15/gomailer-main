import { v4 as uuidv4 } from 'uuid';
import { Prop, Schema } from '@nestjs/mongoose';

@Schema({
  timestamps: true,
})
export abstract class Base {
  @Prop({ default: () => uuidv4() })
  _id: string;
}
