import { createHash } from 'crypto';

export class MD5 {
  static hash(plain: string): string {
    return createHash('md5').update(plain).digest('base64');
  }
}
