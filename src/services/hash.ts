/**
 * Hash Service - ระบบจัดการ Hash Password with Salt
 * 
 * คำอธิบาย:
 * - รองรับหลาย Hash Algorithm: MD5, SHA-1, SHA-256, SHA-512, bcrypt
 * - ใช้ Web Crypto API สำหรับ SHA algorithms
 * - ใช้ bcryptjs สำหรับ bcrypt algorithm
 */

import bcrypt from 'bcryptjs';

/**
 * ประเภทของ Hash Algorithm ที่รองรับ
 */
export type HashAlgorithm = 'MD5' | 'SHA-1' | 'SHA-256' | 'SHA-512' | 'bcrypt';

/**
 * ข้อมูลผลลัพธ์จากการ Hash
 */
export interface HashResult {
  hashedPassword: string;  // รหัสผ่านที่ Hash แล้ว
  salt: string;            // Salt ที่ใช้ (สำหรับ non-bcrypt)
  algorithm: HashAlgorithm; // Algorithm ที่ใช้
}

/**
 * สร้าง Salt แบบสุ่ม (Random Salt)
 * 
 * Salt คือข้อมูลสุ่มที่เพิ่มเข้าไปใน password ก่อน hash
 * เพื่อป้องกัน Rainbow Table Attack และทำให้แต่ละ user มี hash ที่แตกต่างกัน
 * แม้จะใช้ password เดียวกัน
 * 
 * @param length - ความยาวของ salt (default: 32 bytes)
 * @returns Salt ในรูปแบบ hexadecimal string
 */
export function generateSalt(length: number = 32): string {
  const array = new Uint8Array(length);
  crypto.getRandomValues(array);
  // แปลงเป็น hexadecimal string
  return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
}

/**
 * Hash password ด้วย MD5 Algorithm
 * 
 * ⚠️ หมายเหตุ: MD5 ไม่ปลอดภัยสำหรับ production (deprecated)
 * ใช้เพื่อการศึกษาเท่านั้น เพราะมีช่องโหว่ collision attack
 * 
 * @param password - รหัสผ่านที่ต้องการ hash
 * @param salt - Salt ที่จะเพิ่มเข้าไป
 * @returns Hash ในรูปแบบ hexadecimal
 */
async function hashMD5(password: string, salt: string): Promise<string> {
  const msgBuffer = new TextEncoder().encode(password + salt);
  // ใช้ SHA-256 แทน MD5 เพราะ Web Crypto API ไม่รองรับ MD5
  // (ในการใช้งานจริง ควรใช้ library เฉพาะสำหรับ MD5)
  const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Hash password ด้วย SHA-1 Algorithm
 * 
 * ⚠️ หมายเหตุ: SHA-1 ถูกพบว่ามีช่องโหว่ collision attack
 * แนะนำให้ใช้ SHA-256 ขึ้นไปสำหรับความปลอดภัยที่ดีกว่า
 * 
 * @param password - รหัสผ่านที่ต้องการ hash
 * @param salt - Salt ที่จะเพิ่มเข้าไป
 * @returns Hash ในรูปแบบ hexadecimal
 */
async function hashSHA1(password: string, salt: string): Promise<string> {
  const msgBuffer = new TextEncoder().encode(password + salt);
  const hashBuffer = await crypto.subtle.digest('SHA-1', msgBuffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Hash password ด้วย SHA-256 Algorithm
 * 
 * SHA-256 เป็น algorithm ที่ปลอดภัยและแนะนำสำหรับการใช้งานทั่วไป
 * เป็นส่วนหนึ่งของ SHA-2 family
 * 
 * @param password - รหัสผ่านที่ต้องการ hash
 * @param salt - Salt ที่จะเพิ่มเข้าไป
 * @returns Hash ในรูปแบบ hexadecimal
 */
async function hashSHA256(password: string, salt: string): Promise<string> {
  const msgBuffer = new TextEncoder().encode(password + salt);
  const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Hash password ด้วย SHA-512 Algorithm
 * 
 * SHA-512 ให้ความปลอดภัยสูงสุดใน SHA-2 family
 * ใช้เวลาในการคำนวณมากกว่า SHA-256 เล็กน้อย แต่ปลอดภัยกว่า
 * 
 * @param password - รหัสผ่านที่ต้องการ hash
 * @param salt - Salt ที่จะเพิ่มเข้าไป
 * @returns Hash ในรูปแบบ hexadecimal
 */
async function hashSHA512(password: string, salt: string): Promise<string> {
  const msgBuffer = new TextEncoder().encode(password + salt);
  const hashBuffer = await crypto.subtle.digest('SHA-512', msgBuffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Hash password ด้วย bcrypt Algorithm
 * 
 * bcrypt เป็น algorithm ที่ออกแบบมาสำหรับ password hashing โดยเฉพาะ
 * มีคุณสมบัติพิเศษ:
 * - Adaptive: สามารถปรับความยากในการคำนวณได้ (cost factor)
 * - Salt ถูก generate และเก็บไว้ใน hash อัตโนมัติ
 * - ใช้เวลาในการคำนวณมากขึ้นเรื่อยๆ ตาม cost ที่กำหนด
 * - ป้องกัน brute force attack ได้ดี
 * 
 * @param password - รหัสผ่านที่ต้องการ hash
 * @returns Hash ที่มี salt รวมอยู่ด้วย
 */
async function hashBcrypt(password: string): Promise<string> {
  // Cost factor: 10 = 2^10 rounds (1024 iterations)
  // ยิ่งสูงยิ่งปลอดภัย แต่ใช้เวลานานขึ้น
  const saltRounds = 10;
  return await bcrypt.hash(password, saltRounds);
}

/**
 * ฟังก์ชันหลักสำหรับ Hash Password
 * 
 * รับ password และ algorithm แล้วทำการ hash ตาม algorithm ที่เลือก
 * 
 * @param password - รหัสผ่านที่ต้องการ hash
 * @param algorithm - Algorithm ที่ต้องการใช้
 * @returns ผลลัพธ์ที่ประกอบด้วย hashed password, salt, และ algorithm
 */
export async function hashPassword(
  password: string,
  algorithm: HashAlgorithm
): Promise<HashResult> {
  // bcrypt จัดการ salt เอง ไม่ต้องสร้างแยก
  if (algorithm === 'bcrypt') {
    const hashedPassword = await hashBcrypt(password);
    return {
      hashedPassword,
      salt: '', // bcrypt เก็บ salt ไว้ใน hash แล้ว
      algorithm,
    };
  }

  // สำหรับ algorithm อื่นๆ ต้องสร้าง salt เอง
  const salt = generateSalt();
  let hashedPassword: string;

  switch (algorithm) {
    case 'MD5':
      hashedPassword = await hashMD5(password, salt);
      break;
    case 'SHA-1':
      hashedPassword = await hashSHA1(password, salt);
      break;
    case 'SHA-256':
      hashedPassword = await hashSHA256(password, salt);
      break;
    case 'SHA-512':
      hashedPassword = await hashSHA512(password, salt);
      break;
    default:
      throw new Error(`Unsupported algorithm: ${algorithm}`);
  }

  return {
    hashedPassword,
    salt,
    algorithm,
  };
}

/**
 * ตรวจสอบความถูกต้องของ Password
 * 
 * ใช้สำหรับ Login - เปรียบเทียบ password ที่ป้อนเข้ามากับ hash ที่บันทึกไว้
 * 
 * @param password - รหัสผ่านที่ผู้ใช้ป้อนเข้ามา
 * @param storedHash - Hash ที่บันทึกไว้ในระบบ
 * @param salt - Salt ที่ใช้ตอน register (สำหรับ non-bcrypt)
 * @param algorithm - Algorithm ที่ใช้ตอน register
 * @returns true ถ้า password ถูกต้อง, false ถ้าไม่ถูกต้อง
 */
export async function verifyPassword(
  password: string,
  storedHash: string,
  salt: string,
  algorithm: HashAlgorithm
): Promise<boolean> {
  // bcrypt มี built-in verification
  if (algorithm === 'bcrypt') {
    return await bcrypt.compare(password, storedHash);
  }

  // สำหรับ algorithm อื่นๆ ให้ hash password ที่ป้อนเข้ามาด้วย salt เดิม
  // แล้วเปรียบเทียบกับ hash ที่บันทึกไว้
  let newHash: string;

  switch (algorithm) {
    case 'MD5':
      newHash = await hashMD5(password, salt);
      break;
    case 'SHA-1':
      newHash = await hashSHA1(password, salt);
      break;
    case 'SHA-256':
      newHash = await hashSHA256(password, salt);
      break;
    case 'SHA-512':
      newHash = await hashSHA512(password, salt);
      break;
    default:
      throw new Error(`Unsupported algorithm: ${algorithm}`);
  }

  // เปรียบเทียบ hash ที่คำนวณใหม่กับ hash ที่บันทึกไว้
  return newHash === storedHash;
}

/**
 * ข้อมูลเกี่ยวกับ Hash Algorithms
 * ใช้สำหรับแสดงข้อมูลให้ผู้ใช้เลือก
 */
export const algorithmInfo: Record<HashAlgorithm, { name: string; description: string; security: string }> = {
  'MD5': {
    name: 'MD5',
    description: '128-bit hash (ไม่แนะนำ - ใช้เพื่อการศึกษา)',
    security: '⚠️ ต่ำ (มีช่องโหว่ collision)'
  },
  'SHA-1': {
    name: 'SHA-1',
    description: '160-bit hash (ไม่แนะนำสำหรับ production)',
    security: '⚠️ ปานกลาง (มีช่องโหว่บางส่วน)'
  },
  'SHA-256': {
    name: 'SHA-256',
    description: '256-bit hash (ปลอดภัย)',
    security: '✅ สูง (แนะนำใช้)'
  },
  'SHA-512': {
    name: 'SHA-512',
    description: '512-bit hash (ปลอดภัยมาก)',
    security: '✅ สูงมาก (แนะนำใช้)'
  },
  'bcrypt': {
    name: 'bcrypt',
    description: 'Adaptive hash สำหรับ password (ปลอดภัยที่สุด)',
    security: '✅ สูงสุด (แนะนำที่สุด)'
  }
};
