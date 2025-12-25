/**
 * Storage Service - ระบบจัดเก็บข้อมูลผู้ใช้
 * 
 * คำอธิบาย:
 * - ใช้ localStorage สำหรับเก็บข้อมูลผู้ใช้ในฝั่ง client
 * - เก็บ username, salt, algorithm, และ hashed password
 * - ห้ามเก็บ plain text password ตามหลักความปลอดภัย
 */

import { HashAlgorithm } from './hash';

/**
 * โครงสร้างข้อมูลผู้ใช้ที่จัดเก็บในระบบ
 * 
 * ⚠️ สำคัญ: ไม่มีฟิลด์ password แบบ plain text
 * เก็บเฉพาะ hashed password เท่านั้น
 */
export interface User {
  username: string;          // ชื่อผู้ใช้ (unique)
  hashedPassword: string;    // รหัสผ่านที่ hash แล้ว
  salt: string;              // Salt ที่ใช้ (สำหรับ non-bcrypt algorithms)
  algorithm: HashAlgorithm;  // Algorithm ที่ใช้ในการ hash
  createdAt: string;         // วันที่สร้างบัญชี
}

/**
 * Key สำหรับเก็บข้อมูลใน localStorage
 */
const STORAGE_KEY = 'users_database';

/**
 * ดึงข้อมูลผู้ใช้ทั้งหมดจาก localStorage
 * 
 * @returns Array ของข้อมูลผู้ใช้ทั้งหมด
 */
function getAllUsers(): User[] {
  try {
    const data = localStorage.getItem(STORAGE_KEY);
    if (!data) {
      return [];
    }
    return JSON.parse(data) as User[];
  } catch (error) {
    console.error('Error reading from localStorage:', error);
    return [];
  }
}

/**
 * บันทึกข้อมูลผู้ใช้ทั้งหมดลง localStorage
 * 
 * @param users - Array ของข้อมูลผู้ใช้
 */
function saveAllUsers(users: User[]): void {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(users));
  } catch (error) {
    console.error('Error writing to localStorage:', error);
    throw new Error('ไม่สามารถบันทึกข้อมูลได้');
  }
}

/**
 * ค้นหาผู้ใช้จาก username
 * 
 * @param username - ชื่อผู้ใช้ที่ต้องการค้นหา
 * @returns ข้อมูลผู้ใช้ หรือ undefined ถ้าไม่พบ
 */
export function findUserByUsername(username: string): User | undefined {
  const users = getAllUsers();
  // ค้นหาแบบ case-insensitive
  return users.find(user => user.username.toLowerCase() === username.toLowerCase());
}

/**
 * ตรวจสอบว่า username นี้มีอยู่ในระบบแล้วหรือไม่
 * 
 * @param username - ชื่อผู้ใช้ที่ต้องการตรวจสอบ
 * @returns true ถ้ามีผู้ใช้นี้แล้ว, false ถ้าไม่มี
 */
export function isUsernameExists(username: string): boolean {
  return findUserByUsername(username) !== undefined;
}

/**
 * ลงทะเบียนผู้ใช้ใหม่
 * 
 * บันทึกข้อมูลผู้ใช้ใหม่ลงในระบบ
 * ตรวจสอบว่า username ซ้ำหรือไม่ก่อนบันทึก
 * 
 * @param user - ข้อมูลผู้ใช้ที่ต้องการลงทะเบียน
 * @returns true ถ้าสำเร็จ
 * @throws Error ถ้า username ซ้ำหรือมีข้อผิดพลาด
 */
export function registerUser(user: Omit<User, 'createdAt'>): boolean {
  // ตรวจสอบว่า username ซ้ำหรือไม่
  if (isUsernameExists(user.username)) {
    throw new Error('ชื่อผู้ใช้นี้ถูกใช้งานแล้ว');
  }

  // ตรวจสอบความถูกต้องของข้อมูล
  if (!user.username || user.username.trim() === '') {
    throw new Error('กรุณากระบุชื่อผู้ใช้');
  }

  if (!user.hashedPassword) {
    throw new Error('ข้อมูลรหัสผ่านไม่ถูกต้อง');
  }

  // สร้าง user object พร้อม timestamp
  const newUser: User = {
    ...user,
    createdAt: new Date().toISOString(),
  };

  // เพิ่มผู้ใช้ใหม่เข้าไปในรายการ
  const users = getAllUsers();
  users.push(newUser);
  saveAllUsers(users);

  return true;
}

/**
 * ดึงข้อมูลผู้ใช้ทั้งหมด (สำหรับแสดงผล/ดีบัก)
 * 
 * ⚠️ ข้อควรระวัง: ไม่ควรเปิดเผยข้อมูลนี้ในระบบจริง
 * ใช้เพื่อการทดสอบและแสดงผลเท่านั้น
 * 
 * @returns Array ของข้อมูลผู้ใช้ทั้งหมด
 */
export function getAllUsersForDisplay(): User[] {
  return getAllUsers();
}

/**
 * ลบข้อมูลผู้ใช้ทั้งหมด
 * 
 * ใช้สำหรับ reset ระบบหรือทดสอบ
 * 
 * @returns true ถ้าสำเร็จ
 */
export function clearAllUsers(): boolean {
  try {
    localStorage.removeItem(STORAGE_KEY);
    return true;
  } catch (error) {
    console.error('Error clearing localStorage:', error);
    return false;
  }
}

/**
 * นับจำนวนผู้ใช้ทั้งหมดในระบบ
 * 
 * @returns จำนวนผู้ใช้
 */
export function getUserCount(): number {
  return getAllUsers().length;
}

/**
 * ลบผู้ใช้ตาม username
 * 
 * @param username - ชื่อผู้ใช้ที่ต้องการลบ
 * @returns true ถ้าลบสำเร็จ, false ถ้าไม่พบผู้ใช้
 */
export function deleteUser(username: string): boolean {
  const users = getAllUsers();
  const filteredUsers = users.filter(
    user => user.username.toLowerCase() !== username.toLowerCase()
  );

  // ถ้าจำนวนไม่เปลี่ยน แสดงว่าไม่พบผู้ใช้
  if (filteredUsers.length === users.length) {
    return false;
  }

  saveAllUsers(filteredUsers);
  return true;
}

/**
 * ส่งออกข้อมูลผู้ใช้ทั้งหมดเป็น JSON
 * (สำหรับการ backup หรือดีบัก)
 * 
 * @returns JSON string ของข้อมูลผู้ใช้ทั้งหมด
 */
export function exportUsersData(): string {
  const users = getAllUsers();
  return JSON.stringify(users, null, 2);
}

/**
 * นำเข้าข้อมูลผู้ใช้จาก JSON string
 * (สำหรับการ restore)
 * 
 * @param jsonData - JSON string ของข้อมูลผู้ใช้
 * @returns true ถ้าสำเร็จ
 */
export function importUsersData(jsonData: string): boolean {
  try {
    const users = JSON.parse(jsonData) as User[];
    
    // ตรวจสอบความถูกต้องของข้อมูล
    if (!Array.isArray(users)) {
      throw new Error('ข้อมูลไม่ถูกต้อง');
    }

    saveAllUsers(users);
    return true;
  } catch (error) {
    console.error('Error importing data:', error);
    throw new Error('ไม่สามารถนำเข้าข้อมูลได้');
  }
}
