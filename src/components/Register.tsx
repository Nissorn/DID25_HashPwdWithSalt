/**
 * Register Component - หน้าสมัครสมาชิก
 * 
 * คำอธิบาย:
 * - รับ username และ password จากผู้ใช้
 * - ให้ผู้ใช้เลือก Hash Algorithm
 * - ทำการ Hash password ด้วย Salt
 * - บันทึกข้อมูลลงระบบ (ไม่เก็บ plain text password)
 */

import React, { useState } from 'react';
import { hashPassword, algorithmInfo, type HashAlgorithm } from '../services/hash';
import { registerUser, isUsernameExists } from '../services/store';

interface RegisterProps {
  onSwitchToLogin: () => void;  // ฟังก์ชันสำหรับสลับไปหน้า Login
  onRegisterSuccess: () => void; // ฟังก์ชันเมื่อสมัครสมาชิกสำเร็จ
}

/**
 * Component สำหรับสมัครสมาชิก
 */
const Register: React.FC<RegisterProps> = ({ onSwitchToLogin, onRegisterSuccess }) => {
  // State สำหรับเก็บข้อมูลจากฟอร์ม
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [algorithm, setAlgorithm] = useState<HashAlgorithm>('SHA-256');
  
  // State สำหรับแสดงผลลัพธ์
  const [message, setMessage] = useState('');
  const [isError, setIsError] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  
  // State สำหรับแสดง/ซ่อน password
  const [showPassword, setShowPassword] = useState(false);

  /**
   * ฟังก์ชันจัดการการสมัครสมาชิก
   * 
   * ขั้นตอน:
   * 1. ตรวจสอบความถูกต้องของข้อมูล (validation)
   * 2. ตรวจสอบว่า username ซ้ำหรือไม่
   * 3. Hash password ด้วย algorithm ที่เลือก
   * 4. บันทึกข้อมูลลงระบบ (เก็บ hash + salt + algorithm)
   */
  const handleRegister = async (e: React.FormEvent) => {
    e.preventDefault();
    setMessage('');
    setIsError(false);
    setIsLoading(true);

    try {
      // 1. Validation - ตรวจสอบความถูกต้องของข้อมูล
      if (!username.trim()) {
        throw new Error('กรุณากรอกชื่อผู้ใช้');
      }

      if (username.length < 3) {
        throw new Error('ชื่อผู้ใช้ต้องมีอย่างน้อย 3 ตัวอักษร');
      }

      if (!password) {
        throw new Error('กรุณากรอกรหัสผ่าน');
      }

      if (password.length < 12) {
        throw new Error('รหัสผ่านต้องมีอย่างน้อย 12 ตัวอักษร (เพื่อความปลอดภัย)');
      }

      if (password !== confirmPassword) {
        throw new Error('รหัสผ่านไม่ตรงกัน');
      }

      // 2. ตรวจสอบว่า username ซ้ำหรือไม่
      if (isUsernameExists(username)) {
        throw new Error('ชื่อผู้ใช้นี้ถูกใช้งานแล้ว กรุณาเลือกชื่ออื่น');
      }

      // 3. Hash password พร้อม salt
      // ฟังก์ชัน hashPassword จะ:
      // - สร้าง salt แบบสุ่มสำหรับผู้ใช้คนนี้
      // - นำ password + salt มา hash ด้วย algorithm ที่เลือก
      // - คืนค่า hashedPassword, salt, และ algorithm กลับมา
      const hashResult = await hashPassword(password, algorithm);

      // 4. บันทึกข้อมูลลงระบบ
      // ⚠️ สำคัญ: ไม่เก็บ password แบบ plain text
      // เก็บเฉพาะ username, hashed password, salt, และ algorithm
      registerUser({
        username: username.trim(),
        hashedPassword: hashResult.hashedPassword,
        salt: hashResult.salt,
        algorithm: hashResult.algorithm,
      });

      // แสดงข้อความสำเร็จ
      setMessage(`สมัครสมาชิกสำเร็จ! (ใช้ ${algorithm})`);
      setIsError(false);

      // เคลียร์ฟอร์ม
      setUsername('');
      setPassword('');
      setConfirmPassword('');

      // เรียก callback เมื่อสำเร็จ
      setTimeout(() => {
        onRegisterSuccess();
      }, 1500);

    } catch (error) {
      // แสดงข้อความผิดพลาด
      setIsError(true);
      setMessage(error instanceof Error ? error.message : 'เกิดข้อผิดพลาด');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="auth-container">
      <div className="auth-card">
        <h2>สมัครสมาชิก</h2>
        <p className="subtitle">สร้างบัญชีใหม่พร้อม Hash Password + Salt</p>

        <form onSubmit={handleRegister}>
          {/* Username Input */}
          <div className="form-group">
            <label htmlFor="username">ชื่อผู้ใช้</label>
            <input
              id="username"
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder="อย่างน้อย 3 ตัวอักษร"
              disabled={isLoading}
              autoComplete="username"
            />
          </div>

          {/* Password Input */}
          <div className="form-group">
            <label htmlFor="password">รหัสผ่าน</label>
            <div className="password-input-wrapper">
              <input
                id="password"
                type={showPassword ? 'text' : 'password'}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
              placeholder="อย่างน้อย 12 ตัวอักษร (A-Z, a-z, 0-9)"
                disabled={isLoading}
                autoComplete="new-password"
              />
              <button
                type="button"
                className="toggle-password"
                onClick={() => setShowPassword(!showPassword)}
                tabIndex={-1}
              >
                {showPassword ? '👁️' : '👁️‍🗨️'}
              </button>
            </div>
          </div>

          {/* Confirm Password Input */}
          <div className="form-group">
            <label htmlFor="confirmPassword">ยืนยันรหัสผ่าน</label>
            <input
              id="confirmPassword"
              type={showPassword ? 'text' : 'password'}
              value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)}
              placeholder="กรอกรหัสผ่านอีกครั้ง"
              disabled={isLoading}
              autoComplete="new-password"
            />
          </div>

          {/* Algorithm Selection */}
          <div className="form-group">
            <label htmlFor="algorithm">
              เลือก Hash Algorithm
              <span className="info-icon" title="เลือกวิธีการเข้ารหัสรหัสผ่าน">ℹ️</span>
            </label>
            <select
              id="algorithm"
              value={algorithm}
              onChange={(e) => setAlgorithm(e.target.value as HashAlgorithm)}
              disabled={isLoading}
            >
              {/* แสดงตัวเลือก Algorithm ทั้งหมด */}
              {(Object.keys(algorithmInfo) as HashAlgorithm[]).map((algo) => (
                <option key={algo} value={algo}>
                  {algorithmInfo[algo].name} - {algorithmInfo[algo].description}
                </option>
              ))}
            </select>
            <small className="algorithm-security">
              ระดับความปลอดภัย: {algorithmInfo[algorithm].security}
            </small>
          </div>

          {/* Submit Button */}
          <button 
            type="submit" 
            className="btn-primary" 
            disabled={isLoading}
          >
            {isLoading ? 'กำลังประมวลผล...' : 'สมัครสมาชิก'}
          </button>

          {/* Message Display */}
          {message && (
            <div className={`message ${isError ? 'error' : 'success'}`}>
              {message}
            </div>
          )}
        </form>

        {/* Switch to Login */}
        <div className="auth-footer">
          <p>
            มีบัญชีอยู่แล้ว?{' '}
            <button 
              type="button" 
              className="link-button" 
              onClick={onSwitchToLogin}
              disabled={isLoading}
            >
              เข้าสู่ระบบ
            </button>
          </p>
        </div>

        {/* Information Section */}
        <div className="info-section">
          <h3>📚 ข้อมูลเกี่ยวกับความปลอดภัย</h3>
          <ul>
            <li><strong>Salt:</strong> ข้อมูลสุ่มที่เพิ่มเข้าไปก่อน hash เพื่อป้องกัน Rainbow Table Attack</li>
            <li><strong>Hash:</strong> การแปลงรหัสผ่านเป็นข้อความที่ไม่สามารถย้อนกลับได้</li>
            <li><strong>ไม่เก็บ Plain Text:</strong> ระบบไม่เก็บรหัสผ่านจริง เก็บเฉพาะผลลัพธ์ที่ hash แล้ว</li>
          </ul>
        </div>
      </div>
    </div>
  );
};

export default Register;
