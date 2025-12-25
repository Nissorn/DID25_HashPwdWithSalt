/**
 * Login Component - หน้าเข้าสู่ระบบ
 * 
 * คำอธิบาย:
 * - รับ username และ password จากผู้ใช้
 * - ดึง salt และ algorithm ของผู้ใช้จากระบบ
 * - Hash password ที่ป้อนเข้ามาด้วย salt และ algorithm เดิม
 * - เปรียบเทียบกับ hash ที่บันทึกไว้
 * - แสดงผลว่า Login สำเร็จหรือไม่
 */

import React, { useState } from 'react';
import { verifyPassword } from '../services/hash';
import { findUserByUsername } from '../services/store';

interface LoginProps {
  onSwitchToRegister: () => void;  // ฟังก์ชันสำหรับสลับไปหน้า Register
  onLoginSuccess: (username: string) => void; // ฟังก์ชันเมื่อ Login สำเร็จ
}

/**
 * Component สำหรับเข้าสู่ระบบ
 */
const Login: React.FC<LoginProps> = ({ onSwitchToRegister, onLoginSuccess }) => {
  // State สำหรับเก็บข้อมูลจากฟอร์ม
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  
  // State สำหรับแสดงผลลัพธ์
  const [message, setMessage] = useState('');
  const [isError, setIsError] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  
  // State สำหรับแสดง/ซ่อน password
  const [showPassword, setShowPassword] = useState(false);

  /**
   * ฟังก์ชันจัดการการเข้าสู่ระบบ
   * 
   * ขั้นตอนการตรวจสอบ:
   * 1. ตรวจสอบว่ามี username ในระบบหรือไม่
   * 2. ดึงข้อมูล salt และ algorithm ของผู้ใช้
   * 3. Hash password ที่ป้อนเข้ามาด้วย salt และ algorithm เดิม
   * 4. เปรียบเทียบ hash ใหม่กับ hash ที่บันทึกไว้
   * 5. แสดงผลว่า Login สำเร็จหรือไม่
   */
  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setMessage('');
    setIsError(false);
    setIsLoading(true);

    try {
      // Validation - ตรวจสอบความถูกต้องของข้อมูล
      if (!username.trim()) {
        throw new Error('กรุณากรอกชื่อผู้ใช้');
      }

      if (!password) {
        throw new Error('กรุณากรอกรหัสผ่าน');
      }

      // 1. ค้นหาผู้ใช้ในระบบ
      const user = findUserByUsername(username);
      
      if (!user) {
        throw new Error('ไม่พบชื่อผู้ใช้นี้ในระบบ');
      }

      // 2. ตรวจสอบรหัสผ่าน
      // ฟังก์ชัน verifyPassword จะ:
      // - รับ password ที่ผู้ใช้ป้อนเข้ามา
      // - นำ password มา hash ด้วย salt และ algorithm เดิม (ที่เก็บไว้ในระบบ)
      // - เปรียบเทียบกับ hashed password ที่บันทึกไว้
      // - คืนค่า true ถ้าตรงกัน, false ถ้าไม่ตรงกัน
      const isValid = await verifyPassword(
        password,
        user.hashedPassword,
        user.salt,
        user.algorithm
      );

      if (!isValid) {
        throw new Error('รหัสผ่านไม่ถูกต้อง');
      }

      // 3. Login สำเร็จ
      setMessage(`เข้าสู่ระบบสำเร็จ! ยินดีต้อนรับ ${user.username}`);
      setIsError(false);

      // เคลียร์ฟอร์ม
      setPassword('');

      // เรียก callback เมื่อสำเร็จ
      setTimeout(() => {
        onLoginSuccess(user.username);
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
        <h2>เข้าสู่ระบบ</h2>
        <p className="subtitle">ตรวจสอบรหัสผ่านด้วย Hash + Salt</p>

        <form onSubmit={handleLogin}>
          {/* Username Input */}
          <div className="form-group">
            <label htmlFor="username">ชื่อผู้ใช้</label>
            <input
              id="username"
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder="กรอกชื่อผู้ใช้"
              disabled={isLoading}
              autoComplete="username"
              autoFocus
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
                placeholder="กรอกรหัสผ่าน"
                disabled={isLoading}
                autoComplete="current-password"
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

          {/* Submit Button */}
          <button 
            type="submit" 
            className="btn-primary" 
            disabled={isLoading}
          >
            {isLoading ? 'กำลังตรวจสอบ...' : 'เข้าสู่ระบบ'}
          </button>

          {/* Message Display */}
          {message && (
            <div className={`message ${isError ? 'error' : 'success'}`}>
              {message}
            </div>
          )}
        </form>

        {/* Switch to Register */}
        <div className="auth-footer">
          <p>
            ยังไม่มีบัญชี?{' '}
            <button 
              type="button" 
              className="link-button" 
              onClick={onSwitchToRegister}
              disabled={isLoading}
            >
              สมัครสมาชิก
            </button>
          </p>
        </div>

        {/* Information Section */}
        <div className="info-section">
          <h3>🔐 กระบวนการตรวจสอบรหัสผ่าน</h3>
          <ol>
            <li>ระบบดึง <strong>Salt</strong> และ <strong>Algorithm</strong> ของผู้ใช้</li>
            <li>นำรหัสผ่านที่ป้อนมา <strong>Hash</strong> ด้วย Salt และ Algorithm เดิม</li>
            <li><strong>เปรียบเทียบ</strong> hash ใหม่กับ hash ที่บันทึกไว้</li>
            <li>ถ้าตรงกัน = รหัสผ่านถูกต้อง ✅</li>
          </ol>
          
          <div className="security-note">
            <strong>⚠️ หมายเหตุ:</strong> ระบบไม่สามารถแสดงรหัสผ่านจริงของคุณได้
            เพราะเก็บเฉพาะค่า Hash เท่านั้น (ไม่สามารถย้อนกลับเป็นรหัสผ่านจริงได้)
          </div>
        </div>
      </div>
    </div>
  );
};

export default Login;
