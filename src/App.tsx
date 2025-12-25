/**
 * App Component - หน้าหลักของแอปพลิเคชัน
 * 
 * คำอธิบาย:
 * - จัดการการสลับระหว่างหน้า Register และ Login
 * - แสดงข้อมูลผู้ใช้ที่เข้าสู่ระบบสำเร็จ
 * - มีฟีเจอร์ดูข้อมูลผู้ใช้ทั้งหมดในระบบ (สำหรับทดสอบ)
 */

import { useState } from 'react';
import './App.css';
import Register from './components/Register';
import Login from './components/Login';
import { getAllUsersForDisplay, clearAllUsers, type User } from './services/store';

// ประเภทของหน้าที่แสดง
type ViewType = 'register' | 'login' | 'success';

function App() {
  // State สำหรับเก็บหน้าที่แสดงอยู่
  const [currentView, setCurrentView] = useState<ViewType>('register');
  
  // State สำหรับเก็บชื่อผู้ใช้ที่ล็อกอินสำเร็จ
  const [loggedInUser, setLoggedInUser] = useState<string>('');
  
  // State สำหรับแสดง/ซ่อนรายการผู้ใช้ทั้งหมด
  const [showAllUsers, setShowAllUsers] = useState(false);

  /**
   * Callback เมื่อสมัครสมาชิกสำเร็จ
   * นำผู้ใช้ไปหน้า Login
   */
  const handleRegisterSuccess = () => {
    setCurrentView('login');
  };

  /**
   * Callback เมื่อเข้าสู่ระบบสำเร็จ
   * นำผู้ใช้ไปหน้าแสดงผลสำเร็จ
   */
  const handleLoginSuccess = (username: string) => {
    setLoggedInUser(username);
    setCurrentView('success');
  };

  /**
   * ฟังก์ชันสำหรับ Logout
   * กลับไปหน้า Login
   */
  const handleLogout = () => {
    setLoggedInUser('');
    setCurrentView('login');
  };

  /**
   * ฟังก์ชันสำหรับรีเซ็ตระบบ
   * ลบข้อมูลผู้ใช้ทั้งหมดและกลับไปหน้า Register
   */
  const handleResetSystem = () => {
    if (window.confirm('คุณต้องการลบข้อมูลผู้ใช้ทั้งหมดใช่หรือไม่?')) {
      clearAllUsers();
      setLoggedInUser('');
      setCurrentView('register');
      setShowAllUsers(false);
      alert('ลบข้อมูลทั้งหมดเรียบร้อย');
    }
  };

  /**
   * ดึงข้อมูลผู้ใช้ทั้งหมด (สำหรับแสดงผล)
   */
  const allUsers = showAllUsers ? getAllUsersForDisplay() : [];

  return (
    <div className="App">
      {/* Header */}
      <header className="app-header">
        <h1>🔐 Hash Password with Salt System</h1>
        <p className="header-subtitle">ระบบจัดการรหัสผ่านแบบปลอดภัย</p>
      </header>

      {/* Main Content */}
      <main className="app-main">
        {/* แสดงหน้าตาม currentView */}
        {currentView === 'register' && (
          <Register
            onSwitchToLogin={() => setCurrentView('login')}
            onRegisterSuccess={handleRegisterSuccess}
          />
        )}

        {currentView === 'login' && (
          <Login
            onSwitchToRegister={() => setCurrentView('register')}
            onLoginSuccess={handleLoginSuccess}
          />
        )}

        {currentView === 'success' && (
          <div className="auth-container">
            <div className="auth-card success-card">
              <h2>✅ เข้าสู่ระบบสำเร็จ!</h2>
              <p className="welcome-message">
                ยินดีต้อนรับ <strong>{loggedInUser}</strong>
              </p>
              
              <div className="success-info">
                <p>คุณได้เข้าสู่ระบบเรียบร้อยแล้ว</p>
                <p>รหัสผ่านของคุณถูกเก็บอย่างปลอดภัยด้วย Hash + Salt</p>
              </div>

              <div className="button-group">
                <button 
                  className="btn-secondary" 
                  onClick={handleLogout}
                >
                  ออกจากระบบ
                </button>
              </div>
            </div>
          </div>
        )}
      </main>

      {/* Footer - Debug Tools */}
      <footer className="app-footer">
        <div className="debug-section">
          <h3>🛠️ เครื่องมือสำหรับทดสอบ</h3>
          <div className="button-group">
            <button 
              className="btn-info" 
              onClick={() => setShowAllUsers(!showAllUsers)}
            >
              {showAllUsers ? 'ซ่อน' : 'แสดง'}ข้อมูลผู้ใช้ทั้งหมด
            </button>
            <button 
              className="btn-danger" 
              onClick={handleResetSystem}
            >
              รีเซ็ตระบบ (ลบข้อมูลทั้งหมด)
            </button>
          </div>

          {/* แสดงรายการผู้ใช้ทั้งหมด */}
          {showAllUsers && (
            <div className="users-table-container">
              <h4>📋 รายการผู้ใช้ในระบบ ({allUsers.length} คน)</h4>
              {allUsers.length === 0 ? (
                <p className="no-users">ยังไม่มีผู้ใช้ในระบบ</p>
              ) : (
                <div className="table-wrapper">
                  <table className="users-table">
                    <thead>
                      <tr>
                        <th>#</th>
                        <th>Username</th>
                        <th>Algorithm</th>
                        <th>Salt (ตัวอย่าง)</th>
                        <th>Hash (ตัวอย่าง)</th>
                        <th>สร้างเมื่อ</th>
                      </tr>
                    </thead>
                    <tbody>
                      {allUsers.map((user: User, index: number) => (
                        <tr key={user.username}>
                          <td>{index + 1}</td>
                          <td><strong>{user.username}</strong></td>
                          <td>
                            <span className="algorithm-badge">
                              {user.algorithm}
                            </span>
                          </td>
                          <td className="monospace">
                            {user.salt ? `${user.salt.substring(0, 16)}...` : 'N/A (bcrypt)'}
                          </td>
                          <td className="monospace">
                            {user.hashedPassword.substring(0, 20)}...
                          </td>
                          <td>
                            {new Date(user.createdAt).toLocaleString('th-TH')}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          )}
        </div>

        {/* ข้อมูลโปรเจกต์ */}
        <div className="project-info">
          <p>
            📚 <strong>โปรเจกต์:</strong> Hash Password with Salt และระบบตรวจสอบการเข้าสู่ระบบ
          </p>
          <p>
            💡 <strong>เทคโนโลยี:</strong> React + TypeScript + Web Crypto API + bcryptjs
          </p>
        </div>
      </footer>
    </div>
  );
}

export default App;
