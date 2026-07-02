/**
 * App.jsx - Componente raíz de la aplicación
 * 
 * Este es el punto de entrada de todo el frontend del Dashboard EDR.
 * Se encarga de:
 *   1. Manejar el estado de autenticación (si el usuario está logueado o no)
 *   2. Configurar las rutas de la aplicación (Login y Dashboard)
 *   3. Redirigir al usuario según su estado de sesión
 * 
 * Usamos React Router para la navegación entre páginas.
 * El rol del usuario se guarda en localStorage para que persista
 * incluso si se recarga la página.
 */
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { useState, useEffect } from 'react';
import Login from './components/Login';
import Dashboard from './components/Dashboard';

function App() {
  /* 
   * Estado del rol del usuario.
   * Al iniciar, intentamos recuperarlo de localStorage por si ya estaba logueado.
   * Los valores posibles son: null (no logueado), "admin_user", "common_user"
   */
  const [role, setRole] = useState(localStorage.getItem('role') || null);

  /**
   * handleLogin - Se ejecuta cuando el usuario se autentica exitosamente
   * Guarda el rol en localStorage y actualiza el estado de React.
   */
  const handleLogin = (userRole) => {
    localStorage.setItem('role', userRole);
    setRole(userRole);
  };

  /**
   * handleLogout - Se ejecuta cuando el usuario cierra sesión
   * Elimina el rol de localStorage y limpia el estado de React.
   */
  const handleLogout = () => {
    localStorage.removeItem('role');
    setRole(null);
  };

  return (
    <Router>
      <Routes>
        {/* Redirigir la raíz "/" a la página de login */}
        <Route path="/" element={<Navigate to="/login" replace />} />
        
        {/* Ruta de login: solo accesible si NO hay sesión activa */}
        <Route 
          path="/login" 
          element={!role ? <Login onLogin={handleLogin} /> : <Navigate to="/dashboard" replace />} 
        />
        
        {/* Ruta del dashboard: solo accesible si HAY sesión activa */}
        <Route 
          path="/dashboard" 
          element={role ? <Dashboard role={role} onLogout={handleLogout} /> : <Navigate to="/login" replace />} 
        />
        
        {/* Cualquier otra ruta que no exista redirige a login */}
        <Route path="*" element={<Navigate to="/login" replace />} />
      </Routes>
    </Router>
  );
}

export default App;
