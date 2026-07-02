/**
 * Login.jsx - Componente de inicio de sesión
 * 
 * Este componente muestra el formulario de login del dashboard EDR.
 * Las credenciales se envían al backend (daemon en C) que las verifica
 * contra PAM (Pluggable Authentication Modules) del sistema Linux.
 * 
 * Si las credenciales son válidas, el backend retorna el rol del usuario
 * (admin_user o common_user) y el frontend redirige al dashboard.
 * 
 * Incluye:
 *   - Validación de campos
 *   - Indicador de carga mientras se verifica
 *   - Animación de shake cuando hay error
 *   - Mensajes de error descriptivos
 */
import { useState } from 'react';
import { Lock, User, Loader2 } from 'lucide-react';
import axios from 'axios';

const Login = ({ onLogin }) => {
  /* ---- Estados del formulario ---- */
  const [user, setUser] = useState('');          // Nombre de usuario ingresado
  const [pass, setPass] = useState('');          // Contraseña ingresada
  const [error, setError] = useState('');        // Mensaje de error a mostrar
  const [isLoading, setIsLoading] = useState(false);  // Indicador de carga
  const [isShaking, setIsShaking] = useState(false);  // Animación de shake en error

  /**
   * handleSubmit - Se ejecuta al enviar el formulario
   * Envía las credenciales al backend via GET /api/login
   */
  const handleSubmit = async (e) => {
    e.preventDefault(); // Evitamos que la página se recargue
    setIsLoading(true);
    setError('');
    
    try {
      // Enviamos las credenciales al backend
      const res = await axios.get(`http://${window.location.hostname}:8080/api/login?user=${user}&pass=${pass}`);
      if (res.data.status === 'success') {
        // Login exitoso: llamamos a onLogin con el rol del usuario
        onLogin(res.data.role);
      } else {
        triggerError(res.data.message || 'Error desconocido');
      }
    } catch (err) {
      // Manejamos diferentes tipos de errores
      if (err.response && err.response.data && err.response.data.message) {
        triggerError(err.response.data.message);
      } else {
        triggerError('Credenciales inválidas o error de conexión al servidor.');
      }
    } finally {
      setIsLoading(false);
    }
  };

  /**
   * triggerError - Muestra un error con animación de shake
   * La animación hace que el formulario "tiemble" brevemente,
   * dando feedback visual inmediato al usuario.
   */
  const triggerError = (msg) => {
    setError(msg);
    setIsShaking(true);
    setTimeout(() => setIsShaking(false), 400);
  };

  return (
    <div 
      className="min-h-screen flex items-center justify-center p-4 bg-cover bg-center bg-no-repeat relative"
      style={{ backgroundImage: 'url(/bg.png)' }}
    >
      {/* Overlay oscuro con efecto de desenfoque */}
      <div className="absolute inset-0 bg-gray-950/80 backdrop-blur-sm z-0"></div>

      {/* Tarjeta del formulario con efecto glassmorphism */}
      <div className={`max-w-md w-full bg-gray-900/90 rounded-2xl shadow-2xl overflow-hidden border border-gray-700 z-10 backdrop-blur-md ${isShaking ? 'animate-shake' : ''}`}>
        <div className="p-8">
          {/* Encabezado */}
          <div className="text-center mb-8">
            <h2 className="text-3xl font-bold text-white mb-2">EDR Híbrido</h2>
            <p className="text-gray-400">Inicia sesión en el panel de seguridad</p>
          </div>

          {/* Mensaje de error (solo visible cuando hay error) */}
          {error && (
            <div className="bg-red-500/10 border border-red-500/50 text-red-500 text-sm p-3 rounded-lg mb-6">
              {error}
            </div>
          )}

          {/* Formulario de login */}
          <form onSubmit={handleSubmit} className="space-y-6">
            {/* Campo de usuario */}
            <div>
              <label className="block text-sm font-medium text-gray-400 mb-2">Usuario</label>
              <div className="relative">
                <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                  <User className="h-5 w-5 text-gray-500" />
                </div>
                <input
                  type="text"
                  value={user}
                  onChange={(e) => setUser(e.target.value)}
                  disabled={isLoading}
                  className="block w-full pl-10 pr-3 py-2 border border-gray-700 rounded-lg bg-gray-800 text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-all disabled:opacity-50"
                  placeholder="admin"
                  required
                />
              </div>
            </div>

            {/* Campo de contraseña */}
            <div>
              <label className="block text-sm font-medium text-gray-400 mb-2">Contraseña</label>
              <div className="relative">
                <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                  <Lock className="h-5 w-5 text-gray-500" />
                </div>
                <input
                  type="password"
                  value={pass}
                  onChange={(e) => setPass(e.target.value)}
                  disabled={isLoading}
                  className="block w-full pl-10 pr-3 py-2 border border-gray-700 rounded-lg bg-gray-800 text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-all disabled:opacity-50"
                  placeholder="••••••••"
                  required
                />
              </div>
            </div>

            {/* Botón de ingreso con indicador de carga */}
            <button
              type="submit"
              disabled={isLoading}
              className="w-full flex justify-center items-center gap-2 py-3 px-4 border border-transparent rounded-lg shadow-sm text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 transition-colors disabled:bg-blue-800 disabled:cursor-not-allowed"
            >
              {isLoading ? (
                <>
                  <Loader2 className="animate-spin h-5 w-5" />
                  Verificando...
                </>
              ) : (
                'Ingresar'
              )}
            </button>
          </form>
        </div>
      </div>
    </div>
  );
};

export default Login;
