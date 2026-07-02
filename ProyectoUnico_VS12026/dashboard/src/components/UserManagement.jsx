/**
 * UserManagement.jsx - Componente de gestión de usuarios (solo admin)
 * 
 * Este componente permite al administrador crear nuevos usuarios
 * del sistema Linux directamente desde el dashboard.
 * 
 * Funcionalidades:
 *   - Formulario para crear usuarios con nombre, contraseña y rol
 *   - Selección de rol: admin_user o common_user
 *   - Validación de campos antes de enviar
 *   - Mensajes de éxito/error con feedback visual
 * 
 * El backend ejecuta los comandos useradd, chpasswd y usermod
 * para crear el usuario en el sistema Linux real.
 */
import { useState } from 'react';
import { UserPlus, Users, Shield, User, Eye, EyeOff } from 'lucide-react';
import axios from 'axios';

const UserManagement = ({ role }) => {
  /* ---- Estados del formulario ---- */
  const [username, setUsername] = useState('');       // Nombre del nuevo usuario
  const [password, setPassword] = useState('');       // Contraseña del nuevo usuario
  const [selectedRole, setSelectedRole] = useState('common_user'); // Rol seleccionado
  const [message, setMessage] = useState(null);       // Mensaje de feedback (éxito/error)
  const [isCreating, setIsCreating] = useState(false); // Estado de carga mientras se crea
  const [showPassword, setShowPassword] = useState(false); // Toggle para ver/ocultar contraseña

  /**
   * handleCreateUser - Envía la petición al backend para crear un usuario
   * 
   * Flujo:
   *   1. Validamos que los campos no estén vacíos
   *   2. Enviamos un POST a /api/create_user con los datos
   *   3. Mostramos un mensaje de éxito o error según la respuesta
   */
  const handleCreateUser = async (e) => {
    e.preventDefault(); // Evitamos que el formulario recargue la página

    // Validación básica de campos
    if (!username.trim() || !password.trim()) {
      setMessage({ type: 'error', text: 'Todos los campos son obligatorios.' });
      setTimeout(() => setMessage(null), 4000);
      return;
    }

    // Validar longitud del nombre de usuario
    if (username.length < 3) {
      setMessage({ type: 'error', text: 'El nombre de usuario debe tener al menos 3 caracteres.' });
      setTimeout(() => setMessage(null), 4000);
      return;
    }

    setIsCreating(true); // Activamos el estado de carga

    try {
      // Enviamos la petición POST al backend
      const res = await axios.post(
        `http://${window.location.hostname}:8080/api/create_user`,
        JSON.stringify({
          username: username.trim(),
          password: password,
          role: selectedRole
        }),
        { headers: { 'Content-Type': 'application/json' } }
      );

      if (res.data.status === 'success') {
        // Usuario creado exitosamente
        setMessage({ type: 'success', text: `Usuario "${username}" creado exitosamente con rol "${selectedRole}".` });
        // Limpiamos el formulario
        setUsername('');
        setPassword('');
        setSelectedRole('common_user');
      } else {
        setMessage({ type: 'error', text: res.data.message || 'Error al crear el usuario.' });
      }
    } catch (err) {
      // Manejamos errores de red o del servidor
      if (err.response && err.response.data && err.response.data.message) {
        setMessage({ type: 'error', text: err.response.data.message });
      } else {
        setMessage({ type: 'error', text: 'Error de conexión con el servidor.' });
      }
    }

    setIsCreating(false);
    setTimeout(() => setMessage(null), 5000); // El mensaje desaparece después de 5 segundos
  };

  /* Solo renderizamos si el usuario es administrador */
  if (role !== 'admin_user') {
    return (
      <div className="p-8 text-center text-gray-500 bg-gray-900 border border-gray-800 rounded-2xl">
        Solo los administradores pueden gestionar usuarios.
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Encabezado de la sección */}
      <div className="flex items-center gap-4 mb-8">
        <div className="p-4 bg-indigo-500/20 text-indigo-500 rounded-2xl">
          <Users size={32} />
        </div>
        <div>
          <h2 className="text-2xl font-bold text-white">Gestión de Usuarios</h2>
          <p className="text-gray-400">Crear nuevos usuarios del sistema para acceder al dashboard</p>
        </div>
      </div>

      {/* Mensaje de feedback (éxito o error) */}
      {message && (
        <div className={`p-4 rounded-xl border ${message.type === 'success' ? 'bg-emerald-500/10 border-emerald-500/50 text-emerald-400' : 'bg-red-500/10 border-red-500/50 text-red-400'}`}>
          {message.text}
        </div>
      )}

      {/* Formulario para crear nuevo usuario */}
      <div className="bg-gray-900 border border-gray-800 rounded-2xl p-8 shadow-xl">
        <h3 className="text-lg font-medium text-white mb-6 flex items-center gap-2">
          <UserPlus size={20} className="text-indigo-400" />
          Crear Nuevo Usuario
        </h3>

        <form onSubmit={handleCreateUser} className="space-y-5">
          {/* Campo: Nombre de usuario */}
          <div>
            <label className="block text-sm font-medium text-gray-400 mb-2">
              Nombre de Usuario
            </label>
            <div className="relative">
              <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                <User size={16} className="text-gray-500" />
              </div>
              <input
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="Ejemplo: operador1"
                className="w-full pl-10 pr-4 py-3 bg-gray-950 border border-gray-700 rounded-xl text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-indigo-500 transition-all"
                required
                maxLength={32}
                disabled={isCreating}
              />
            </div>
            <p className="mt-1 text-xs text-gray-500">El usuario se creará en el sistema Linux (3-32 caracteres)</p>
          </div>

          {/* Campo: Contraseña */}
          <div>
            <label className="block text-sm font-medium text-gray-400 mb-2">
              Contraseña
            </label>
            <div className="relative">
              <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                <Shield size={16} className="text-gray-500" />
              </div>
              <input
                type={showPassword ? "text" : "password"}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="Ingresa una contraseña segura"
                className="w-full pl-10 pr-12 py-3 bg-gray-950 border border-gray-700 rounded-xl text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-indigo-500 transition-all"
                required
                disabled={isCreating}
              />
              {/* Botón para mostrar/ocultar contraseña */}
              <button
                type="button"
                onClick={() => setShowPassword(!showPassword)}
                className="absolute inset-y-0 right-0 pr-3 flex items-center text-gray-500 hover:text-gray-300 transition-colors"
              >
                {showPassword ? <EyeOff size={16} /> : <Eye size={16} />}
              </button>
            </div>
          </div>

          {/* Selector de rol */}
          <div>
            <label className="block text-sm font-medium text-gray-400 mb-3">
              Rol del Usuario
            </label>
            <div className="grid grid-cols-2 gap-3">
              {/* Opción: Usuario estándar */}
              <button
                type="button"
                onClick={() => setSelectedRole('common_user')}
                className={`p-4 rounded-xl border text-left transition-all ${
                  selectedRole === 'common_user'
                    ? 'bg-blue-500/20 border-blue-500/50 text-blue-400'
                    : 'bg-gray-950 border-gray-700 text-gray-400 hover:border-gray-600'
                }`}
              >
                <div className="flex items-center gap-2 mb-1">
                  <User size={16} />
                  <span className="font-medium">common_user</span>
                </div>
                <p className="text-xs opacity-70">Solo visualización. No puede modificar configuraciones.</p>
              </button>

              {/* Opción: Administrador */}
              <button
                type="button"
                onClick={() => setSelectedRole('admin_user')}
                className={`p-4 rounded-xl border text-left transition-all ${
                  selectedRole === 'admin_user'
                    ? 'bg-purple-500/20 border-purple-500/50 text-purple-400'
                    : 'bg-gray-950 border-gray-700 text-gray-400 hover:border-gray-600'
                }`}
              >
                <div className="flex items-center gap-2 mb-1">
                  <Shield size={16} />
                  <span className="font-medium">admin_user</span>
                </div>
                <p className="text-xs opacity-70">Acceso completo. Puede matar procesos, cuarentena, etc.</p>
              </button>
            </div>
          </div>

          {/* Botón de envío */}
          <button
            type="submit"
            disabled={isCreating}
            className="w-full flex items-center justify-center gap-2 py-3 px-4 bg-indigo-600 hover:bg-indigo-700 disabled:bg-indigo-900 disabled:cursor-not-allowed text-white rounded-xl font-medium shadow-lg transition-colors"
          >
            <UserPlus size={18} />
            {isCreating ? 'Creando usuario...' : 'Crear Usuario'}
          </button>
        </form>
      </div>

      {/* Información adicional */}
      <div className="bg-gray-900/50 border border-gray-800 rounded-xl p-5">
        <h4 className="text-sm font-medium text-gray-300 mb-2">ℹ️ Información</h4>
        <ul className="text-xs text-gray-500 space-y-1">
          <li>• El usuario se crea en el sistema Linux y puede usarse para iniciar sesión en el dashboard.</li>
          <li>• Los usuarios <code className="text-blue-400 bg-gray-950 px-1 rounded">admin_user</code> tienen acceso completo a todas las funcionalidades.</li>
          <li>• Los usuarios <code className="text-blue-400 bg-gray-950 px-1 rounded">common_user</code> solo pueden visualizar métricas, procesos y alertas.</li>
          <li>• Si un usuario pertenece a ambos grupos, se le asigna el rol de administrador.</li>
        </ul>
      </div>
    </div>
  );
};

export default UserManagement;
