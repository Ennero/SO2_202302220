/**
 * Dashboard.jsx - Componente principal del panel de control
 * 
 * Este es el layout principal del dashboard. Contiene:
 *   - Sidebar con navegación entre las diferentes secciones
 *   - Área de contenido principal que cambia según la pestaña activa
 *   - Indicador del rol del usuario (admin o estándar)
 *   - Botón de cerrar sesión
 * 
 * El dashboard se adapta automáticamente según el rol del usuario:
 *   - admin_user: Ve todas las secciones incluyendo Gestión de Usuarios
 *   - common_user: Ve solo las secciones de visualización
 * 
 * Los datos se obtienen en tiempo real cada 2 segundos del backend
 * (daemon en C corriendo en el puerto 8080).
 */
import { useState, useEffect } from 'react';
import { Activity, ShieldAlert, Cpu, FileWarning, LogOut, Menu, X, FileSearch, Bug, Users } from 'lucide-react';
import Metrics from './Metrics';
import Processes from './Processes';
import Alerts from './Alerts';
import Quarantine from './Quarantine';
import Files from './Files';
import Threats from './Threats';
import UserManagement from './UserManagement';
import axios from 'axios';

const Dashboard = ({ role, onLogout }) => {
  /* ---- Estados del componente ---- */
  const [activeTab, setActiveTab] = useState('metrics');     // Pestaña activa actual
  const [isSidebarOpen, setIsSidebarOpen] = useState(true);  // Si el sidebar está visible
  const [metrics, setMetrics] = useState(null);              // Datos de métricas del sistema
  const [alerts, setAlerts] = useState([]);                  // Lista de alertas de seguridad
  const [isTransitioning, setIsTransitioning] = useState(false); // Animación de transición

  /**
   * useEffect para obtener métricas y alertas periódicamente.
   * Se ejecuta al montar el componente y cada 2 segundos.
   * 
   * Usamos setInterval para polling (consulta periódica).
   * El return () => clearInterval() limpia el intervalo
   * cuando el componente se desmonta (evita memory leaks).
   */
  useEffect(() => {
    // Función que obtiene las métricas del sistema del backend
    const fetchMetrics = async () => {
      try {
        const res = await axios.get(`http://${window.location.hostname}:8080/api/metrics`);
        setMetrics(res.data);
      } catch (err) {
        console.error("Error fetching metrics:", err);
      }
    };

    // Función que obtiene las alertas de seguridad del backend
    const fetchAlerts = async () => {
      try {
        const res = await axios.get(`http://${window.location.hostname}:8080/api/alerts`);
        setAlerts(res.data);
      } catch (err) {
        console.error("Error fetching alerts:", err);
      }
    };

    // Ejecutamos inmediatamente y luego cada 2 segundos
    fetchMetrics();
    fetchAlerts();
    const interval = setInterval(() => {
      fetchMetrics();
      fetchAlerts();
    }, 1000);

    // Cleanup: limpiar el intervalo al desmontar el componente
    return () => clearInterval(interval);
  }, []); // [] = solo se ejecuta una vez al montar

  /**
   * changeTab - Cambia la pestaña activa con animación
   * Aplica una transición suave de fade+slide para que el cambio
   * de contenido se vea fluido y profesional.
   */
  const changeTab = (tab) => {
    if (tab === activeTab) return; // No hacer nada si ya está en esa pestaña
    setIsTransitioning(true); // Inicia la animación de salida
    setTimeout(() => {
      setActiveTab(tab);
      setIsTransitioning(false); // Inicia la animación de entrada
    }, 200);
  };

  /**
   * Definición de las pestañas del sidebar.
   * Cada objeto tiene: id, label, icono, y si se muestra siempre.
   * La pestaña de "Gestión de Usuarios" solo se muestra para admins.
   */
  const navItems = [
    { id: 'metrics', label: 'Métricas Globales', icon: Activity, showAlways: true },
    { id: 'processes', label: 'Procesos', icon: Cpu, showAlways: true },
    { id: 'files', label: 'Archivos Analizados', icon: FileSearch, showAlways: true },
    { id: 'threats', label: 'Amenazas', icon: Bug, showAlways: true },
    { id: 'alerts', label: `Alertas (${alerts.length})`, icon: ShieldAlert, showAlways: true },
    { id: 'quarantine', label: 'Cuarentena', icon: FileWarning, showAlways: true },
    ...(role === 'admin_user' ? [{ id: 'users', label: 'Gestión de Usuarios', icon: Users, showAlways: true }] : []),
  ];

  return (
    <div 
      className="flex h-screen text-gray-100 font-sans bg-cover bg-center bg-no-repeat relative"
      style={{ backgroundImage: 'url(/bg.png)' }}
    >
      {/* Overlay oscuro con efecto glassmorphism sobre el fondo */}
      <div className="absolute inset-0 bg-gray-950/80 backdrop-blur-md z-0"></div>
      
      {/* Botón para abrir/cerrar el sidebar (responsive) */}
      <button 
        onClick={() => setIsSidebarOpen(!isSidebarOpen)}
        className="absolute top-4 left-4 z-50 p-2 bg-gray-900 border border-gray-700 rounded-lg text-white hover:bg-gray-800 transition-colors shadow-lg"
      >
        {isSidebarOpen ? <X size={20} /> : <Menu size={20} />}
      </button>

      {/* ---- SIDEBAR (Barra lateral de navegación) ---- */}
      <aside 
        className={`bg-gray-900/90 border-r border-gray-800 flex flex-col transition-all duration-300 ease-in-out z-40 backdrop-blur-xl ${
          isSidebarOpen ? 'w-64 translate-x-0' : 'w-0 -translate-x-full overflow-hidden border-r-0'
        }`}
      >
        {/* Logo y nombre de la aplicación */}
        <div className="p-6 border-b border-gray-800 pl-16">
          <h1 className="text-xl font-bold text-white flex items-center gap-2">
            <ShieldAlert className="text-blue-500" />
            EDR Core
          </h1>
          {/* Mostramos el rol del usuario actual */}
          <p className="text-xs text-gray-500 mt-2 uppercase tracking-wider">
            {role === 'admin_user' ? 'Administrador' : 'Usuario Estándar'}
          </p>
        </div>
        
        {/* Lista de pestañas de navegación */}
        <nav className="flex-1 p-4 space-y-1.5 overflow-y-auto">
          {navItems.map(item => (
            <button
              key={item.id}
              onClick={() => changeTab(item.id)}
              className={`w-full flex items-center gap-3 px-4 py-3 rounded-lg transition-colors ${
                activeTab === item.id 
                  ? 'bg-blue-600/20 text-blue-400 border border-blue-500/30' 
                  : 'text-gray-400 hover:bg-gray-800 hover:text-gray-200'
              }`}
            >
              <item.icon size={18} />
              <span className="font-medium whitespace-nowrap text-sm">{item.label}</span>
            </button>
          ))}
        </nav>

        {/* Botón de cerrar sesión */}
        <div className="p-4 border-t border-gray-800">
          <button
            onClick={onLogout}
            className="w-full flex items-center gap-3 px-4 py-3 text-red-400 hover:bg-red-500/10 rounded-lg transition-colors"
          >
            <LogOut size={20} />
            <span className="font-medium whitespace-nowrap">Cerrar Sesión</span>
          </button>
        </div>
      </aside>

      {/* ---- CONTENIDO PRINCIPAL ---- */}
      <main className="flex-1 overflow-y-auto p-8 pt-16 z-10 transition-all duration-300">
        <div 
          className={`max-w-7xl mx-auto transition-all duration-200 transform ${
            isTransitioning ? 'opacity-0 scale-95 translate-y-4' : 'opacity-100 scale-100 translate-y-0'
          }`}
        >
          {/* Renderizamos el componente correspondiente a la pestaña activa */}
          {activeTab === 'metrics' && <Metrics metrics={metrics} role={role} />}
          {activeTab === 'processes' && <Processes role={role} totalRam={metrics ? metrics.memoria_usada + metrics.memoria_libre : 0} />}
          {activeTab === 'files' && <Files role={role} />}
          {activeTab === 'threats' && <Threats role={role} />}
          {activeTab === 'alerts' && <Alerts alerts={alerts} />}
          {activeTab === 'quarantine' && <Quarantine role={role} />}
          {activeTab === 'users' && <UserManagement role={role} />}
        </div>
      </main>
    </div>
  );
};

export default Dashboard;
