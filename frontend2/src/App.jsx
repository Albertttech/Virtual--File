// src/App.jsx
import { Routes, Route } from 'react-router-dom';
import AdminLayout from './components/AdminLayout';
import AdminDashboard from './pages/admin/AdminDashboard';
import AllVcfList from './pages/admin/AllVcfList';
import CreateVcfForm from './pages/admin/CreateVcfForm';
import VcfVault from './pages/admin/VcfVault';
export default function App() {
  return (
    <Routes>
      <Route path="/admin" element={<AdminLayout />}>
        <Route index element={<AdminDashboard />} />
        <Route path="dashboard" element={<AdminDashboard />} />
        <Route path="vcfs" element={<AllVcfList />} />
        <Route path="create" element={<CreateVcfForm />} />
        <Route path="vault" element={<VcfVault />} />
      </Route>
      <Route path="*" element={<div className="p-6">Not Found</div>} />
    </Routes>
  );
}