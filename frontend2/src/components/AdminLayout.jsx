// src/components/AdminLayout.jsx
import { Outlet } from 'react-router-dom';

export default function AdminLayout() {
  return (
    <div>
      <h1>Admin Layout Loaded!</h1>
      <p>If you see this, the component is working.</p>
      <Outlet />
    </div>
  );
}