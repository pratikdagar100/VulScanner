import { Navigate, Route, BrowserRouter as Router, Routes } from 'react-router-dom';

import AppLayout from '@/layouts/AppLayout';
import { tokens } from '@/services/api';

import AssetDetail from '@/pages/AssetDetail';
import Assets from '@/pages/Assets';
import AuditLogs from '@/pages/AuditLogs';
import Dashboard from '@/pages/Dashboard';
import FindingDetail from '@/pages/FindingDetail';
import Findings from '@/pages/Findings';
import Login from '@/pages/Login';
import NetworkMap from '@/pages/NetworkMap';
import NewScan from '@/pages/NewScan';
import PortsServices from '@/pages/PortsServices';
import PostureView from '@/pages/PostureView';
import Remediation from '@/pages/Remediation';
import Reports from '@/pages/Reports';
import ScanDetail from '@/pages/ScanDetail';
import Scans from '@/pages/Scans';
import Settings from '@/pages/Settings';
import Vulnerabilities from '@/pages/Vulnerabilities';

function RequireAuth({ children }: { children: JSX.Element }) {
  return tokens.access() ? children : <Navigate to="/login" replace />;
}

export default function App() {
  return (
    <Router>
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route
          path="/"
          element={
            <RequireAuth>
              <AppLayout />
            </RequireAuth>
          }
        >
          <Route index element={<Dashboard />} />
          <Route path="assets" element={<Assets />} />
          <Route path="assets/:assetId" element={<AssetDetail />} />
          <Route path="scans" element={<Scans />} />
          <Route path="scans/new" element={<NewScan />} />
          <Route path="scans/:scanId" element={<ScanDetail />} />
          <Route path="findings" element={<Findings />} />
          <Route path="findings/:findingId" element={<FindingDetail />} />
          <Route path="vulnerabilities" element={<Vulnerabilities />} />
          <Route path="remediation" element={<Remediation />} />
          <Route path="network" element={<NetworkMap />} />
          <Route path="ports" element={<PortsServices />} />

          {/* Windows posture views are all projections of stored collector
              evidence, so they share one evidence-driven page. */}
          <Route path="software" element={<PostureView view="software" />} />
          <Route path="patches" element={<PostureView view="patches" />} />
          <Route path="firewall" element={<PostureView view="firewall" />} />
          <Route path="defender" element={<PostureView view="defender" />} />
          <Route path="rdp" element={<PostureView view="rdp" />} />
          <Route path="accounts" element={<PostureView view="accounts" />} />
          <Route path="policies" element={<PostureView view="policies" />} />

          <Route path="reports" element={<Reports />} />
          <Route path="audit" element={<AuditLogs />} />
          <Route path="settings" element={<Settings />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Route>
      </Routes>
    </Router>
  );
}
