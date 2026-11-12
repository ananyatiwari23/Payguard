import React from 'react';
import { PayGuardProvider, usePayGuard } from './context/PayGuardContext';
import { TopNav } from './components/layout/TopNav';
import { Footer } from './components/layout/Footer';
import { ToastContainer } from './components/layout/ToastContainer';
import { APP_CONTAINER_CLASS } from './constants/layout';
import { Dashboard } from './pages/Dashboard';
import { ScamDetection } from './pages/ScamDetection';
import { SpendingGuard } from './pages/SpendingGuard';
import { TrustedCircle } from './pages/TrustedCircle';
import { Transactions } from './pages/Transactions';
import { Settings } from './pages/Settings';
import { TransactionDetailModal } from './components/transactions/TransactionDetailModal';

const AppContent: React.FC = () => {
  const { activeTab, selectedTransaction, setSelectedTransaction } = usePayGuard();

  const renderActivePage = () => {
    switch (activeTab) {
      case 'overview':
        return <Dashboard />;
      case 'scam-detection':
        return <ScamDetection />;
      case 'spending-guard':
        return <SpendingGuard />;
      case 'trusted-circle':
        return <TrustedCircle />;
      case 'transactions':
        return <Transactions />;
      case 'settings':
        return <Settings />;
      default:
        return <Dashboard />;
    }
  };

  return (
    <div className="min-h-screen w-full min-w-0 bg-slate-50 dark:bg-[#060B18] text-slate-900 dark:text-slate-100 flex flex-col transition-colors duration-200">
      {/* Top Navigation Bar with integrated header navigation and theme switcher */}
      <TopNav />

      {/* Main content body */}
      <main className={`flex-1 ${APP_CONTAINER_CLASS} py-6 md:py-8 animate-in fade-in duration-200`}>
        {renderActivePage()}
      </main>

      {/* Professional Fintech Footer */}
      <Footer />

      {/* Global Transaction Detail Modal */}
      <TransactionDetailModal
        transaction={selectedTransaction}
        onClose={() => setSelectedTransaction(null)}
      />

      {/* Toast Notification Container */}
      <ToastContainer />
    </div>
  );
};

export function App() {
  return (
    <PayGuardProvider>
      <AppContent />
    </PayGuardProvider>
  );
}

export default App;
