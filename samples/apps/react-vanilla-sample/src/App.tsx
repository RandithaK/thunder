/*
 * Copyright (c) 2025, WSO2 LLC. (https://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

import { Route, BrowserRouter as Router, Routes, useLocation } from 'react-router-dom';
import HomePage from './pages/HomePage';
import LoginPage from './pages/LoginPage';
import RedirectLoginPage from './pages/RedirectLoginPage';
import AuthProvider from './contexts/AuthProvider';
import useAuth from './hooks/useAuth';
import config from './config';
import './App.css';

const App = () => {
  const { token } = useAuth();
  const location = useLocation(); // Get the current location
  const searchParams = new URLSearchParams(location.search);
  const hasMagicLinkParams = searchParams.has('magicLinkToken') && searchParams.has('flowId');

  const renderContent = () => {
    if (token && !hasMagicLinkParams) {
      return <HomePage />;
    } else {
      if (config.redirectBasedLogin) {
        return <RedirectLoginPage />;
      } else {
        return <LoginPage />;
      }
    }
  };

  return (
    <Routes>
      <Route path="/" element={renderContent()} key={location.key} />
      <Route path="/signin" element={renderContent()} key={`${location.key}-signin`} />
    </Routes>
  );
};

const AppWrapper = () => (
  <AuthProvider>
    <Router>
      <App />
    </Router>
  </AuthProvider>
);

export default AppWrapper;
