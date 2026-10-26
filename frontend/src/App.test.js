import { render, screen } from '@testing-library/react';
import App from './App';

// The dashboard fetches on mount; with no backend reachable it falls back to
// the bundled sample alerts, so these assertions do not need a running API.
jest.mock('./services/api', () => {
  const actual = jest.requireActual('./services/api');
  return {
    ...actual,
    api: {
      getAlerts: jest.fn(() => Promise.reject(new Error('offline in tests'))),
      getMetrics: jest.fn(() => Promise.reject(new Error('offline in tests'))),
      getIncidents: jest.fn(() => Promise.reject(new Error('offline in tests'))),
      getQueries: jest.fn(() => Promise.reject(new Error('offline in tests'))),
      getWhitelist: jest.fn(() => Promise.reject(new Error('offline in tests'))),
    },
  };
});

test('renders the dashboard shell', async () => {
  render(<App />);
  expect(await screen.findByRole('banner')).toBeInTheDocument();
  expect(screen.getByRole('heading', { name: /dns tunneling detection/i })).toBeInTheDocument();
});

test('exposes the three primary views', async () => {
  render(<App />);
  const tabs = await screen.findAllByRole('tab');
  expect(tabs.map((tab) => tab.textContent.replace(/\d+/g, '').trim())).toEqual([
    'Alerts',
    'Incidents',
    'Whitelist',
  ]);
});
