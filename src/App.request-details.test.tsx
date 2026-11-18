import { act, fireEvent, render, screen, within } from '@testing-library/react';
import { beforeEach, expect, it, vi } from 'vitest';
import App from './App';
import type { Exchange } from './types';

const mocks = vi.hoisted(() => ({
  bootstrap: vi.fn(),
  list_sessions: vi.fn(),
  device_status: vi.fn(),
  proxy_status: vi.fn(),
  pending: vi.fn(),
  list_exchange_page: vi.fn(),
  get_exchange: vi.fn(),
}));
vi.mock('./api', () => ({ isNative: () => true, api: mocks }));

const session = {
  id: 'session',
  name: 'Local capture',
  source: 'desktop',
  createdAt: 0,
  exchangeCount: 2,
};
const request: Exchange = {
  id: 'first',
  sessionId: session.id,
  method: 'POST',
  url: 'http://127.0.0.1:8080/first',
  status: 200,
  requestHeaders: [{ name: 'Content-Type', value: 'text/plain' }],
  responseHeaders: [],
  requestBody: '',
  responseBody: '',
  requestBodyBase64: false,
  responseBodyBase64: false,
  startedAt: 0,
  durationMs: 1,
  requestBytes: 9,
  responseBytes: 0,
  error: null,
  edited: false,
  completed: true,
};
const other = { ...request, id: 'second', url: 'http://127.0.0.1:8080/second' };
const curlButton = () => screen.getByRole('button', { name: 'Copy as cURL' });
const replayButton = () => screen.getByRole('button', { name: 'Compose replay' });
const row = (exchange: Exchange) => screen.findByRole('row', { name: `POST ${exchange.url}` });
function openReplayBody() {
  fireEvent.click(replayButton());
  const replay = within(screen.getByRole('dialog', { name: 'Replay composer' }));
  fireEvent.click(replay.getByRole('button', { name: 'Body' }));
  return replay.getByLabelText('Request body');
}

beforeEach(() => {
  vi.resetAllMocks();
  const proxy = { running: false, port: 0, sessionId: null };
  const device = { running: false };
  mocks.bootstrap.mockResolvedValue({ sessions: [session], proxy, deviceStatus: device });
  mocks.list_sessions.mockResolvedValue([session]);
  mocks.device_status.mockResolvedValue(device);
  mocks.proxy_status.mockResolvedValue(proxy);
  mocks.pending.mockResolvedValue([]);
  mocks.list_exchange_page.mockResolvedValue({ rows: [request, other], nextCursor: null });
});

it('waits for the captured request body before enabling cURL and replay', async () => {
  let finish!: (value: Exchange) => void;
  mocks.get_exchange.mockImplementation(
    () =>
      new Promise<Exchange>((resolve) => {
        finish = resolve;
      }),
  );
  render(<App />);
  fireEvent.click(await row(request));

  expect(screen.getByText('Loading request details…')).toBeVisible();
  expect(curlButton()).toBeDisabled();
  expect(replayButton()).toBeDisabled();

  await act(async () => finish({ ...request, requestBody: 'full data' }));
  expect(curlButton()).toBeEnabled();
  expect(replayButton()).toBeEnabled();
  fireEvent.click(curlButton());
  const command = screen.getByLabelText<HTMLTextAreaElement>('cURL command (POSIX shell)').value;
  expect(command).toContain("printf '%s' 'full data'");
  expect(command).toContain('--data-binary @-');
  fireEvent.keyDown(document, { key: 'Escape' });
  expect(openReplayBody()).toHaveValue('full data');
});

it('keeps another request disabled on failure and only unlocks actions after a successful retry', async () => {
  let finishFirst!: (value: Exchange) => void;
  mocks.get_exchange
    .mockImplementationOnce(
      () =>
        new Promise<Exchange>((resolve) => {
          finishFirst = resolve;
        }),
    )
    .mockRejectedValueOnce(new Error('Archive read failed'))
    .mockResolvedValueOnce({ ...other, requestBody: 'other data' });
  render(<App />);
  fireEvent.click(await row(request));
  fireEvent.click(await row(other));

  expect(await screen.findByRole('alert')).toHaveTextContent('Archive read failed');
  await act(async () => finishFirst({ ...request, requestBody: 'stale data' }));
  expect(curlButton()).toBeDisabled();
  expect(replayButton()).toBeDisabled();

  await act(async () =>
    fireEvent.click(screen.getByRole('button', { name: 'Retry loading details' })),
  );
  expect(openReplayBody()).toHaveValue('other data');
});
