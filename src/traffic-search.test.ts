import { act, renderHook } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { api } from './api';
import { useTrafficPages } from './traffic-search';
import type { ExchangePage, TrafficFilter } from './types';

vi.mock('./api', () => ({ api: { list_exchange_page: vi.fn() } }));

const fetchPage = vi.mocked(api.list_exchange_page);
const props = {
  native: true,
  sessionId: 'session',
  query: '',
  filter: 'all' as TrafficFilter,
  snapshot: '1',
};

function page(start: number, size: number, nextCursor: string | null): ExchangePage {
  return {
    rows: Array.from({ length: size }, (_, offset) => ({
      id: String(start + offset),
      sessionId: props.sessionId,
      method: 'GET',
      url: 'https://example.test/',
      status: 200,
      requestHeaders: [],
      responseHeaders: [],
      requestBody: '',
      responseBody: '',
      requestBodyBase64: false,
      responseBodyBase64: false,
      startedAt: 0,
      durationMs: 0,
      requestBytes: 0,
      responseBytes: 0,
      error: null,
      edited: false,
      completed: true,
    })),
    nextCursor,
  };
}

async function settle(delay = 0) {
  await act(async () => {
    await vi.advanceTimersByTimeAsync(delay);
  });
}

beforeEach(() => {
  vi.useFakeTimers();
  fetchPage.mockReset();
});
afterEach(() => vi.useRealTimers());

describe('Traffic pagination', () => {
  it('loads more than 1,000 matching records in distinct cursor pages and stops at the end', async () => {
    for (let n = 0; n < 5; n += 1) {
      fetchPage.mockResolvedValueOnce(page(n * 250, 250, n < 4 ? String(n * 250 + 249) : null));
    }
    const { result } = renderHook(() => useTrafficPages(props));
    await settle();
    expect(result.current.rows).toHaveLength(250);

    for (let n = 1; n < 5; n += 1) {
      act(() => result.current.loadMore());
      await settle();
      expect(fetchPage).toHaveBeenLastCalledWith('session', '', 'all', 250, String(n * 250 - 1));
    }
    expect(result.current.rows.map(({ id }) => id)).toEqual(
      Array.from({ length: 1250 }, (_, n) => String(n)),
    );
    expect(result.current.hasMore).toBe(false);
    act(() => result.current.loadMore());
    await settle();
    expect(fetchPage).toHaveBeenCalledTimes(5);
  });

  it('passes text and status together and clears stale results during a new query', async () => {
    fetchPage.mockResolvedValueOnce(page(0, 2, '1'));
    const { result, rerender } = renderHook(useTrafficPages, { initialProps: props });
    await settle();

    const filterProps = { ...props, filter: 'errors' as const, query: 'filter:status>=' };
    fetchPage.mockRejectedValueOnce('Invalid search expression');
    rerender(filterProps);
    expect(result.current.rows).toHaveLength(0);
    expect(result.current.loading).toBe(true);
    await settle(220);
    expect(result.current.error).toBe('Invalid search expression');
    expect(fetchPage).toHaveBeenLastCalledWith('session', 'filter:status>=', 'errors', 250, null);

    fetchPage.mockResolvedValueOnce(page(250, 1, null));
    rerender({ ...filterProps, query: 'filter:status>=400' });
    await settle(220);
    expect(fetchPage).toHaveBeenLastCalledWith(
      'session',
      'filter:status>=400',
      'errors',
      250,
      null,
    );
    expect(result.current.rows.map(({ id }) => id)).toEqual(['250']);
    expect(result.current.error).toBe('');
  });

  it('keeps the current page and retries its cursor after a load-more failure', async () => {
    fetchPage.mockResolvedValueOnce(page(0, 2, '1'));
    const { result } = renderHook(() => useTrafficPages(props));
    await settle();

    fetchPage.mockRejectedValueOnce(new Error('Archive temporarily unavailable'));
    act(() => result.current.loadMore());
    await settle();
    expect(result.current.rows.map(({ id }) => id)).toEqual(['0', '1']);
    expect(result.current.error).toBe('Archive temporarily unavailable');
    expect(result.current.hasMore).toBe(true);

    fetchPage.mockResolvedValueOnce(page(2, 1, null));
    act(() => result.current.loadMore());
    await settle();
    expect(fetchPage).toHaveBeenLastCalledWith('session', '', 'all', 250, '1');
    expect(result.current.rows.map(({ id }) => id)).toEqual(['0', '1', '2']);
    expect(result.current.error).toBe('');
  });

  it('rebuilds loaded pages with new cursor boundaries after an archive revision', async () => {
    fetchPage.mockResolvedValueOnce(page(1, 2, '2')).mockResolvedValueOnce(page(3, 2, null));
    const { result, rerender } = renderHook(useTrafficPages, { initialProps: props });
    await settle();
    act(() => result.current.loadMore());
    await settle();

    fetchPage.mockResolvedValueOnce(page(0, 2, '1')).mockResolvedValueOnce(page(2, 2, '3'));
    rerender({ ...props, snapshot: '2' });
    await settle();
    expect(fetchPage).toHaveBeenNthCalledWith(3, 'session', '', 'all', 250, null);
    expect(fetchPage).toHaveBeenNthCalledWith(4, 'session', '', 'all', 250, '1');
    expect(result.current.rows.map(({ id }) => id)).toEqual(['0', '1', '2', '3']);
    expect(result.current.hasMore).toBe(true);
  });

  it('ignores a page resolving after the selected session changes', async () => {
    fetchPage.mockResolvedValueOnce(page(0, 2, '1'));
    const { result, rerender } = renderHook(useTrafficPages, { initialProps: props });
    await settle();

    let finish!: (value: ExchangePage) => void;
    fetchPage.mockImplementationOnce(
      () =>
        new Promise((resolve) => {
          finish = resolve;
        }),
    );
    act(() => result.current.loadMore());
    await settle();

    fetchPage.mockResolvedValueOnce(page(300, 1, null));
    rerender({ ...props, sessionId: 'other-session' });
    await settle();
    await act(async () => finish(page(2, 2, null)));
    expect(fetchPage).toHaveBeenLastCalledWith('other-session', '', 'all', 250, null);
    expect(result.current.rows.map(({ id }) => id)).toEqual(['300']);
  });
});
