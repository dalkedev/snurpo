import { useEffect, useRef, useState } from 'react';
import { api } from './api';
import type { Exchange, ExchangePage, TrafficFilter } from './types';

const PAGE_SIZE = 250;
const emptyRows: Exchange[] = [];

interface TrafficResults extends ExchangePage {
  scope: string;
  snapshot: string;
  pages: number;
  error: string;
}

export function useTrafficPages({
  native,
  sessionId,
  query,
  filter,
  snapshot,
}: {
  native: boolean;
  sessionId: string;
  query: string;
  filter: TrafficFilter;
  snapshot: string;
}) {
  const scope = JSON.stringify([sessionId, query, filter]);
  const [target, setTarget] = useState({ scope, pages: 1, attempt: 0 });
  const pages = target.scope === scope ? target.pages : 1;
  const [result, setResult] = useState<TrafficResults | null>(null);
  const resultRef = useRef<TrafficResults | null>(null);
  const [loading, setLoading] = useState(false);
  const enabled = native && !!sessionId;

  useEffect(() => {
    if (!enabled) return;
    setLoading(true);
    setTarget((previous) =>
      previous.scope === scope ? previous : { ...previous, scope, pages: 1 },
    );

    let active = true;
    const previous = resultRef.current;
    const canAppend =
      previous?.scope === scope &&
      previous.snapshot === snapshot &&
      previous.nextCursor !== null &&
      previous.pages < pages;
    const timer = window.setTimeout(
      async () => {
        // On archive changes, rebuild the visible window with fresh cursor boundaries.
        // A load-more click within the same revision only fetches the next page.
        const current: TrafficResults = canAppend
          ? { ...previous, rows: [...previous.rows], error: '' }
          : { rows: [], nextCursor: null, scope, snapshot, pages: 0, error: '' };
        try {
          do {
            const page = await api.list_exchange_page(
              sessionId,
              query,
              filter,
              PAGE_SIZE,
              current.nextCursor,
            );
            if (!active) return;
            current.rows.push(...page.rows);
            current.nextCursor = page.nextCursor;
            current.pages += 1;
          } while (current.nextCursor !== null && current.pages < pages);
        } catch (error) {
          current.error = error instanceof Error ? error.message : String(error);
        }
        if (!active) return;
        resultRef.current = current;
        setResult(current);
        setLoading(false);
      },
      query && !canAppend ? 220 : 0,
    );
    return () => {
      active = false;
      window.clearTimeout(timer);
    };
  }, [enabled, sessionId, query, filter, scope, snapshot, pages, target.attempt]);

  const visible = result?.scope === scope ? result : null;
  return {
    rows: visible?.rows ?? emptyRows,
    error: visible?.error ?? '',
    loading: enabled && (loading || !visible),
    hasMore: visible?.nextCursor != null,
    loadMore: () => {
      if (loading || !visible?.nextCursor) return;
      setTarget((previous) => ({ scope, pages: visible.pages + 1, attempt: previous.attempt + 1 }));
    },
  };
}
