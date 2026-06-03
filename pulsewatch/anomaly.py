"""
Anomaly detection — Z-score on per-minute error counts.

Algorithm:
  1. Build a time-series of error counts per 1-minute bucket.
  2. Compute rolling mean and std over a configurable window.
  3. Flag buckets whose count deviates more than `z_threshold` standard
     deviations from the rolling mean as anomalous.

This is intentionally simple and production-safe (no external ML deps).
For higher fidelity, swap in Prophet or a streaming EWMA from the same
interface without changing callers.
"""

import math
from dataclasses import dataclass
from datetime import datetime
from typing import Optional

from .analyzer import TimelineWindow


@dataclass
class AnomalyEvent:
    window_start: datetime
    error_count:  int
    z_score:      float
    baseline_mean: float
    baseline_std:  float

    @property
    def severity(self) -> str:
        if self.z_score >= 4.0:
            return "CRITICAL"
        if self.z_score >= 3.0:
            return "HIGH"
        return "WARNING"


class AnomalyDetector:
    def __init__(
        self,
        z_threshold: float = 2.5,
        rolling_window: int = 10,      # windows (minutes) for baseline
        min_baseline_points: int = 3,  # need at least N points before scoring
    ):
        self.z_threshold         = z_threshold
        self.rolling_window      = rolling_window
        self.min_baseline_points = min_baseline_points

    def detect(self, timeline: list[TimelineWindow]) -> list[AnomalyEvent]:
        """
        Scan a chronologically-ordered list of TimelineWindows and return
        anomalous windows.
        """
        if len(timeline) < self.min_baseline_points + 1:
            return []

        counts = [w.error_count for w in timeline]
        anomalies: list[AnomalyEvent] = []

        for i in range(self.min_baseline_points, len(counts)):
            # Use up to `rolling_window` preceding points as baseline
            baseline = counts[max(0, i - self.rolling_window): i]
            mean = sum(baseline) / len(baseline)
            variance = sum((x - mean) ** 2 for x in baseline) / len(baseline)
            std  = math.sqrt(variance)

            current = counts[i]

            # Avoid division by zero in flat baselines — treat std=0 specially
            if std < 0.5:
                # Any count > mean + 2 in a flat baseline is suspicious
                if current > mean + 2:
                    z = (current - mean) / 0.5  # normalised against a proxy
                else:
                    continue
            else:
                z = (current - mean) / std

            if z >= self.z_threshold:
                anomalies.append(AnomalyEvent(
                    window_start=timeline[i].window_start,
                    error_count=current,
                    z_score=round(z, 2),
                    baseline_mean=round(mean, 2),
                    baseline_std=round(std, 2),
                ))

        return anomalies
