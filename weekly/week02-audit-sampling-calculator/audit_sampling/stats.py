"""Sampling statistics for tests of controls (attribute sampling).

Everything here is exact, standard-library math: binomial and hypergeometric
probabilities computed in log space with ``math.lgamma`` so large populations
do not overflow.

Design rule (the one behind the AICPA attribute-sampling tables):

    Choose the smallest n such that, if the true deviation rate were the
    tolerable rate, the chance of seeing no more than the expected number of
    deviations k = ceil(n * expected_rate) is at most (1 - confidence).

At 95% confidence, 5% tolerable rate and 0% expected rate that gives the
familiar n = 59.
"""
from __future__ import annotations

import math
from dataclasses import dataclass

# --------------------------------------------------------------------------- #
# Probability helpers
# --------------------------------------------------------------------------- #

def _log_comb(n: int, k: int) -> float:
    """log(C(n, k)); -inf when k is out of range."""
    if k < 0 or k > n:
        return float("-inf")
    return math.lgamma(n + 1) - math.lgamma(k + 1) - math.lgamma(n - k + 1)


def binom_cdf(k: int, n: int, p: float) -> float:
    """P(X <= k) for X ~ Binomial(n, p)."""
    if k < 0:
        return 0.0
    if k >= n or p <= 0.0:
        return 1.0
    if p >= 1.0:
        return 0.0
    lp, lq = math.log(p), math.log1p(-p)
    total = sum(math.exp(_log_comb(n, i) + i * lp + (n - i) * lq) for i in range(k + 1))
    return min(1.0, total)


def hypergeom_cdf(k: int, population: int, defects: int, n: int) -> float:
    """P(X <= k) when drawing n items without replacement from a population
    of ``population`` items that contains ``defects`` deviations."""
    if k < 0:
        return 0.0
    lo = max(0, n - (population - defects))
    hi = min(n, defects)
    if k >= hi:
        return 1.0
    if k < lo:
        return 0.0
    log_total = _log_comb(population, n)
    total = sum(math.exp(_log_comb(defects, i) + _log_comb(population - defects, n - i) - log_total)
                for i in range(lo, k + 1))
    return min(1.0, total)


# --------------------------------------------------------------------------- #
# Attribute sample size
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class SampleSize:
    """Result of a sample-size calculation."""
    n: int
    allowed_deviations: int          # max deviations that still support reliance
    method: str                      # "attribute-binomial", "attribute-hypergeometric", "frequency"
    confidence: float | None = None
    tolerable_rate: float | None = None
    expected_rate: float | None = None
    population: int | None = None
    test_all: bool = False           # True when the whole population must be tested
    basis: str = ""                  # human-readable explanation

    def to_dict(self) -> dict:
        return {k: v for k, v in self.__dict__.items()}


def _validate_rates(confidence: float, tolerable: float, expected: float) -> None:
    if not 0.5 <= confidence < 1.0:
        raise ValueError("confidence must be between 0.50 and 0.999 (e.g. 0.95)")
    if not 0.0 < tolerable < 1.0:
        raise ValueError("tolerable rate must be between 0 and 1 (e.g. 0.05)")
    if not 0.0 <= expected < tolerable:
        raise ValueError("expected rate must be >= 0 and below the tolerable rate; "
                         "if you expect that many deviations, do not plan to rely on the control")


def tolerable_defects(population: int, tolerable: float) -> int:
    """Number of deviations in the population that equals the tolerable rate
    (rounded down, minimum 1 - the conservative choice)."""
    return max(1, math.floor(tolerable * population))


def attribute_sample_size(confidence: float, tolerable: float, expected: float = 0.0,
                          population: int | None = None, max_n: int = 5000) -> SampleSize:
    """Smallest attribute sample that supports reliance on a control.

    If ``population`` is given the exact hypergeometric model is used (sampling
    without replacement), which gives slightly smaller samples for small
    populations. Otherwise the binomial (large-population) model is used.
    """
    _validate_rates(confidence, tolerable, expected)
    alpha = 1.0 - confidence
    if population is not None and population < 1:
        raise ValueError("population must be at least 1")
    limit = min(max_n, population) if population else max_n
    d_tol = tolerable_defects(population, tolerable) if population else None

    for n in range(1, limit + 1):
        k = math.ceil(n * expected - 1e-9)
        if population:
            risk = hypergeom_cdf(k, population, d_tol, n)
        else:
            risk = binom_cdf(k, n, tolerable)
        if risk <= alpha:
            method = "attribute-hypergeometric" if population else "attribute-binomial"
            return SampleSize(
                n=n, allowed_deviations=k, method=method, confidence=confidence,
                tolerable_rate=tolerable, expected_rate=expected, population=population,
                test_all=bool(population and n >= population),
                basis=(f"{confidence:.0%} confidence that the deviation rate is below "
                       f"{tolerable:.1%} if no more than {k} deviation(s) are found"),
            )
    if population and limit == population:
        return SampleSize(n=population, allowed_deviations=0, method="attribute-hypergeometric",
                          confidence=confidence, tolerable_rate=tolerable,
                          expected_rate=expected, population=population, test_all=True,
                          basis="population too small for sampling to give the required "
                                "assurance; test every item")
    raise ValueError(f"no sample size up to {max_n} meets these parameters; "
                     "widen the tolerable rate or lower confidence")


# --------------------------------------------------------------------------- #
# Frequency-based (non-statistical) sample sizes
# --------------------------------------------------------------------------- #

# Widely used practitioner convention for manual controls (it appears, with
# small variations, in many audit firms' methodologies and in IIA/ISACA
# training). It is NOT prescribed by any standard - document your own basis.
FREQUENCY_GUIDE: dict[str, tuple[int, int, int]] = {
    #  frequency         (lower-risk, higher-risk, typical annual population)
    "annual":            (1, 1, 1),
    "semi-annual":       (1, 2, 2),
    "quarterly":         (2, 2, 4),
    "monthly":           (2, 5, 12),
    "weekly":            (5, 15, 52),
    "daily":             (20, 40, 250),
    "multiple-daily":    (25, 60, 1000),
}
RISK_LEVELS = ("lower", "moderate", "higher")


def frequency_sample_size(frequency: str, risk: str = "moderate",
                          population: int | None = None) -> SampleSize:
    """Judgmental sample size from control frequency and risk of failure."""
    freq = frequency.strip().lower().replace("_", "-")
    if freq not in FREQUENCY_GUIDE:
        raise ValueError(f"unknown frequency '{frequency}'; choose from {', '.join(FREQUENCY_GUIDE)}")
    risk = risk.strip().lower()
    if risk not in RISK_LEVELS:
        raise ValueError(f"risk must be one of {', '.join(RISK_LEVELS)}")
    low, high, typical = FREQUENCY_GUIDE[freq]
    n = {"lower": low, "higher": high, "moderate": math.ceil((low + high) / 2)}[risk]
    pop = population if population is not None else typical
    test_all = n >= pop
    return SampleSize(
        n=min(n, pop), allowed_deviations=0, method="frequency", population=pop,
        test_all=test_all,
        basis=(f"{freq} control, {risk} risk: practitioner guide "
               + (f"range {low}-{high}" if low != high else f"value {low}")
               + ("; population no larger than sample, test all items" if test_all else "")),
    )


# --------------------------------------------------------------------------- #
# Evaluation
# --------------------------------------------------------------------------- #

def upper_deviation_limit(deviations: int, n: int, confidence: float,
                          population: int | None = None) -> float:
    """Achieved upper deviation limit: the deviation rate we can rule out at the
    given confidence after finding ``deviations`` in a sample of ``n``.

    Binomial: one-sided Clopper-Pearson bound (solved by bisection).
    Hypergeometric: smallest defect count D whose probability of producing
    this few deviations is <= alpha, expressed as D / population.
    """
    if n <= 0:
        return 1.0
    if deviations >= n:
        return 1.0
    alpha = 1.0 - confidence
    if population:
        for d in range(deviations + 1, population + 1):
            if hypergeom_cdf(deviations, population, d, n) <= alpha:
                return d / population
        return 1.0
    lo, hi = deviations / n, 1.0
    for _ in range(100):
        mid = (lo + hi) / 2
        if binom_cdf(deviations, n, mid) > alpha:
            lo = mid
        else:
            hi = mid
    return hi


def supports_reliance(deviations: int, n: int, confidence: float, tolerable: float,
                      population: int | None = None) -> bool:
    """True when the tolerable rate can be rejected at the given confidence."""
    alpha = 1.0 - confidence
    if population:
        return hypergeom_cdf(deviations, population,
                             tolerable_defects(population, tolerable), n) <= alpha
    return binom_cdf(deviations, n, tolerable) <= alpha
