//! Debouncing for fault and recovery observations. Persistence and delivery
//! must be performed by the caller in the same transaction as the observation.
use crate::Error;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct State {
    pub bad: i64,
    pub good: i64,
    pub firing: bool,
    pub since: i64,
    pub last_sample: i64,
    pub last_seen: i64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Transition {
    Fault { started: i64 },
    Recovery { started: i64 },
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Observation {
    pub state: State,
    pub transition: Option<Transition>,
    pub fresh: bool,
}

/// `sample` identifies a sensor result, while `now` is the observation time.
/// Re-reading one result never advances a threshold. A long sampling gap
/// breaks the consecutive streak but does not silently clear a firing alarm.
pub fn observe(
    mut state: State,
    failed: bool,
    sample: i64,
    now: i64,
    failure_threshold: i64,
    recovery_threshold: i64,
) -> Result<Observation, Error> {
    if !(0..=100).contains(&state.bad)
        || !(0..=100).contains(&state.good)
        || state.since < 0
        || state.last_sample < 0
        || state.last_seen < 0
        || sample < 0
        || now < 0
        || !(1..=10).contains(&failure_threshold)
        || !(1..=10).contains(&recovery_threshold)
    {
        return Err(Error::Invalid);
    }
    if sample <= state.last_sample {
        return Ok(Observation {
            state,
            transition: None,
            fresh: false,
        });
    }
    if now < state.last_seen {
        return Err(Error::Invalid);
    }
    if failed {
        state.bad = (state.bad + 1).min(100);
        state.good = 0;
    } else {
        state.good = (state.good + 1).min(100);
        state.bad = 0;
    }
    if now - state.last_seen > 180 {
        state.bad = i64::from(failed);
        state.good = i64::from(!failed);
    }
    if failed && state.bad == 1 && !state.firing {
        state.since = now;
    }
    let transition = if failed && !state.firing && state.bad >= failure_threshold {
        state.firing = true;
        Some(Transition::Fault {
            started: state.since,
        })
    } else if !failed && state.firing && state.good >= recovery_threshold {
        state.firing = false;
        let started = state.since;
        state.since = 0;
        Some(Transition::Recovery { started })
    } else {
        None
    };
    if !failed && !state.firing {
        state.since = 0;
    }
    state.last_sample = sample;
    state.last_seen = now;
    Ok(Observation {
        state,
        transition,
        fresh: true,
    })
}

/// Unknown does not prove either failure or recovery and breaks the streak.
pub fn unknown(mut state: State) -> State {
    state.bad = 0;
    state.good = 0;
    state
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn distinct_samples_open_once_and_recover_once_after_thresholds() {
        let mut state = State::default();
        for (sample, now) in [(1, 100), (2, 160)] {
            let result = observe(state, true, sample, now, 3, 2).unwrap();
            assert_eq!(result.transition, None);
            state = result.state;
        }
        let repeated = observe(state, true, 2, 170, 3, 2).unwrap();
        assert!(!repeated.fresh);
        assert_eq!(repeated.state, state);
        let fault = observe(state, true, 3, 220, 3, 2).unwrap();
        assert_eq!(fault.transition, Some(Transition::Fault { started: 100 }));
        state = fault.state;
        state = observe(state, true, 4, 280, 3, 2).unwrap().state;
        state = observe(state, false, 5, 340, 3, 2).unwrap().state;
        assert!(state.firing);
        let recovered = observe(state, false, 6, 400, 3, 2).unwrap();
        assert_eq!(
            recovered.transition,
            Some(Transition::Recovery { started: 100 })
        );
        assert!(!recovered.state.firing);
        assert_eq!(recovered.state.since, 0);
    }
    #[test]
    fn gaps_and_unknown_samples_never_silently_clear_a_firing_alarm() {
        let state = observe(State::default(), true, 1, 100, 1, 2).unwrap().state;
        assert!(state.firing);
        let first_good = observe(state, false, 2, 400, 1, 2).unwrap().state;
        assert_eq!(first_good.good, 1);
        assert!(first_good.firing);
        let uncertain = unknown(first_good);
        assert_eq!(uncertain.good, 0);
        assert!(uncertain.firing);
        let next = observe(uncertain, false, 3, 460, 1, 2).unwrap();
        assert!(next.state.firing);
        assert_eq!(next.state.good, 1);
        assert_eq!(
            observe(next.state, false, 4, 459, 1, 2),
            Err(Error::Invalid)
        );
    }
}
