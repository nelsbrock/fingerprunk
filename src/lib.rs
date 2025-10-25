#![forbid(unsafe_code)]

use std::{
    fmt::{self, Write},
    io,
    num::NonZeroU64,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant},
};

use fancy_regex::Regex;
use num_integer::Integer;
use sequoia_openpgp::{
    Cert, Packet, armor,
    crypto::Password,
    packet::{
        Key,
        key::{Key4, PrimaryRole, SecretParts},
        prelude::SignatureBuilder,
    },
    serialize::Serialize,
    types::{Curve, HashAlgorithm, SignatureType, SymmetricAlgorithm},
};

type SecretKey = Key<SecretParts, PrimaryRole>;

#[derive(Clone, Debug)]
pub struct Config {
    pub regex: Regex,
    pub status_enabled: bool,
    pub stop_after: Option<NonZeroU64>,
    pub password: Option<Password>,
}

#[derive(Debug)]
pub struct Fingerprunk {
    config: Config,
    started_instant: Instant,
    stop: AtomicBool,
    counter_tried: AtomicU64,
    counter_found: AtomicU64,
}

impl From<Config> for Fingerprunk {
    fn from(config: Config) -> Self {
        Fingerprunk::new_from_config(config)
    }
}

impl Fingerprunk {
    #[must_use]
    pub fn new_from_config(config: Config) -> Self {
        Self {
            config,
            started_instant: Instant::now(),
            stop: AtomicBool::new(false),
            counter_tried: AtomicU64::new(0),
            counter_found: AtomicU64::new(0),
        }
    }

    pub fn run(mut self) {
        self.started_instant = Instant::now();

        let (tx, rx) = mpsc::channel();

        thread::scope(|scope| {
            const THREAD_SPAWN_EXPECT_MSG: &str = "should be able to spawn thread";

            let ref_self = &self;

            let status_displayer = if self.config.status_enabled {
                Some(
                    thread::Builder::new()
                        .name("status_displayer".to_string())
                        .spawn_scoped(scope, move || ref_self.status_displayer_thread())
                        .expect(THREAD_SPAWN_EXPECT_MSG),
                )
            } else {
                None
            };

            for num in 0..num_cpus::get() {
                let tx = tx.clone();

                thread::Builder::new()
                    .name(format!("worker-{num:03}"))
                    .spawn_scoped(scope, move || ref_self.worker_thread(tx))
                    .expect(THREAD_SPAWN_EXPECT_MSG);
            }

            let on_stop = || {
                // Ask all other threads to stop
                self.stop.store(true, Ordering::Relaxed);

                // Unpark the status displayer thread
                if let Some(status_displayer) = status_displayer {
                    status_displayer.thread().unpark();
                }
            };

            thread::Builder::new()
                .name("finalizer".to_string())
                .spawn_scoped(scope, move || ref_self.finalizer_thread(rx, on_stop))
                .expect(THREAD_SPAWN_EXPECT_MSG);
        });
    }

    fn worker_thread(&self, matches_tx: mpsc::Sender<SecretKey>) {
        let mut fingerprint_hex = String::with_capacity(20 * 2);

        while !self.stop.load(Ordering::Relaxed) {
            let key =
                Key4::generate_ecc(true, Curve::Ed25519).expect("should be able to generate key");
            fingerprint_hex.clear();
            write!(fingerprint_hex, "{:X}", key.fingerprint())
                .expect("should write into string without error");
            if self.check_fingerprint(&fingerprint_hex) {
                matches_tx
                    .send(Key::V4(key))
                    .expect("should be able to send key");
            }
            self.counter_tried.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[inline]
    fn check_fingerprint(&self, fingerprint_hex: &str) -> bool {
        self.config
            .regex
            .is_match(fingerprint_hex)
            .expect("should check regex without error")
    }

    fn finalizer_thread(&self, matches_rx: mpsc::Receiver<SecretKey>, on_stop: impl FnOnce()) {
        let mut stdout = io::stdout().lock();

        for key in matches_rx {
            let cert = self
                .key_to_cert(&key)
                .expect("should be able to create certificate");

            self.serialize_cert(cert, &mut stdout)
                .expect("should be able to serialize certificate");

            let prev = self.counter_found.fetch_add(1, Ordering::Relaxed);

            if self.config.stop_after.is_some_and(|s| prev + 1 == s.get()) {
                break;
            }
        }

        on_stop();
    }

    fn key_to_cert(&self, key: &SecretKey) -> anyhow::Result<Cert> {
        let sig = SignatureBuilder::new(SignatureType::DirectKey)
            .set_hash_algo(HashAlgorithm::SHA512)
            .set_preferred_hash_algorithms(vec![HashAlgorithm::SHA512, HashAlgorithm::SHA256])?
            .set_preferred_symmetric_algorithms(vec![
                SymmetricAlgorithm::AES256,
                SymmetricAlgorithm::AES128,
            ])?;

        let mut signer = key
            .clone()
            .into_keypair()
            .expect("key should have a secret");
        let sig = sig.sign_direct_key(&mut signer, key.parts_as_public())?;

        let secret_key_packet = Packet::SecretKey({
            let mut key = key.clone();
            if let Some(ref password) = self.config.password {
                let (k, mut secret) = key.take_secret();
                secret.encrypt_in_place(&k, password)?;
                key = k.add_secret(secret).0;
            }
            key
        });

        Cert::try_from(vec![secret_key_packet, Packet::from(sig)])
    }

    fn serialize_cert(&self, cert: Cert, to: impl io::Write) -> anyhow::Result<()> {
        let mut comments = cert.armor_headers();
        comments.push(format!(
            "Generated with Fingerprunk. Regex: {}",
            self.config.regex
        ));

        let headers: Vec<_> = comments
            .into_iter()
            .map(|s| ("Comment".to_string(), s))
            .collect();

        let mut writer = armor::Writer::with_headers(to, armor::Kind::SecretKey, headers)?;

        // Set the profile to RFC4880 because we generate v4 keys.
        writer.set_profile(sequoia_openpgp::Profile::RFC4880)?;

        cert.serialize(&mut writer)?;
        writer.finalize()?;

        Ok(())
    }

    fn status_displayer_thread(&self) {
        const UPDATE_INTERVAL: Duration = Duration::from_millis(250);

        eprint!("\n\n\n\n\n");

        while !self.stop.load(Ordering::Relaxed) {
            self.print_status();
            // We are parking the thread instead of sleeping so we can unpark it when we want to
            // stop the program.
            thread::park_timeout(UPDATE_INTERVAL);
        }

        self.print_status();
    }

    fn print_status(&self) {
        struct DurationDhms(Duration);

        impl fmt::Display for DurationDhms {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                let seconds = self.0.as_secs();
                let (minutes, seconds) = seconds.div_rem(&60);
                let (hours, minutes) = minutes.div_rem(&60);
                let (days, hours) = hours.div_rem(&24);

                write!(f, "{days}d {hours: >2}h {minutes: >2}m {seconds: >2}s")
            }
        }

        const FORMAT_WIDTH: usize = 12;

        let duration = DurationDhms(self.started_instant.elapsed());
        let keys = self.counter_tried.load(Ordering::Relaxed);
        let keys_per_sec = keys as f64 / duration.0.as_secs_f64();
        let found = self.counter_found.load(Ordering::Relaxed);
        eprint!(
            "\x1b[F\x1b[F\x1b[F\x1b[F\x1b[F\
                Time:  {duration}\n\
                Tried: {keys: >w$} keys\n\
                Rate:  {keys_per_sec: >w$.0} keys/s\n\
                ---\n\
                Found: {found: >w$} keys\n",
            w = FORMAT_WIDTH
        );
    }
}
