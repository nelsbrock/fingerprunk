#![forbid(unsafe_code)]

use std::{
    fmt::{self, Write},
    io,
    num::NonZero,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant, SystemTime},
};

use fancy_regex::Regex;
use num_integer::Integer;
use sequoia_openpgp::{
    Cert, Packet, armor,
    crypto::Password,
    packet::{
        Key, UserID,
        key::{Key4, PrimaryRole, SecretParts},
        prelude::SignatureBuilder,
    },
    serialize::Serialize,
    types::{Curve, HashAlgorithm, SignatureType, SymmetricAlgorithm},
};

type SecretKey = Key<SecretParts, PrimaryRole>;

#[allow(clippy::large_enum_variant)]
enum Message {
    Key(SecretKey),
    Stop,
}

#[derive(Clone, Debug)]
pub struct Config {
    pub regex: Regex,
    pub status_enabled: bool,
    pub count: Option<NonZero<u64>>,
    pub password: Option<Password>,
    pub userids: Vec<UserID>,
    pub workers: NonZero<usize>,
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

    pub fn run(mut self) -> anyhow::Result<()> {
        self.started_instant = Instant::now();

        let (sender, receiver) = mpsc::sync_channel(16);

        {
            let sender = sender.clone();
            ctrlc::set_handler(move || {
                let _ = sender.send(Message::Stop);
            })?;
        }

        thread::scope(|scope| {
            let status_displayer = if self.config.status_enabled {
                Some(
                    thread::Builder::new()
                        .name("status_displayer".to_string())
                        .spawn_scoped(scope, || self.status_displayer_thread())?,
                )
            } else {
                None
            };

            for num in 0..self.config.workers.get() {
                thread::Builder::new()
                    .name(format!("worker-{num:03}"))
                    .spawn_scoped(scope, || self.worker_thread(&sender))?;
            }

            let mut stdout = io::stdout().lock();

            // Receive and process messages from the workers and the ctrl-c handler
            for message in receiver {
                match message {
                    Message::Key(key) => {
                        let cert = self.key_to_cert(key)?;
                        self.serialize_cert(&cert, &mut stdout)?;

                        // Increase "found" counter and stop if enough matches have been found
                        let prev = self.counter_found.fetch_add(1, Ordering::Relaxed);
                        if self.config.count.is_some_and(|s| prev + 1 == s.get()) {
                            break;
                        }
                    }
                    Message::Stop => break,
                }
            }

            // Ask all other threads to stop
            self.stop.store(true, Ordering::Relaxed);

            // Unpark the status displayer thread, if existant
            if let Some(status_displayer) = status_displayer {
                status_displayer.thread().unpark();
            }

            Ok(())
        })
    }

    fn worker_thread(&self, sender: &mpsc::SyncSender<Message>) {
        let mut fingerprint_hex = String::with_capacity(20 * 2);

        while !self.stop.load(Ordering::Relaxed) {
            let key =
                Key4::generate_ecc(true, Curve::Ed25519).expect("should be able to generate key");
            fingerprint_hex.clear();
            write!(fingerprint_hex, "{:X}", key.fingerprint())
                .expect("should write into string without error");
            if self.check_fingerprint(&fingerprint_hex) {
                // The channel might already be closed here if we're stopping.
                // That is fine, so we just ignore the error.
                let _ = sender.send(Message::Key(Key::V4(key)));
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

    fn key_to_cert(&self, mut key: SecretKey) -> anyhow::Result<Cert> {
        let creation_time = SystemTime::now();

        let mut signer = key
            .clone()
            .into_keypair()
            .expect("key should have a secret");

        // Sign keypair
        let key_sig = create_sig_builder(SignatureType::DirectKey, creation_time)?
            .sign_direct_key(&mut signer, key.parts_as_public())?;

        // Create certificate
        let mut cert = Cert::try_from(Packet::SecretKey({
            if let Some(ref password) = self.config.password {
                let (k, mut secret) = key.take_secret();
                secret.encrypt_in_place(&k, password)?;
                key = k.add_secret(secret).0;
            }
            key
        }))?;

        let mut packets = vec![Packet::from(key_sig)];

        // Sign user IDs
        let mut next_is_primary = true;
        for user_id in self.config.userids.iter().cloned() {
            let mut sig_builder =
                create_sig_builder(SignatureType::PositiveCertification, creation_time)?;
            if next_is_primary {
                sig_builder = sig_builder.set_primary_userid(true)?;
                next_is_primary = false;
            }
            let sig = user_id.bind(&mut signer, &cert, sig_builder)?;

            packets.push(user_id.into());
            packets.push(sig.into());
        }

        cert = cert.insert_packets(packets)?.0;
        Ok(cert)
    }

    fn serialize_cert(&self, cert: &Cert, to: impl io::Write) -> anyhow::Result<()> {
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

fn create_sig_builder(
    typ: SignatureType,
    creation_time: SystemTime,
) -> Result<SignatureBuilder, anyhow::Error> {
    SignatureBuilder::new(typ)
        .set_signature_creation_time(creation_time)?
        .set_hash_algo(HashAlgorithm::SHA512)
        .set_preferred_hash_algorithms(vec![HashAlgorithm::SHA512, HashAlgorithm::SHA256])?
        .set_preferred_symmetric_algorithms(vec![
            SymmetricAlgorithm::AES256,
            SymmetricAlgorithm::AES128,
        ])
}
