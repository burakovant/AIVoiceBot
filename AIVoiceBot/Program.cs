using AIVoiceBot.Client;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using NAudio.MediaFoundation;
using NAudio.Wave;
using Org.BouncyCastle.Asn1.Ocsp;
using Serilog;
using Serilog.Extensions.Logging;
using SIPSorcery.Media;
using SIPSorcery.Net;
using SIPSorcery.SIP;
using SIPSorcery.SIP.App;
using SIPSorcery.Sys;
using SIPSorceryMedia.Abstractions;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using static Org.BouncyCastle.Math.EC.ECCurve;

namespace SIPSorcery
{
    struct SIPRegisterAccount
    {
        public string Username;
        public string Password;
        public string Domain;
        public int Expiry;

        public SIPRegisterAccount(string username, string password, string domain, int expiry)
        {
            Username = username;
            Password = password;
            Domain = domain;
            Expiry = expiry;
        }
    }

    struct SendSilenceJob
    {
        public Timer SendSilenceTimer;
        public SIPUserAgent UserAgent;

        public SendSilenceJob(Timer timer, SIPUserAgent ua)
        {
            SendSilenceTimer = timer;
            UserAgent = ua;
        }
    }

    class SIPServer
    {
        private const string PUBLIC_IP_ADDRESS_ENV_VAR = "PUBLIC_IP_ADDRESS";
        private const string RTP_PORT_ENV_VAR = "RTP_PORT";
        private const string IS_HEADLESS_ENV_VAR = "IS_HEADLESS";

        //private static string DEFAULT_CALL_DESTINATION = "sip:*61@192.168.0.48";
        private static string DEFAULT_CALL_DESTINATION = "sip:aaron@127.0.0.1:7060;transport=tcp";
        private static string DEFAULT_TRANSFER_DESTINATION = "sip:*61@192.168.0.48";
        private static int SIP_LISTEN_PORT = 5060;
        private static int SIPS_LISTEN_PORT = 5061;
        private static string SIPS_CERTIFICATE_PATH = "localhost.pfx";

        private static Microsoft.Extensions.Logging.ILogger Log = NullLogger.Instance;

        /// <summary>
        /// The set of SIP accounts available for registering and/or authenticating calls.
        /// </summary>
        private static readonly List<SIPRegisterAccount> _sipAccounts = new List<SIPRegisterAccount>
        {
            new SIPRegisterAccount( "user", "password", "sipsorcery.cloud", 120)
        };

        private static SIPTransport _sipTransport;

        /// <summary>
        /// Keeps track of the current active calls. It includes both received and placed calls.
        /// </summary>
        private static ConcurrentDictionary<string, SIPUserAgent> _calls = new ConcurrentDictionary<string, SIPUserAgent>();

        /// <summary>
        /// Keeps track of the SIP account registrations.
        /// </summary>
        private static ConcurrentDictionary<string, SIPRegistrationUserAgent> _registrations = new ConcurrentDictionary<string, SIPRegistrationUserAgent>();

        private static string _publicIPAddress = null;
        private static int _rtpPort = 0;

        /// <summary>
        /// If running on K8S or similar there is no console window to receive key presses.
        /// </summary>
        private static bool _isHeadless = false;

        private static readonly WaveFormat _waveFormat = new WaveFormat(8000, 16, 1);
        private static readonly int SegmentSeconds = 15;

        // To keep state specific to each call:
        private class CallRecordingState
        {
            public int SegmentIndex = 0;
            public int SegmentBytesWritten = 0;
            public WaveFileWriter CurrentSegmentWriter = null;
            public readonly object LockObj = new object();
            public string CallId;
        }

        private static ConcurrentDictionary<string, CallRecordingState> _callRecordings = new ConcurrentDictionary<string, CallRecordingState>();

        private class CallAIState
        {
            public MemoryStream CurrentSpeechBuffer = new MemoryStream();
            public bool IsProcessing = false;
            public DateTime LastVoiceTime = DateTime.UtcNow;
            public string CallId;
            public string FromUser;
            public string ToUser;
        }

        private static ConcurrentDictionary<string, CallAIState> _aiStates = new ConcurrentDictionary<string, CallAIState>();
        private static int SilenceThreshold;
        private static short SilencePcmLevel;
        private static int SampleRate;
        private static int BytesPerSample;
        private static int Channels;
        private static int SilenceWindowMs;
        private static int SegmentBytes;

        private static STTClient _sttClient = new STTClient("AIzaSyCFosz434vO10vU3O3W3dfl77v74_A_voY"); // Enter your API key here
        private static TTSClient _ttsClient = new TTSClient("AIzaSyCFosz434vO10vU3O3W3dfl77v74_A_voY"); // Enter your API key here
        private static int maxSimultaneousCalls;

        private static ConcurrentDictionary<string, LLMClient> _llmClients = new ConcurrentDictionary<string, LLMClient>();

        static async Task Main()
        {
            Console.WriteLine("AIVoiceBot SIP Call Server example.");

            // Load configuration
            var config = new ConfigurationBuilder()
                .SetBasePath(Directory.GetCurrentDirectory())
                .AddJsonFile("appsettings.json", optional: true)
                .AddJsonFile("appsettings.Development.json", optional: true)
                .Build();

            maxSimultaneousCalls = config.GetValue<int>("MaxSimultaneousCalls", 10);

            SilenceThreshold = config.GetValue<int>("SilenceThreshold", 500);
            SilencePcmLevel = (short)config.GetValue<int>("SilencePcmLevel", 500);
            SampleRate = config.GetValue<int>("SampleRate", 8000);
            BytesPerSample = config.GetValue<int>("BytesPerSample", 2);
            Channels = config.GetValue<int>("Channels", 1);
            SilenceWindowMs = config.GetValue<int>("SilenceWindowMs", 1500);
            SegmentBytes = SampleRate * BytesPerSample * Channels * SegmentSeconds;

            if (!_isHeadless)
            {
                Console.WriteLine("Press 'c' to place a call to the default destination.");
                Console.WriteLine("Press 'd' to send a random DTMF tone to the newest call.");
                Console.WriteLine("Press 'h' to hangup the oldest call.");
                Console.WriteLine("Press 'H' to hangup all calls.");
                Console.WriteLine("Press 'l' to list current calls.");
                Console.WriteLine("Press 'r' to list current registrations.");
                Console.WriteLine("Press 't' to transfer the newest call to the default destination.");
                Console.WriteLine("Press 'q' to quit.");
            }

            Log = AddConsoleLogger();

            // Set up a default SIP transport.
            _sipTransport = new SIPTransport();

            if (!string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable(PUBLIC_IP_ADDRESS_ENV_VAR)))
            {
                _publicIPAddress = Environment.GetEnvironmentVariable(PUBLIC_IP_ADDRESS_ENV_VAR);
                _sipTransport.ContactHost = _publicIPAddress;
            }

            if (!string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable(RTP_PORT_ENV_VAR)))
            {
                int.TryParse(Environment.GetEnvironmentVariable(RTP_PORT_ENV_VAR), out _rtpPort);
            }

            if (!string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable(IS_HEADLESS_ENV_VAR)))
            {
                bool.TryParse(Environment.GetEnvironmentVariable(IS_HEADLESS_ENV_VAR), out _isHeadless);
            }

            _sipTransport.AddSIPChannel(new SIPUDPChannel(new IPEndPoint(IPAddress.Any, SIP_LISTEN_PORT)));
            _sipTransport.AddSIPChannel(new SIPUDPChannel(new IPEndPoint(IPAddress.IPv6Any, SIP_LISTEN_PORT)));
            //_sipTransport.AddSIPChannel(new SIPTCPChannel(new IPEndPoint(IPAddress.Any, SIP_LISTEN_PORT)));
            var localhostCertificate = new X509Certificate2(SIPS_CERTIFICATE_PATH);
            //_sipTransport.AddSIPChannel(new SIPTLSChannel(localhostCertificate, new IPEndPoint(IPAddress.Any, SIPS_LISTEN_PORT)));
            // If it's desired to listen on a single IP address use the equivalent of:
            //_sipTransport.AddSIPChannel(new SIPUDPChannel(new IPEndPoint(IPAddress.Parse("192.168.11.50"), SIP_LISTEN_PORT)));
            //_sipTransport.EnableTraceLogs();

            _sipTransport.SIPTransportRequestReceived += OnRequest;

            // Uncomment to enable registrations.
            //StartRegistrations(_sipTransport, _sipAccounts);

            if (!_isHeadless)
            {
                CancellationTokenSource exitCts = new CancellationTokenSource();
                await Task.Run(() => OnKeyPress(exitCts.Token));

                Console.WriteLine("Press ctrl-c to exit.");
            }
            else
            {
                // Ctrl-c will gracefully exit the call at any point.
                ManualResetEvent exitMre = new ManualResetEvent(false);
                Console.CancelKeyPress += delegate (object sender, ConsoleCancelEventArgs e)
                {
                    e.Cancel = true;
                    exitMre.Set();
                };

                // Wait for a signal saying the call failed, was cancelled with ctrl-c or completed.
                exitMre.WaitOne();
            }

            Log.LogInformation("Exiting...");

            if (_sipTransport != null)
            {
                Log.LogInformation("Shutting down SIP transport...");
                _sipTransport.Shutdown();
            }
        }

        /// <summary>
        /// Process user key presses.
        /// </summary>
        /// <param name="exit">The cancellation token to set if the user requests to quit the application.</param>
        private static async Task OnKeyPress(CancellationToken exit)
        {
            try
            {
                while (!exit.WaitHandle.WaitOne(0))
                {
                    var keyProps = Console.ReadKey();

                    if (keyProps.KeyChar == 'c')
                    {
                        // Place an outgoing call.
                        var ua = new SIPUserAgent(_sipTransport, null);
                        ua.ClientCallTrying += (uac, resp) => Log.LogInformation($"{uac.CallDescriptor.To} Trying: {resp.StatusCode} {resp.ReasonPhrase}.");
                        ua.ClientCallRinging += (uac, resp) => Log.LogInformation($"{uac.CallDescriptor.To} Ringing: {resp.StatusCode} {resp.ReasonPhrase}.");
                        ua.ClientCallFailed += (uac, err, resp) => Log.LogWarning($"{uac.CallDescriptor.To} Failed: {err}, Status code: {resp?.StatusCode}");
                        ua.ClientCallAnswered += (uac, resp) => Log.LogInformation($"{uac.CallDescriptor.To} Answered: {resp.StatusCode} {resp.ReasonPhrase}.");
                        ua.OnDtmfTone += (key, duration) => OnDtmfTone(ua, key, duration);
                        ua.OnRtpEvent += (evt, hdr) => Log.LogDebug($"rtp event {evt.EventID}, duration {evt.Duration}, end of event {evt.EndOfEvent}, timestamp {hdr.Timestamp}, marker {hdr.MarkerBit}.");
                        ua.OnCallHungup += OnHangup;

                        var rtpSession = CreateRtpSession(ua, null, _rtpPort);
                        var callResult = await ua.Call(DEFAULT_CALL_DESTINATION, null, null, rtpSession);

                        if (callResult)
                        {
                            await rtpSession.Start();
                            _calls.TryAdd(ua.Dialogue.CallId, ua);
                        }
                    }
                    else if (keyProps.KeyChar == 'd')
                    {
                        if (_calls.Count == 0)
                        {
                            Log.LogWarning("There are no active calls.");
                        }
                        else
                        {
                            var newestCall = _calls.OrderByDescending(x => x.Value.Dialogue.Inserted).First();
                            byte randomDtmf = (byte)Crypto.GetRandomInt(0, 15);
                            Log.LogInformation($"Sending DTMF {randomDtmf} to {newestCall.Key}.");
                            await newestCall.Value.SendDtmf(randomDtmf);
                        }
                    }
                    else if (keyProps.KeyChar == 'h')
                    {
                        if (_calls.Count == 0)
                        {
                            Log.LogWarning("There are no active calls.");
                        }
                        else
                        {
                            var oldestCall = _calls.OrderBy(x => x.Value.Dialogue.Inserted).First();
                            Log.LogInformation($"Hanging up call {oldestCall.Key}.");
                            oldestCall.Value.OnCallHungup -= OnHangup;
                            oldestCall.Value.Hangup();
                            _calls.TryRemove(oldestCall.Key, out _);
                        }
                    }
                    else if (keyProps.KeyChar == 'H')
                    {
                        if (_calls.Count == 0)
                        {
                            Log.LogWarning("There are no active calls.");
                        }
                        else
                        {
                            foreach (var call in _calls)
                            {
                                Log.LogInformation($"Hanging up call {call.Key}.");
                                call.Value.OnCallHungup -= OnHangup;
                                call.Value.Hangup();
                            }
                            _calls.Clear();
                        }
                    }
                    else if (keyProps.KeyChar == 'l')
                    {
                        if (_calls.Count == 0)
                        {
                            Log.LogInformation("There are no active calls.");
                        }
                        else
                        {
                            Log.LogInformation("Current call list:");
                            foreach (var call in _calls)
                            {
                                int duration = Convert.ToInt32(DateTimeOffset.Now.Subtract(call.Value.Dialogue.Inserted).TotalSeconds);
                                uint rtpSent = (call.Value.MediaSession as VoIPMediaSession).AudioRtcpSession.PacketsSentCount;
                                uint rtpRecv = (call.Value.MediaSession as VoIPMediaSession).AudioRtcpSession.PacketsReceivedCount;
                                Log.LogInformation($"{call.Key}: {call.Value.Dialogue.RemoteTarget} {duration}s {rtpSent}/{rtpRecv}");
                            }
                        }
                    }
                    else if (keyProps.KeyChar == 'r')
                    {
                        if (_registrations.Count == 0)
                        {
                            Log.LogInformation("There are no active registrations.");
                        }
                        else
                        {
                            Log.LogInformation("Current registration list:");
                            foreach (var registration in _registrations)
                            {
                                Log.LogInformation($"{registration.Key}: is registered {registration.Value.IsRegistered}, last attempt at {registration.Value.LastRegisterAttemptAt}");
                            }
                        }
                    }
                    else if (keyProps.KeyChar == 't')
                    {
                        if (_calls.Count == 0)
                        {
                            Log.LogWarning("There are no active calls.");
                        }
                        else
                        {
                            var newestCall = _calls.OrderByDescending(x => x.Value.Dialogue.Inserted).First();
                            Log.LogInformation($"Transferring call {newestCall.Key} to {DEFAULT_TRANSFER_DESTINATION}.");
                            bool transferResult = await newestCall.Value.BlindTransfer(SIPURI.ParseSIPURI(DEFAULT_TRANSFER_DESTINATION), TimeSpan.FromSeconds(3), exit);

                            if (transferResult)
                            {
                                Log.LogInformation($"Transferring succeeded.");

                                // The remote party will often put us on hold after the transfer.
                                await Task.Delay(1000);

                                newestCall.Value.OnCallHungup -= OnHangup;
                                newestCall.Value.Hangup();
                                _calls.TryRemove(newestCall.Key, out _);
                            }
                            else
                            {
                                Log.LogWarning($"Transfer attempt failed.");
                            }
                        }
                    }
                    else if (keyProps.KeyChar == 'q')
                    {
                        // Quit application.
                        Log.LogInformation("Quitting");
                        break;
                    }
                }
            }
            catch (Exception excp)
            {
                Log.LogError($"Exception OnKeyPress. {excp.Message}.");
            }
        }

        /// <summary>
        /// Example of how to create a basic RTP session object and hook up the event handlers.
        /// </summary>
        /// <param name="ua">The user agent the RTP session is being created for.</param>
        /// <param name="dst">THe destination specified on an incoming call. Can be used to
        /// set the audio source.</param>
        /// <returns>A new RTP session object.</returns>
        private static VoIPMediaSession CreateRtpSession(SIPUserAgent ua, string dst, int bindPort)
        {
            List<AudioCodecsEnum> codecs = new List<AudioCodecsEnum> { AudioCodecsEnum.PCMU, AudioCodecsEnum.PCMA, AudioCodecsEnum.G722 };

            var audioSource = AudioSourcesEnum.None;
            /*if (string.IsNullOrEmpty(dst) || !Enum.TryParse(dst, out audioSource))
            {
                audioSource = AudioSourcesEnum.Music;
            }*/

            Log.LogInformation($"RTP audio session source set to {audioSource}.");

            AudioExtrasSource audioExtrasSource = new AudioExtrasSource(new AudioEncoder(), new AudioSourceOptions { AudioSource = audioSource });
            audioExtrasSource.RestrictFormats(formats => codecs.Contains(formats.Codec));
            var rtpAudioSession = new VoIPMediaSession(new MediaEndPoints { AudioSource = audioExtrasSource }, bindPort: bindPort);
            rtpAudioSession.AcceptRtpFromAny = true;

            // Wire up the event handler for RTP packets received from the remote party.
            rtpAudioSession.OnRtpPacketReceived += (ep, type, rtp) =>
            {
                // Get the "from user" information
                string fromUser = ua?.Dialogue?.RemoteUserField?.URI?.UnescapedUser;
                if (string.IsNullOrWhiteSpace(fromUser))
                {
                    fromUser = "unknown";
                }

                // Get the "to user" information (i.e., this application's user)
                string toUser = ua?.Dialogue?.LocalUserField?.URI?.UnescapedUser;
                if (string.IsNullOrWhiteSpace(toUser))
                {
                    toUser = "unknown";
                }

                //Log.LogDebug($"From user: {fromUser}, To user: {toUser}");

                OnRtpPacketReceived(ua, ep, type, rtp, rtpAudioSession, fromUser, toUser);
            };
            rtpAudioSession.OnTimeout += (mediaType) =>
            {
                if (ua?.Dialogue != null)
                {
                    Log.LogWarning($"RTP timeout on call with {ua.Dialogue.RemoteTarget}, hanging up.");
                }
                else
                {
                    Log.LogWarning($"RTP timeout on incomplete call, closing RTP session.");
                }

                ua.Hangup();
            };

            return rtpAudioSession;
        }

        /// <summary>
        /// Event handler for receiving RTP packets.
        /// </summary>
        /// <param name="ua">The SIP user agent associated with the RTP session.</param>
        /// <param name="type">The media type of the RTP packet (audio or video).</param>
        /// <param name="rtpPacket">The RTP packet received from the remote party.</param>
        private static void OnRtpPacketReceived(
    SIPUserAgent ua,
    IPEndPoint remoteEp,
    SDPMediaTypesEnum type,
    RTPPacket rtpPacket)
        {
            if (type != SDPMediaTypesEnum.audio || rtpPacket?.Payload == null)
            {
                return;
            }

            // Get the Call-ID, or generate one if missing
            string callId = ua?.Dialogue?.CallId;
            if (string.IsNullOrWhiteSpace(callId))
            {
                callId = Guid.NewGuid().ToString();
            }

            // Get or create the state specific to this call
            var state = _callRecordings.GetOrAdd(callId, id => new CallRecordingState { CallId = id });

            lock (state.LockObj)
            {
                if (state.CurrentSegmentWriter == null)
                {
                    string fileName = $"output_{callId}_segment_{state.SegmentIndex:D4}.wav";
                    state.CurrentSegmentWriter = new WaveFileWriter(fileName, _waveFormat);
                    state.SegmentBytesWritten = 0;
                }

                var sample = rtpPacket.Payload;
                for (int i = 0; i < sample.Length; i++)
                {
                    short pcm;
                    if (rtpPacket.Header.PayloadType == (int)SDPWellKnownMediaFormatsEnum.PCMA)
                    {
                        pcm = NAudio.Codecs.ALawDecoder.ALawToLinearSample(sample[i]);
                    }
                    else
                    {
                        pcm = NAudio.Codecs.MuLawDecoder.MuLawToLinearSample(sample[i]);
                    }

                    byte[] pcmSample = { (byte)(pcm & 0xFF), (byte)(pcm >> 8) };
                    state.CurrentSegmentWriter.Write(pcmSample, 0, 2);
                    state.SegmentBytesWritten += 2;

                    if (state.SegmentBytesWritten >= SegmentBytes)
                    {
                        string closedFileName = $"output_{callId}_segment_{state.SegmentIndex:D4}.wav";
                        state.CurrentSegmentWriter.Dispose();
                        Log.LogDebug($"Segment file closed: {closedFileName}");

                        // Send to STT API
                        _ = Task.Run(async () =>
                        {
                            try
                            {
                                //string recognizedText = await _sttClient.RecognizeAsync(closedFileName, "tr-TR"); // or "en"
                                //Log.LogInformation($"STT result for {closedFileName}: {recognizedText}");
                                // Here you can start LLM/TTS integration with recognizedText
                            }
                            catch (Exception ex)
                            {
                                Log.LogError($"STT API error for {closedFileName}: {ex.Message}");
                            }
                        });

                        state.SegmentIndex++;
                        string fileName = $"output_{callId}_segment_{state.SegmentIndex:D4}.wav";
                        state.CurrentSegmentWriter = new WaveFileWriter(fileName, _waveFormat);
                        state.SegmentBytesWritten = 0;
                    }
                }
            }
        }

        /// <summary>
        /// Event handler for receiving a DTMF tone.
        /// </summary>
        /// <param name="ua">The user agent that received the DTMF tone.</param>
        /// <param name="key">The DTMF tone.</param>
        /// <param name="duration">The duration in milliseconds of the tone.</param>
        private static void OnDtmfTone(SIPUserAgent ua, byte key, int duration)
        {
            string callID = ua.Dialogue.CallId;
            Log.LogInformation($"Call {callID} received DTMF tone {key}, duration {duration}ms.");
        }

        /// <summary>
        /// Because this is a server user agent the SIP transport must start listening for client user agents.
        /// </summary>
        private static async Task OnRequest(SIPEndPoint localSIPEndPoint, SIPEndPoint remoteEndPoint, SIPRequest sipRequest)
        {
            try
            {
                if (sipRequest.Header.From != null &&
                sipRequest.Header.From.FromTag != null &&
                sipRequest.Header.To != null &&
                sipRequest.Header.To.ToTag != null)
                {
                    // This is an in-dialog request that will be handled directly by a user agent instance.
                }
                else if (sipRequest.Method == SIPMethodsEnum.INVITE)
                {
                    Log.LogInformation($"Incoming call request: {localSIPEndPoint}<-{remoteEndPoint} {sipRequest.URI}.");

                    if (_calls.Count >= maxSimultaneousCalls) // Example limit, adjust as needed
                    {
                        Log.LogWarning("Maximum number of simultaneous calls reached, rejecting incoming call.");
                        SIPResponse busyResponse = SIPResponse.GetResponse(sipRequest, SIPResponseStatusCodesEnum.BusyHere, null);
                        await _sipTransport.SendResponseAsync(busyResponse);
                        return;
                    }

                    SIPUserAgent ua = new SIPUserAgent(_sipTransport, null);
                    ua.OnCallHungup += OnHangup;
                    ua.ServerCallCancelled += (uas, cancelReq) => Log.LogDebug("Incoming call cancelled by remote party.");
                    ua.OnDtmfTone += (key, duration) => OnDtmfTone(ua, key, duration);
                    ua.OnRtpEvent += (evt, hdr) => Log.LogDebug($"rtp event {evt.EventID}, duration {evt.Duration}, end of event {evt.EndOfEvent}, timestamp {hdr.Timestamp}, marker {hdr.MarkerBit}.");
                    //ua.OnTransactionTraceMessage += (tx, msg) => Log.LogDebug($"uas tx {tx.TransactionId}: {msg}");
                    ua.ServerCallRingTimeout += (uas) =>
                    {
                        Log.LogWarning($"Incoming call timed out in {uas.ClientTransaction.TransactionState} state waiting for client ACK, terminating.");
                        ua.Hangup();
                    };

                    //bool wasMangled = false;
                    //sipRequest.Body = SIPPacketMangler.MangleSDP(sipRequest.Body, remoteEndPoint.Address.ToString(), out wasMangled);
                    //Log.LogDebug("INVITE was mangled=" + wasMangled + " remote=" + remoteEndPoint.Address.ToString() + ".");
                    //sipRequest.Header.ContentLength = sipRequest.Body.Length;

                    var uas = ua.AcceptCall(sipRequest);
                    var rtpSession = CreateRtpSession(ua, sipRequest.URI.User, _rtpPort);

                    // Insert a brief delay to allow testing of the "Ringing" progress response.
                    // Without the delay the call gets answered before it can be sent.
                    await Task.Delay(500);

                    if (!string.IsNullOrWhiteSpace(_publicIPAddress))
                    {
                        await ua.Answer(uas, rtpSession, IPAddress.Parse(_publicIPAddress));
                    }
                    else
                    {
                        await ua.Answer(uas, rtpSession);
                    }

                    if (ua.IsCallActive)
                    {
                        await rtpSession.Start();
                        _calls.TryAdd(ua.Dialogue.CallId, ua);
                        string systemPrompt = "Sen Türkçe konuşan yardımsever bir asistansın. 3 cümleyi geçmesin cevapların."; // veya ihtiyaca göre
                        var llmClient = new LLMClient("AIzaSyCFosz434vO10vU3O3W3dfl77v74_A_voY", systemPrompt);
                        _llmClients.TryAdd(ua.Dialogue.CallId, llmClient);
                    }
                }
                else if (sipRequest.Method == SIPMethodsEnum.BYE)
                {
                    SIPResponse byeResponse = SIPResponse.GetResponse(sipRequest, SIPResponseStatusCodesEnum.CallLegTransactionDoesNotExist, null);
                    await _sipTransport.SendResponseAsync(byeResponse);
                }
                else if (sipRequest.Method == SIPMethodsEnum.SUBSCRIBE)
                {
                    SIPResponse notAllowededResponse = SIPResponse.GetResponse(sipRequest, SIPResponseStatusCodesEnum.MethodNotAllowed, null);
                    await _sipTransport.SendResponseAsync(notAllowededResponse);
                }
                else if (sipRequest.Method == SIPMethodsEnum.OPTIONS || sipRequest.Method == SIPMethodsEnum.REGISTER)
                {
                    SIPResponse optionsResponse = SIPResponse.GetResponse(sipRequest, SIPResponseStatusCodesEnum.Ok, null);
                    await _sipTransport.SendResponseAsync(optionsResponse);
                }
            }
            catch (Exception reqExcp)
            {
                Log.LogWarning($"Exception handling {sipRequest.Method}. {reqExcp.Message}");
            }
        }

        /// <summary>
        /// Remove call from the active calls list.
        /// </summary>
        /// <param name="dialogue">The dialogue that was hungup.</param>
        private static void OnHangup(SIPDialogue dialogue)
        {
            if (dialogue != null)
            {
                string callId = dialogue.CallId;
                if (_calls.ContainsKey(callId))
                {
                    _llmClients.TryRemove(callId, out _);
                    Log.LogInformation($"Call {callId} with {dialogue.RemoteTarget} hungup, removing its llmClient.");
                    if (_calls.TryRemove(callId, out var ua))
                    {
                        // This app only uses each SIP user agent once so here the agent is 
                        // explicitly closed to prevent is responding to any new SIP requests.
                        ua.Close();
                    }
                }

                if (_callRecordings.TryRemove(callId, out var state))
                {
                    lock (state.LockObj)
                    {
                        state.CurrentSegmentWriter?.Dispose();
                        state.CurrentSegmentWriter = null;
                    }
                }
            }
        }

        /// <summary>
        /// Starts a registration agent for each of the supplied SIP accounts.
        /// </summary>
        /// <param name="sipTransport">The SIP transport to use for the registrations.</param>
        /// <param name="sipAccounts">The list of SIP accounts to create a registration for.</param>
        private static void StartRegistrations(SIPTransport sipTransport, List<SIPRegisterAccount> sipAccounts)
        {
            foreach (var sipAccount in sipAccounts)
            {
                var regUserAgent = new SIPRegistrationUserAgent(sipTransport, sipAccount.Username, sipAccount.Password, sipAccount.Domain, sipAccount.Expiry);

                // Event handlers for the different stages of the registration.
                regUserAgent.RegistrationFailed += (uri, resp, err) => Log.LogError($"{uri.ToString()}: {err}");
                regUserAgent.RegistrationTemporaryFailure += (uri, resp, msg) => Log.LogWarning($"{uri.ToString()}: {msg}");
                regUserAgent.RegistrationRemoved += (uri, resp) => Log.LogError($"{uri.ToString()} registration failed.");
                regUserAgent.RegistrationSuccessful += (uri, resp) => Log.LogInformation($"{uri.ToString()} registration succeeded.");

                // Start the thread to perform the initial registration and then periodically resend it.
                regUserAgent.Start();

                _registrations.TryAdd($"{sipAccount.Username}@{sipAccount.Domain}", regUserAgent);
            }
        }

        /// <summary>
        /// Adds a console logger. Can be omitted if internal SIPSorcery debug and warning messages are not required.
        /// </summary>
        private static Microsoft.Extensions.Logging.ILogger AddConsoleLogger()
        {
            var serilogLogger = new LoggerConfiguration()
                .Enrich.FromLogContext()
                .MinimumLevel.Is(Serilog.Events.LogEventLevel.Verbose)
                .WriteTo.Console()
                .CreateLogger();
            var factory = new SerilogLoggerFactory(serilogLogger);
            SIPSorcery.LogFactory.Set(factory);
            return factory.CreateLogger<SIPServer>();
        }

        /// <summary>
        /// STT integration (example, modify according to your own API)
        /// </summary>
        private static async Task<string> SendToSTTAsync(byte[] pcmData, int sampleRate)
        {
            // Here, send pcmData to an STT service via HTTP POST and get the text
            string recognizedText = await _sttClient.RecognizeAsync(pcmData, sampleRate, "tr-TR"); // or "en"
            //string recognizedText = "ses ses deneme";
            Log.LogDebug($"STT result: {recognizedText}");
            return recognizedText;
        }

        /// <summary>
        /// LLM integration (example, modify according to your own API)
        /// </summary>
        private static async Task<string> SendToLLMAsync(string userInput, string callId)
        {
            string response = "Üzgünüm. Şu anda yardımcı olamıyorum.";
            if (_llmClients.TryGetValue(callId, out var llmClient))
            {
                response = await llmClient.GetChatCompletionAsync(userInput);
            }
            Log.LogDebug($"LLM result: {response}");
            return response;
        }

        /// <summary>
        /// TTS integration (example, modify according to your own API)
        /// </summary>
        private static async Task<byte[]> SendToTTSAsync(string text, int sampleRate)
        {
            Log.LogDebug($"LLM response will be sent to TTS: {text}");
            return await _ttsClient.SynthesizeSpeechAsync(text, "tr-TR");
            // return new byte[0];
        }

        /// <summary>
        /// Sending TTS audio to the client via RTP (example)
        /// </summary>
        private static async Task SendAudioToClientAsync(SIPUserAgent ua, byte[] ttsAudio, VoIPMediaSession voipMediaSession)
        {
            // ALAW -> PCM çevirip MemoryStream ile gönderme örneği
            byte[] pcmData = new byte[ttsAudio.Length * 2];
            for (int i = 0; i < ttsAudio.Length; i++)
            {
                short pcm = NAudio.Codecs.ALawDecoder.ALawToLinearSample(ttsAudio[i]);
                pcmData[2 * i] = (byte)(pcm & 0xFF);
                pcmData[2 * i + 1] = (byte)(pcm >> 8);
            }
            using var ms = new MemoryStream(pcmData);
            await voipMediaSession.AudioExtrasSource.SendAudioFromStream(ms, AudioSamplingRatesEnum.Rate8KHz);
            //await voipMediaSession.AudioExtrasSource.SendAudioFromStream(new MemoryStream(ttsAudio), AudioSamplingRatesEnum.Rate8KHz);
            //await voipMediaSession.AudioExtrasSource.SendAudioFromStream(new FileStream("test_output.wav", FileMode.Open), AudioSamplingRatesEnum.Rate8KHz);
        }

        /// <summary>
        /// Function that processes the RTP packet:
        /// </summary>
        private static async void OnRtpPacketReceived(
            SIPUserAgent ua,
            IPEndPoint remoteEp,
            SDPMediaTypesEnum type,
            RTPPacket rtpPacket,
            VoIPMediaSession voIPMediaSession,
            string fromUser,
            string toUser)
        {
            if (type != SDPMediaTypesEnum.audio || rtpPacket?.Payload == null)
                return;

            string callId = ua?.Dialogue?.CallId ?? Guid.NewGuid().ToString();
            var state = _aiStates.GetOrAdd(callId, _ => new CallAIState { CallId = callId, FromUser = fromUser, ToUser = toUser });

            lock (state)
            {
                // Add PCM data to the buffer
                for (int i = 0; i < rtpPacket.Payload.Length; i++)
                {
                    short pcm;
                    if (rtpPacket.Header.PayloadType == (int)SDPWellKnownMediaFormatsEnum.PCMA)
                        pcm = NAudio.Codecs.ALawDecoder.ALawToLinearSample(rtpPacket.Payload[i]);
                    else
                        pcm = NAudio.Codecs.MuLawDecoder.MuLawToLinearSample(rtpPacket.Payload[i]);

                    byte[] pcmSample = { (byte)(pcm & 0xFF), (byte)(pcm >> 8) };
                    state.CurrentSpeechBuffer.Write(pcmSample, 0, 2);

                    // Check if it is voice or silence
                    if (Math.Abs(pcm) > SilencePcmLevel)
                        state.LastVoiceTime = DateTime.UtcNow;
                }
            }

            // If silence is detected (e.g., no sound for 1 second)
            if (!state.IsProcessing && (DateTime.UtcNow - state.LastVoiceTime).TotalMilliseconds > SilenceWindowMs)
            {
                state.IsProcessing = true;
                byte[] speechData;
                lock (state)
                {
                    using (var wavStream = new MemoryStream())
                    {
                        using (var writer = new WaveFileWriter(wavStream, new WaveFormat(8000, 16, 1)))
                        {
                            writer.Write(state.CurrentSpeechBuffer.ToArray(), 0, (int)state.CurrentSpeechBuffer.Length);
                        }
                        speechData = wavStream.ToArray();
                    }
                    state.CurrentSpeechBuffer.SetLength(0); // reset the buffer
                }

                try
                {
                    // speechData boşsa işleme girme
                    if (speechData.Length > 44) // WAV header'ı 44 bayt, sadece header ise ses yoktur
                    {
                        Log.LogInformation($"Processing speech data for call {callId} from {fromUser} to {toUser}.");
                        // 1. Send to STT
                        string recognizedText = await SendToSTTAsync(speechData, SampleRate);

                        // 2. Send to LLM
                        string botReply = await SendToLLMAsync(recognizedText, callId);

                        // 3. Send to TTS
                        byte[] ttsAudio = await SendToTTSAsync(botReply, SampleRate);

                        // 4. Send TTS audio to the client via RTP
                        await SendAudioToClientAsync(ua, ttsAudio, voIPMediaSession);
                    }
                    else
                    {
                        Log.LogInformation($"No valid speech data to process for call {callId} from {fromUser} to {toUser}.");
                    }
                }
                catch (Exception ex)
                {
                    Log.LogError($"Error processing speech data: {ex.Message}", ex);
                    await voIPMediaSession.AudioExtrasSource.SendAudioFromStream(new FileStream("Sounds/Turkish_error_message.wav", FileMode.Open), AudioSamplingRatesEnum.Rate8KHz);
                }

                // 5. Reset the state
                state.IsProcessing = false;
                lock (state)
                {
                    state.CurrentSpeechBuffer.SetLength(0);
                    state.LastVoiceTime = DateTime.UtcNow;
                }
            }
        }
    }
}