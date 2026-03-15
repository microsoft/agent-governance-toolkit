// Copyright (c) Microsoft Corporation. Licensed under the MIT License.

using System.Collections.Concurrent;
using System.Text.Json;

namespace AgentGovernance.Trust;

/// <summary>
/// A file-backed trust store that persists agent trust scores to a JSON file.
/// Thread-safe for concurrent reads and writes with periodic flush to disk.
/// </summary>
public sealed class FileTrustStore : IDisposable
{
    private readonly string _filePath;
    private readonly ConcurrentDictionary<string, TrustRecord> _scores = new();
    private readonly object _ioLock = new();
    private readonly double _defaultScore;
    private readonly double _decayRate;
    private readonly Action<Exception, string>? _loadErrorHandler;
    private bool _disposed;

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
    };

    /// <summary>
    /// Initializes a new <see cref="FileTrustStore"/>.
    /// Loads existing trust data from the file if it exists.
    /// </summary>
    /// <param name="filePath">Path to the JSON trust store file.</param>
    /// <param name="defaultScore">Default trust score for new agents (0–1000). Defaults to 500.</param>
    /// <param name="decayRate">
    /// Trust decay rate per hour of inactivity (0–1000). Defaults to 10.
    /// Agents that have not had positive signals lose trust over time.
    /// </param>
    /// <param name="loadErrorHandler">
    /// Optional callback invoked when the trust store file is corrupted.
    /// Receives the exception and file path. When null, corruption is handled silently.
    /// </param>
    public FileTrustStore(string filePath, double defaultScore = 500.0, double decayRate = 10.0, Action<Exception, string>? loadErrorHandler = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(filePath);
        _filePath = filePath;
        _defaultScore = Math.Clamp(defaultScore, 0, 1000);
        _decayRate = Math.Max(0, decayRate);
        _loadErrorHandler = loadErrorHandler;

        Load();
    }

    /// <summary>
    /// Gets the current trust score for an agent, applying time-based decay.
    /// Returns the default score if the agent is not tracked.
    /// </summary>
    /// <param name="agentDid">The agent's decentralised identifier.</param>
    /// <returns>The trust score (0–1000).</returns>
    public double GetScore(string agentDid)
    {
        if (_scores.TryGetValue(agentDid, out var record))
        {
            return ApplyDecay(record);
        }
        return _defaultScore;
    }

    /// <summary>
    /// Updates the trust score for an agent and persists to disk.
    /// </summary>
    /// <param name="agentDid">The agent's decentralised identifier.</param>
    /// <param name="score">The new trust score (clamped to 0–1000).</param>
    public void SetScore(string agentDid, double score)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(agentDid);
        var clamped = Math.Clamp(score, 0, 1000);

        _scores[agentDid] = new TrustRecord
        {
            Score = clamped,
            LastUpdatedUtc = DateTime.UtcNow,
            LastPositiveSignalUtc = DateTime.UtcNow
        };

        Save();
    }

    /// <summary>
    /// Records a positive trust signal for an agent, boosting their score.
    /// </summary>
    /// <param name="agentDid">The agent's decentralised identifier.</param>
    /// <param name="boost">Amount to increase the score by.</param>
    public void RecordPositiveSignal(string agentDid, double boost = 5.0)
    {
        var current = GetScore(agentDid);
        var record = new TrustRecord
        {
            Score = Math.Clamp(current + boost, 0, 1000),
            LastUpdatedUtc = DateTime.UtcNow,
            LastPositiveSignalUtc = DateTime.UtcNow
        };
        _scores[agentDid] = record;
        Save();
    }

    /// <summary>
    /// Records a negative trust signal for an agent, reducing their score.
    /// </summary>
    /// <param name="agentDid">The agent's decentralised identifier.</param>
    /// <param name="penalty">Amount to decrease the score by.</param>
    public void RecordNegativeSignal(string agentDid, double penalty = 50.0)
    {
        var current = GetScore(agentDid);
        var existing = _scores.GetValueOrDefault(agentDid);
        var record = new TrustRecord
        {
            Score = Math.Clamp(current - penalty, 0, 1000),
            LastUpdatedUtc = DateTime.UtcNow,
            LastPositiveSignalUtc = existing?.LastPositiveSignalUtc ?? DateTime.UtcNow
        };
        _scores[agentDid] = record;
        Save();
    }

    /// <summary>
    /// Returns all tracked agents and their current (decayed) trust scores.
    /// </summary>
    public IReadOnlyDictionary<string, double> GetAllScores()
    {
        var result = new Dictionary<string, double>();
        foreach (var (key, record) in _scores)
        {
            result[key] = ApplyDecay(record);
        }
        return result;
    }

    /// <summary>
    /// Returns the number of agents being tracked.
    /// </summary>
    public int Count => _scores.Count;

    /// <summary>
    /// Removes an agent from the trust store and persists the change.
    /// </summary>
    public bool Remove(string agentDid)
    {
        if (_scores.TryRemove(agentDid, out _))
        {
            Save();
            return true;
        }
        return false;
    }

    /// <summary>
    /// Forces a save to disk.
    /// </summary>
    public void Flush() => Save();

    private double ApplyDecay(TrustRecord record)
    {
        if (_decayRate <= 0) return record.Score;

        var hoursSinceSignal = (DateTime.UtcNow - record.LastPositiveSignalUtc).TotalHours;
        var decay = hoursSinceSignal * _decayRate;
        return Math.Clamp(record.Score - decay, 0, 1000);
    }

    private void Load()
    {
        lock (_ioLock)
        {
            if (!File.Exists(_filePath)) return;

            try
            {
                var json = File.ReadAllText(_filePath);
                var data = JsonSerializer.Deserialize<Dictionary<string, TrustRecord>>(json, JsonOptions);
                if (data is not null)
                {
                    foreach (var (key, value) in data)
                    {
                        _scores[key] = value;
                    }
                }
            }
            catch (JsonException ex)
            {
                // Preserve corrupted file for forensics.
                try
                {
                    var corruptPath = _filePath + ".corrupt";
                    File.Copy(_filePath, corruptPath, overwrite: true);
                }
                catch
                {
                    // Best-effort backup; ignore if it fails.
                }

                _loadErrorHandler?.Invoke(ex, _filePath);
            }
        }
    }

    private void Save()
    {
        if (_disposed) return;

        lock (_ioLock)
        {
            var data = new Dictionary<string, TrustRecord>(_scores);
            var json = JsonSerializer.Serialize(data, JsonOptions);
            var dir = Path.GetDirectoryName(_filePath);
            if (!string.IsNullOrEmpty(dir))
            {
                Directory.CreateDirectory(dir);
            }
            File.WriteAllText(_filePath, json);
        }
    }

    /// <inheritdoc />
    public void Dispose()
    {
        if (!_disposed)
        {
            _disposed = true;
            Save();
        }
    }

    /// <summary>
    /// Internal record for serialisation.
    /// </summary>
    internal sealed class TrustRecord
    {
        public double Score { get; set; }
        public DateTime LastUpdatedUtc { get; set; }
        public DateTime LastPositiveSignalUtc { get; set; }
    }
}
