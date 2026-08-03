namespace HIP.Web.Marketing.Models;

public enum Tone { Ok, Warn, Risk }

public static class ToneColors
{
    public static string Fg(Tone t) => t switch
    {
        Tone.Ok => "var(--ok)",
        Tone.Warn => "var(--warn)",
        _ => "var(--danger)"
    };

    public static string Bg(Tone t) => t switch
    {
        Tone.Ok => "rgba(34,197,94,.14)",
        Tone.Warn => "rgba(245,158,11,.14)",
        _ => "rgba(239,68,68,.14)"
    };
}

/// <summary>One scored signal, shown with its plain-language explanation.</summary>
public record Finding(string Id, string Label, string Plain, string Category, string Status, Tone Tone, string Delta, string? Technical = null)
{
    /// <summary>Falls back to the plain reading when no technical variant is written.</summary>
    public string Explain(bool technical) => technical ? (Technical ?? Plain) : Plain;

    public string Dot => ToneColors.Fg(Tone);
    public string StatusBg => ToneColors.Bg(Tone);
    public string StatusFg => ToneColors.Fg(Tone);
}

public record SpotSignal(Tone Tone, string Label, string Plain)
{
    public string Dot => ToneColors.Fg(Tone);
}

public record SpotOption(
    string Id,
    string Url,
    bool Secure,
    string? Urgency,
    int Score,
    string Verdict,
    Tone Tone,
    IReadOnlyList<SpotSignal> Signals);

public record SpotRound(string Brand, string Tagline, string FakeId, IReadOnlyList<SpotOption> Options);

/// <summary>View wrapper so the markup can stay declarative.</summary>
public class SpotOptionView
{
    private readonly SpotOption _o;
    private readonly SpotRound _r;
    private readonly string? _pick;

    public SpotOptionView(SpotOption o, SpotRound r, string? pick, Action<string> onPick)
    {
        _o = o;
        _r = r;
        _pick = pick;
        Pick = () => onPick(o.Id);
    }

    public string Letter => _o.Id.ToUpperInvariant();
    public string Url => _o.Url;
    public string Brand => _r.Brand;
    public string Tagline => _r.Tagline;
    public bool Secure => _o.Secure;
    public bool Insecure => !_o.Secure;
    public string? Urgency => _o.Urgency;
    public bool HasUrgency => !string.IsNullOrEmpty(_o.Urgency);
    public string Score => _o.Score.ToString();
    public string Verdict => _o.Verdict;
    public string VerdictBg => ToneColors.Bg(_o.Tone);
    public string VerdictFg => ToneColors.Fg(_o.Tone);
    public string BarWidth => _o.Score + "%";
    public bool Revealed => _pick is not null;
    public bool Pending => _pick is null;
    public bool Chosen => _pick == _o.Id;
    public string ChosenLabel => Chosen ? "You chose this one" : "";
    public IReadOnlyList<SpotSignal> Signals => _o.Signals;
    public Action Pick { get; }
}

public record Faq(string Q, string A);

public class FaqView
{
    public FaqView(string q, string a, bool open, Action toggle)
    {
        Q = q;
        A = a;
        Open = open;
        Toggle = toggle;
    }

    public string Q { get; }
    public string A { get; }
    public bool Open { get; }
    public string Rotate => Open ? "rotate(45deg)" : "none";
    public Action Toggle { get; }
}
