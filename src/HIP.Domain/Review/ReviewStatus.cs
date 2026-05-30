namespace HIP.Domain.Review;

public enum ReviewStatus
{
    Submitted = 0,
    Open = Submitted,
    InReview = 1,
    Confirmed = 2,
    Approved = Confirmed,
    Rejected = 3,
    NeedsMoreInfo = 4,
    Closed = 5
}
