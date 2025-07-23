namespace HIP.ApiService.Models
{

    public record HipMessage(string SenderId, string ReceiverId, string Payload, DateTime SentAt);

}
// This code defines a record type `HipMessage` that represents a message in the HIP system.